package updater

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
)

// ApplyPackage (ADR-0225) verifies like Apply and hands only a verified
// package to the package manager; a broken result goes back to the kept
// previous package.
func TestApplyPackage(t *testing.T) {
	root, rootPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, signPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := release.IssueCertificate(rootPriv, release.CertificateRequest{SigningKey: signing, Serial: 1, NotBefore: time.Now().Add(-time.Hour), Validity: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const deb = "openscale_1.0.1_amd64.deb"
	pkg := bytes.Repeat([]byte("deb"), 1000)
	a, _ := release.HashArtifact(deb, bytes.NewReader(pkg))
	signed, err := release.SignManifest(signPriv, cert, root, release.NewManifest("1.0.1", "b", 1, []release.Artifact{a}), time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	src := func(data []byte) Source {
		return Source{Manifest: signed, Where: "test", Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
	}
	state := t.TempDir()
	installed := "1.0.0"
	var got [][]byte
	po := PackageOptions{
		Options: Options{Exe: "openscale", Artifact: deb, Root: root, StateDir: state,
			ProgramVersion: func(context.Context, string) (string, error) { return installed, nil }},
		Install: func(_ context.Context, path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			got = append(got, data)
			installed = "1.0.1"
			return nil
		},
	}
	// A changed package never reaches dpkg.
	evil := bytes.Clone(pkg)
	evil[0] ^= 1
	if _, err := ApplyPackage(context.Background(), po, src(evil)); !errors.Is(err, release.ErrDigestMismatch) || len(got) != 0 {
		t.Fatalf("tampered: %v %d", err, len(got))
	}
	res, err := ApplyPackage(context.Background(), po, src(pkg))
	if err != nil || res.To != "1.0.1" || len(got) != 1 || !bytes.Equal(got[0], pkg) {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(state, InstalledPackageFile)); err != nil {
		t.Fatal("package not kept for rollback")
	}
	// Same version again: refused; older: refused by the rollback rule.
	if _, err := ApplyPackage(context.Background(), po, src(pkg)); !errors.Is(err, ErrAlreadyLatest) {
		t.Fatalf("again: %v", err)
	}
	installed = "2.0.0"
	if _, err := ApplyPackage(context.Background(), po, src(pkg)); err == nil {
		t.Fatal("downgrade installed")
	}
	// A package that installs but reports another version is rolled back.
	installed = "1.0.0"
	po.Install = func(_ context.Context, path string) error {
		got = append(got, nil)
		if filepath.Base(path) == InstalledPackageFile {
			return nil // the kept package goes back
		}
		installed = "0.0.1"
		return nil
	}
	res, err = ApplyPackage(context.Background(), po, src(pkg))
	if !errors.Is(err, ErrUnhealthy) || res == nil || !res.RolledBack {
		t.Fatalf("broken install: %+v %v", res, err)
	}
}
