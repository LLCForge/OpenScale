package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
)

// A root-signed list published next to the manifest is enforced without a
// flag: the person verifying a download should not have to know about it.
func TestListNextToManifestIsEnforced(t *testing.T) {
	root, rootPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, signPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := release.IssueCertificate(rootPriv, release.CertificateRequest{SigningKey: signing, Serial: 1, NotBefore: now.Add(-time.Hour), Validity: release.DefaultCertificateValidity})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	art, err := release.HashArtifact("openscale-linux-amd64", strings.NewReader("linux"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openscale-linux-amd64"), []byte("linux"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := release.SignManifest(signPriv, cert, root, release.NewManifest("0.9.0", "b", 0, []release.Artifact{art}), now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "rel.json")
	if err := os.WriteFile(manifest, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := runArgs("-root-key", root.String(), "-manifest", manifest); code != exitOK {
		t.Fatalf("no list: code %d: %s", code, out)
	}
	list, err := release.SignRevocations(rootPriv, release.Revocations{Sequence: 1, Issued: now,
		Revoked: []release.RevokedKey{{SigningKey: signing}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "revocations.json"), list, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := runArgs("-root-key", root.String(), "-manifest", manifest); code != exitFailed {
		t.Fatalf("revoked signing key: code %d: %s", code, out)
	}
	// A list that does not verify is an error, not "no list".
	if err := os.WriteFile(filepath.Join(dir, "revocations.json"), []byte("bozuk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := runArgs("-root-key", root.String(), "-manifest", manifest); code == exitOK {
		t.Fatalf("damaged list accepted: %s", out)
	}
}
