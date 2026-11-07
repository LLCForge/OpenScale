package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func makeRelease(t *testing.T, version string) (dir string, root release.PublicKey) {
	t.Helper()
	dir = t.TempDir()
	root, rootPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, signPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certEnv, _, err := release.IssueCertificate(rootPriv, release.CertificateRequest{SigningKey: signing, NotBefore: now.Add(-time.Hour), Validity: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"openscale-linux-amd64": "linux", "openscale-windows-amd64.exe": "windows"}
	var arts []release.Artifact
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := release.HashArtifact(name, strings.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		arts = append(arts, a)
	}
	data, err := release.SignManifest(signPriv, certEnv, root, release.NewManifest(version, "b", 0, arts), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rel.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.pub"), []byte(root.String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, root
}

func runArgs(args ...string) (int, string) {
	var out bytes.Buffer
	code := run(args, &out, &out, now.Add(time.Hour))
	return code, out.String()
}

func TestVerifyAll(t *testing.T) {
	dir, root := makeRelease(t, "0.9.0")
	m := filepath.Join(dir, "rel.json")
	if code, out := runArgs("-root-key", filepath.Join(dir, "root.pub"), "-manifest", m); code != exitOK {
		t.Fatalf("code %d: %s", code, out)
	}
	if code, out := runArgs("-root-key", root.String(), "-root-fingerprint", root.Fingerprint(), "-manifest", m, "openscale-linux-amd64"); code != exitOK {
		t.Fatalf("code %d: %s", code, out)
	}
	if code, _ := runArgs("-root-key", root.String(), "-root-fingerprint", strings.Repeat("0", 64), "-manifest", m); code != exitFailed {
		t.Fatal("wrong fingerprint accepted")
	}
}

func TestVerifyDetectsTamperingAndRollback(t *testing.T) {
	dir, root := makeRelease(t, "0.9.0")
	m := filepath.Join(dir, "rel.json")
	if code, _ := runArgs("-root-key", root.String(), "-manifest", m, "-installed", "1.0.0"); code != exitFailed {
		t.Fatal("rollback accepted")
	}
	if code, out := runArgs("-root-key", root.String(), "-manifest", m, "-installed", "1.0.0", "-allow-downgrade"); code != exitOK {
		t.Fatalf("explicit downgrade refused: %s", out)
	}
	if err := os.WriteFile(filepath.Join(dir, "openscale-linux-amd64"), []byte("evil!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := runArgs("-root-key", root.String(), "-manifest", m); code != exitFailed {
		t.Fatal("tampered file accepted")
	}
	if err := os.Remove(filepath.Join(dir, "openscale-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	if code, _ := runArgs("-root-key", root.String(), "-manifest", m); code != exitFailed {
		t.Fatal("missing file accepted")
	}
	if code, out := runArgs("-root-key", root.String(), "-manifest", m, "-present-only"); code != exitOK {
		t.Fatalf("present-only: %s", out)
	}
	other, _, _ := release.GenerateKey(rand.Reader)
	if code, _ := runArgs("-root-key", other.String(), "-manifest", m, "-present-only"); code != exitFailed {
		t.Fatal("other root accepted")
	}
}

func TestNoRootKey(t *testing.T) {
	dir, _ := makeRelease(t, "0.9.0")
	if code, _ := runArgs("-manifest", filepath.Join(dir, "rel.json")); code != exitFailed {
		t.Fatal("verified without a root key")
	}
}
