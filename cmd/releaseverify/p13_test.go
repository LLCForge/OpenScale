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

func TestWitnessAndAdvisories(t *testing.T) {
	dir := t.TempDir()
	root, rootPriv, _ := release.GenerateKey(rand.Reader)
	signing, signPriv, _ := release.GenerateKey(rand.Reader)
	certEnv, _, err := release.IssueCertificate(rootPriv, release.CertificateRequest{SigningKey: signing, NotBefore: now.Add(-time.Hour), Validity: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openscale-linux-amd64"), []byte("linux"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := release.HashArtifact("openscale-linux-amd64", strings.NewReader("linux"))
	signed, err := release.SignManifest(signPriv, certEnv, root, release.NewManifest("0.9.0", "b", 0, []release.Artifact{a}), now)
	if err != nil {
		t.Fatal(err)
	}
	m := filepath.Join(dir, "rel.json")
	if err := os.WriteFile(m, signed, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := release.Verify(root, signed, release.VerifyOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := release.ManifestDigest(signed)
	wk, wpriv, _ := release.GenerateKey(rand.Reader)
	w, err := release.NewWitness(v, digest, "ikinci", []release.Artifact{a}, now)
	if err != nil {
		t.Fatal(err)
	}
	wdata, _ := release.SignWitness(wpriv, w)
	wpath := filepath.Join(dir, "rel.witness.json")
	if err := os.WriteFile(wpath, wdata, 0o644); err != nil {
		t.Fatal(err)
	}

	if code, out := runArgs("-root-key", root.String(), "-manifest", m, "-witness", wpath, "-witness-key", wk.String()); code != exitOK || !strings.Contains(out, "Bağımsız derleme") {
		t.Fatalf("witness: %d %s", code, out)
	}
	other, _, _ := release.GenerateKey(rand.Reader)
	if code, _ := runArgs("-root-key", root.String(), "-manifest", m, "-witness", wpath, "-witness-key", other.String()); code != exitFailed {
		t.Fatal("witness accepted with another key")
	}
	if code, _ := runArgs("-root-key", root.String(), "-manifest", m, "-witness", wpath); code != exitFailed {
		t.Fatal("-witness without -witness-key accepted")
	}

	adv, err := release.SignAdvisories(rootPriv, release.Advisories{Sequence: 1, Advisories: []release.Advisory{
		{ID: "OSA-2026-0001", Severity: release.SeverityHigh, Title: "Örnek", Introduced: "0.8.0", Fixed: "0.9.0", Published: now},
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	apath := filepath.Join(dir, "adv.json")
	if err := os.WriteFile(apath, adv, 0o644); err != nil {
		t.Fatal(err)
	}
	// The release (0.9.0) is fixed; the installed 0.8.5 is affected.
	if code, out := runArgs("-root-key", root.String(), "-manifest", m, "-advisories", apath); code != exitOK {
		t.Fatalf("fixed release reported: %d %s", code, out)
	}
	if code, out := runArgs("-root-key", root.String(), "-advisories", apath, "-installed", "0.8.5"); code != exitFailed || !strings.Contains(out, "OSA-2026-0001") {
		t.Fatalf("affected version not reported: %d %s", code, out)
	}
	if code, _ := runArgs("-root-key", other.String(), "-advisories", apath, "-installed", "0.8.5"); code != exitFailed {
		t.Fatal("advisories verified with another root")
	}
}
