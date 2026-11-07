package service

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/updater"
)

// A revoked signing key blocks the service at start-up, so the self check must
// report it as an error, not as a warning about a damaged manifest.
func TestSelfCheckReportsRevokedSigningKeyAsError(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
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
	const artifact, content = "openscale-linux-amd64", "program"
	art, err := release.HashArtifact(artifact, strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := release.SignManifest(signPriv, cert, root, release.NewManifest("1.2.3", "b", now.Unix(), []release.Artifact{art}), now)
	if err != nil {
		t.Fatal(err)
	}
	list, err := release.SignRevocations(rootPriv, release.Revocations{Sequence: 1, Issued: now,
		Revoked: []release.RevokedKey{{SigningKey: signing, Reason: "sizdi"}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "openscale")
	for path, data := range map[string][]byte{
		exe: []byte(content),
		filepath.Join(dir, updater.InstalledManifestFile): manifest,
		filepath.Join(dir, updater.InstalledArtifactFile): []byte(artifact),
		filepath.Join(dir, updater.RevocationsFile):       list,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := updater.EmbeddedRootKey
	t.Cleanup(func() { updater.EmbeddedRootKey = old })
	updater.EmbeddedRootKey = root.String()

	c := &checker{now: now}
	c.checkProgram(dir, exe)
	if len(c.out) != 1 || c.out[0].Level != FindingError {
		t.Fatalf("findings: %+v, want one error", c.out)
	}
}
