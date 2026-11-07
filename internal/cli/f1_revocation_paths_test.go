package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/release"
)

const revokedRunArtifact = "openscale-linux-amd64"

// revokedKeyRelease signs a valid release and a root-signed list that revokes
// its signing key. The list is returned, not yet placed anywhere.
func revokedKeyRelease(t *testing.T, h *harness) (manifest string, root release.PublicKey, list []byte) {
	t.Helper()
	now := h.env.Now()
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
	deb, err := release.HashArtifact("openscale_1.2.3_amd64.deb", strings.NewReader("deb"))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := release.HashArtifact(revokedRunArtifact, strings.NewReader("bin"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := release.SignManifest(signPriv, cert, root, release.NewManifest("1.2.3", "b", now.Unix(), []release.Artifact{deb, bin}), now)
	if err != nil {
		t.Fatal(err)
	}
	manifest = filepath.Join(t.TempDir(), "openscale-1.2.3.release.json")
	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
	list, err = release.SignRevocations(rootPriv, release.Revocations{Sequence: 1, Issued: now,
		Revoked: []release.RevokedKey{{SigningKey: signing, Reason: "sizdi"}}})
	if err != nil {
		t.Fatal(err)
	}
	return manifest, root, list
}

// "update apply --verify-only" must judge a release as "update apply" does:
// the list published next to the manifest counts, and nothing is stored.
func TestVerifyOnlyHonoursListNextToManifest(t *testing.T) {
	h := newHarness(t)
	manifest, root, list := revokedKeyRelease(t, h)
	args := []string{"update", "apply", "--verify-only", "--root-key", root.String(), "--artifact", revokedRunArtifact, manifest}
	if out := h.run(exitOK, args...); !strings.Contains(out, "geçerli") {
		t.Fatalf("no list yet:\n%s", out)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(manifest), "revocations.json"), list, 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, args...)
}

// "server cloud-init" pins a package to a manifest for a new server, so a
// revoked signing key must not get through this path either.
func TestCloudInitRefusesRevokedSigningKey(t *testing.T) {
	h := newHarness(t)
	manifest, root, list := revokedKeyRelease(t, h)
	dir := filepath.Dir(manifest)
	base := []string{"server", "cloud-init", "--root-key", root.String(), "--manifest", manifest,
		"--package-url", "https://indirme.ornek.com/openscale_1.2.3_amd64.deb", "--ssh-key", testSSHKey}
	h.run(exitOK, append(base, "--out", filepath.Join(dir, "clean"))...)

	// Published next to the manifest.
	sibling := filepath.Join(dir, "revocations.json")
	if err := os.WriteFile(sibling, list, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "next-to-manifest")
	h.run(exitError, append(base, "--out", out)...)
	if _, err := os.Stat(out); err == nil {
		t.Fatal("user-data written for a revoked signing key")
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}

	// Given on the command line.
	given := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(given, list, 0o600); err != nil {
		t.Fatal(err)
	}
	out = filepath.Join(dir, "given")
	h.run(exitError, append(base, "--revocations", given, "--out", out)...)
	if _, err := os.Stat(out); err == nil {
		t.Fatal("user-data written for a revoked signing key")
	}
}
