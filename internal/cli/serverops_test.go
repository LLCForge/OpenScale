package cli

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/usage"
)

const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOpenScaleTestKeyOnlyForUnitTests0000000 owner@laptop"

func TestServerCloudInitPinsVerifiedPackage(t *testing.T) {
	h := newHarness(t)
	now := h.env.Now()
	root, rootPriv, err := release.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, signPriv, _ := release.GenerateKey(rand.Reader)
	cert, _, err := release.IssueCertificate(rootPriv, release.CertificateRequest{SigningKey: signing, Serial: 1, NotBefore: now.Add(-time.Hour), Validity: release.DefaultCertificateValidity})
	if err != nil {
		t.Fatal(err)
	}
	deb, _ := release.HashArtifact("openscale_1.2.3_amd64.deb", strings.NewReader("deb bytes"))
	other, _ := release.HashArtifact("openscale-linux-amd64", strings.NewReader("bin"))
	data, err := release.SignManifest(signPriv, cert, root, release.NewManifest("1.2.3", "b", now.Unix(), []release.Artifact{deb, other}), now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifest := filepath.Join(dir, "openscale-1.2.3.release.json")
	if err := os.WriteFile(manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "user-data")
	h.run(exitOK, "server", "cloud-init", "--root-key", root.String(), "--manifest", manifest,
		"--package-url", "https://indirme.ornek.com/openscale_1.2.3_amd64.deb", "--ssh-key", testSSHKey, "--hostname", "vpn", "--out", out)
	ud, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ud), deb.SHA256) || !strings.Contains(string(ud), "coordinator keygen") {
		t.Fatalf("user-data does not pin the package:\n%s", ud)
	}
	// Another root key: the manifest is refused and nothing is written.
	other2, _, _ := release.GenerateKey(rand.Reader)
	h.run(exitError, "server", "cloud-init", "--root-key", other2.String(), "--manifest", manifest,
		"--package-url", "https://indirme.ornek.com/openscale_1.2.3_amd64.deb", "--ssh-key", testSSHKey, "--out", filepath.Join(dir, "x"))
	if _, err := os.Stat(filepath.Join(dir, "x")); err == nil {
		t.Fatal("user-data written for an unverified manifest")
	}
	// No arm64 package in the manifest.
	h.run(exitError, "server", "cloud-init", "--root-key", root.String(), "--manifest", manifest, "--arch", "arm64",
		"--package-url", "https://indirme.ornek.com/openscale_1.2.3_arm64.deb", "--ssh-key", testSSHKey, "--out", filepath.Join(dir, "y"))
}

func TestPromotePreflightGate(t *testing.T) {
	h := newHarness(t)
	key := "a2V5"
	res := coordinator.PreflightResult{Schema: 1, Coordinator: key, Fingerprint: "f", At: h.env.Now(), Compared: true,
		Reachable: []string{"a"}, Unreachable: []string{"b"}, Offline: []string{}}
	path := filepath.Join(t.TempDir(), "sonuc.json")
	write := func() {
		data, _ := json.Marshal(res)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := checkPromotePreflight(h.env, path, key); err == nil || !strings.Contains(err.Error(), "b") {
		t.Fatalf("unreachable device must block signing: %v", err)
	}
	res.Unreachable = []string{}
	write()
	if err := checkPromotePreflight(h.env, path, key); err != nil {
		t.Fatal(err)
	}
	if err := checkPromotePreflight(h.env, path, "other"); err == nil {
		t.Fatal("result of another coordinator accepted")
	}
	h.stderr.Reset()
	if err := checkPromotePreflight(h.env, "", key); err != nil || !strings.Contains(h.stderr.String(), "ön denetim") {
		t.Fatalf("missing preflight must warn: %v %q", err, h.stderr.String())
	}
}

func TestCoordinatorUsageCommand(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	m := usage.NewMonthly(0)
	m.Add("abcd", 3<<20, h.env.Now())
	data, _ := m.Encode()
	if err := os.WriteFile(filepath.Join(dir, coordinator.RelayUsageFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitOK, "coordinator", "usage", "--state-dir", dir)
	if !strings.Contains(out, "(belgede yok)") || !strings.Contains(out, "Toplam") {
		t.Fatalf("usage output:\n%s", out)
	}
	out = h.run(exitOK, "coordinator", "usage", "--state-dir", dir, "--month", "2020-01")
	if !strings.Contains(out, "trafik yok") {
		t.Fatalf("empty month:\n%s", out)
	}
	h.run(exitUsage, "coordinator", "usage")
	h.run(exitUsage, "coordinator", "drill", "--state-dir", dir)
	h.run(exitUsage, "coordinator", "drill", "--state-dir", dir, "--duration", "1s")
	h.run(exitUsage, "coordinator", "drill", "--state-dir", dir, "--cancel", "--status")
	if out := h.run(exitOK, "coordinator", "drill", "--state-dir", dir, "--status"); !strings.Contains(out, "henüz") {
		t.Fatalf("drill status:\n%s", out)
	}
	h.run(exitUsage, "server", "audit", "--role", "x")
	h.run(exitUsage, "server", "surface", "--timeout", "1ms")
}
