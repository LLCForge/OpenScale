package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

func p28Join(h *harness, netDir string, extra ...string) string {
	h.t.Helper()
	out := h.run(exitOK, "bundle", "--dir", netDir)
	args := append(extra, "join", "--bundle", bundleLine.FindString(out), "--root-fingerprint", rootFPLine.FindStringSubmatch(out)[1])
	return h.run(exitOK, args...)
}

func TestNetworkProfilesJoinListSwitch(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	familyDir := filepath.Join(filepath.Dir(h.netDir), "aile-ag")
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--skip-backup", pass)
	h.run(exitOK, "network", "init", "--dir", familyDir, "--ipv4", "100.90.0.0/16", "--skip-backup", pass)

	p28Join(h, h.netDir)
	out := p28Join(h, familyDir, "--network", "aile")
	base, _ := h.env.DefaultStateDir()
	if !strings.Contains(out, filepath.Join(base, "networks", "aile")) {
		t.Fatalf("join did not use the profile directory:\n%s", out)
	}

	out = h.run(exitOK, "network", "list")
	if !strings.Contains(out, "* default") || !strings.Contains(out, "  aile") {
		t.Fatalf("list:\n%s", out)
	}
	h.run(exitError, "network", "switch", "yok")
	h.run(exitUsage, "network", "switch", "Kötü/Ad")
	h.run(exitUsage, "--network", "aile", "network", "list")
	h.run(exitUsage, "--network")

	h.run(exitOK, "network", "switch", "aile")
	out = h.run(exitOK, "network", "list")
	if !strings.Contains(out, "* aile") || strings.Contains(out, "* default") {
		t.Fatalf("after switch:\n%s", out)
	}
	// The active profile now feeds every command's default state dir:
	// joining network A again lands in "aile" and is refused there.
	h.run(exitError, append([]string{}, "join", "--bundle", bundleLine.FindString(h.run(exitOK, "bundle", "--dir", h.netDir)), "--root-fingerprint", rootFPLine.FindStringSubmatch(h.run(exitOK, "bundle", "--dir", h.netDir))[1])...)

	h.run(exitOK, "network", "switch", "default")
	if _, err := os.Stat(filepath.Join(base, "networks", "active")); !os.IsNotExist(err) {
		t.Fatalf("default switch left a pointer: %v", err)
	}
	// A profile that never joined cannot become active.
	if err := os.MkdirAll(filepath.Join(base, "networks", "bos"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "network", "switch", "bos")
}

func TestNetworkReaddressCLI(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--skip-backup", pass)
	req, fp := h.keygen(filepath.Join(filepath.Dir(h.netDir), "laptop"), "laptop")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)

	out := h.run(exitOK, "network", "readdress", "--dir", h.netDir, "--ipv4", "10.44.0.0/16", "--dry-run")
	if !strings.Contains(out, "-> 10.44.") || !strings.Contains(out, "Kuru çalıştırma") {
		t.Fatalf("dry run:\n%s", out)
	}
	h.run(exitUsage, "network", "readdress", "--dir", h.netDir, "--ipv4", "10.44.0.0/16", pass)
	h.run(exitUsage, "network", "readdress", "--dir", h.netDir)
	h.run(exitOK, "network", "readdress", "--dir", h.netDir, "--ipv4", "10.44.0.0/16", "--confirm", readdressWord, pass)
	n, err := admin.Load(h.netDir, admin.Options{Argon2: h.env.Argon2})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := n.Document()
	if doc.IPv4Prefix.String() != "10.44.0.0/16" || doc.Version != 3 {
		t.Fatalf("prefix %s version %d", doc.IPv4Prefix, doc.Version)
	}
	for _, d := range doc.Devices {
		if !doc.IPv4Prefix.Contains(d.IPv4) {
			t.Fatalf("%s at %s", d.Name, d.IPv4)
		}
	}
	_ = trust.DefaultValidity
}
