package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/node"
)

func TestOpsecCommands(t *testing.T) {
	h := newHarness(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, "opsec", "obfs", "--state-dir", dir, "--mode", "auto", "--jitter", "20ms", "--tls-sni", "cdn.example.test")
	h.run(exitOK, "opsec", "decoy", "--state-dir", dir, "--ports", "ssh,rdp", "--quarantine-on-scan")
	h.run(exitOK, "opsec", "canary", "--state-dir", dir, "--add", "bank.example:443")
	h.run(exitOK, "opsec", "chain", "--state-dir", dir, "--entry", "ev")
	s, err := node.LoadOpsecSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Obfs.Mode != "auto" || s.Obfs.JitterMS != 20 || s.Obfs.TLS == nil || len(s.DecoyPorts) != 2 || !s.QuarantineOnScan ||
		len(s.ExitCanary) != 1 || s.ExitChainEntry != "ev" {
		t.Fatalf("%+v", s)
	}
	out := h.run(exitOK, "opsec", "show", "--state-dir", dir)
	if !strings.Contains(out, "Trafik gizleme:      auto") || !strings.Contains(out, "SNI cdn.example.test") {
		t.Fatalf("show:\n%s", out)
	}
	// Invalid values are refused and leave the file unchanged.
	h.run(exitUsage, "opsec", "obfs", "--state-dir", dir, "--mode", "maybe")
	h.run(exitError, "opsec", "decoy", "--state-dir", dir, "--ports", "telnet")
	h.run(exitError, "opsec", "obfs", "--state-dir", dir, "--mode", "on", "--jitter", "1s")
	if s2, _ := node.LoadOpsecSettings(dir); s2.Obfs.Mode != "auto" {
		t.Fatal("refused change was saved")
	}
}

func TestOpsecPlansDoNotApply(t *testing.T) {
	h := newHarness(t)
	out := h.run(exitOK, "opsec", "webrtc", "--iface", "openscale0")
	if !strings.Contains(out, "Hiçbir şey değiştirilmedi") || !strings.Contains(out, "Kurma planı") {
		t.Fatalf("%s", out)
	}
	out = h.run(exitOK, "opsec", "dhcp-name", "--conn", "Kafe", "--name", "DESKTOP-AB12CD3")
	if !strings.Contains(out, "Hiçbir şey değiştirilmedi") {
		t.Fatalf("%s", out)
	}
	h.run(exitUsage, "opsec", "webrtc", "--iface", "x", "--apply", "--remove")
}

func TestCoordinatorObfsCert(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	out := h.run(exitOK, "coordinator", "obfs-cert", "--state-dir", dir, "--name", "cdn.example.test")
	if !strings.Contains(out, "SPKI sabitlemesi: sha256/") {
		t.Fatalf("%s", out)
	}
	again := h.run(exitOK, "coordinator", "obfs-cert", "--state-dir", dir, "--name", "cdn.example.test")
	if out != again {
		t.Fatal("pin changed on the second run")
	}
}
