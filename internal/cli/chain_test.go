package cli

import (
	"strings"
	"testing"
)

func TestNetworkChainCommand(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	h.run(exitUsage, "network", "chain", "--dir", h.netDir, pass)
	out := h.run(exitUsage, "network", "chain", "--dir", h.netDir, "--state", "on", pass)
	if !strings.Contains(out, "REDDEDER") {
		t.Fatalf("missing warning:\n%s", out)
	}
	out = h.run(exitOK, "network", "chain", "--dir", h.netDir, "--state", "on", "--dry-run", pass)
	if !strings.Contains(out, "Sürüm zinciri: açıldı") || !strings.Contains(out, "imzalanmadı") {
		t.Fatalf("dry run:\n%s", out)
	}
	h.run(exitOK, "network", "chain", "--dir", h.netDir, "--state", "on", "--yes", pass)
	out = h.run(exitOK, "network", "chain", "--dir", h.netDir, "--state", "off", pass)
	if !strings.Contains(out, "Sürüm zinciri: kapatıldı") {
		t.Fatalf("off:\n%s", out)
	}
}
