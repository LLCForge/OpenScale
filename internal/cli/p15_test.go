package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkCoordinatorCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	vpsKey, vpsFP := h.coordinatorKeygen(filepath.Join(t.TempDir(), "vps"))
	h.run(exitOK, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", coordinatorURL, "--wireguard-key", vpsKey, "--fingerprint", vpsFP, pass)

	homeKey, homeFP := h.coordinatorKeygen(filepath.Join(t.TempDir(), "ev"))
	h.run(exitError, "network", "coordinator", "add", "--dir", h.netDir, "--endpoint", "ev.ornek.net:41820", "--wireguard-key", homeKey, "--fingerprint", wrongFP, pass)
	h.run(exitOK, "network", "coordinator", "add", "--dir", h.netDir, "--endpoint", "ev.ornek.net:41820", "--wireguard-key", homeKey, "--fingerprint", homeFP, "--name", "ev", "--region", "ist", pass)
	out := h.run(exitOK, "network", "coordinator", "list", "--dir", h.netDir)
	if !strings.Contains(out, "birincil") || !strings.Contains(out, "ev.ornek.net:41820") || !strings.Contains(out, "bölge=ist") {
		t.Fatalf("list:\n%s", out)
	}

	h.run(exitOK, "network", "coordinator", "promote", "--dir", h.netDir, "--wireguard-key", homeKey, "--transition", "720h", pass)
	out = h.run(exitOK, "network", "coordinator", "list", "--dir", h.netDir)
	if first := strings.SplitN(out, "\n", 2)[0]; !strings.Contains(first, "ev.ornek.net") || !strings.Contains(out, "geçiş sonu") {
		t.Fatalf("after promote:\n%s", out)
	}
	h.run(exitError, "network", "coordinator", "remove", "--dir", h.netDir, "--wireguard-key", homeKey, pass)
	h.run(exitOK, "network", "coordinator", "remove", "--dir", h.netDir, "--wireguard-key", vpsKey, pass)

	newKey, newFP := h.coordinatorKeygen(filepath.Join(t.TempDir(), "yeni"))
	out = h.run(exitOK, "network", "coordinator", "rotate", "--dir", h.netDir, "--endpoint", "ev.ornek.net:41821", "--wireguard-key", newKey, "--fingerprint", newFP, pass)
	if !strings.Contains(out, "geçerli") {
		t.Fatalf("rotate:\n%s", out)
	}
	out = h.run(exitOK, "network", "coordinator", "list", "--dir", h.netDir)
	if strings.Count(out, "\n") != 2 || !strings.Contains(strings.SplitN(out, "\n", 2)[0], "ev.ornek.net:41821") {
		t.Fatalf("after rotate:\n%s", out)
	}
	h.run(exitError, "network", "coordinator", "prune", "--dir", h.netDir, pass)
}
