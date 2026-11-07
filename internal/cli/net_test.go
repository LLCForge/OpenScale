package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	coordKeyLine   = regexp.MustCompile(`WireGuard açık anahtarı: (\S+)`)
	coordFPLine    = regexp.MustCompile(`Parmak izi:\s+([A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4})`)
	bundleLine     = regexp.MustCompile(`osjoin1\.[A-Za-z0-9_-]+`)
	rootFPLine     = regexp.MustCompile(`Kök anahtar parmak izi: (\S+)`)
	wrongFP        = "AAAA-BBBB-CCCC-DDDD"
	coordinatorURL = "vpn.ornek.com:51820"
)

func (h *harness) coordinatorKeygen(dir string) (string, string) {
	h.t.Helper()
	out := h.run(exitOK, "coordinator", "keygen", "--state-dir", dir)
	key, fp := coordKeyLine.FindStringSubmatch(out), coordFPLine.FindStringSubmatch(out)
	if len(key) != 2 || len(fp) != 2 {
		h.t.Fatalf("coordinator keygen output missing key or fingerprint:\n%s", out)
	}
	return key[1], fp[1]
}

func TestCoordinatorKeygenAndSetCoordinator(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	coordDir := filepath.Join(t.TempDir(), "koordinator")
	key, fp := h.coordinatorKeygen(coordDir)
	if again, againFP := h.coordinatorKeygen(coordDir); again != key || againFP != fp {
		t.Fatal("a second keygen must reuse the existing coordinator key")
	}

	out := h.run(exitError, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", coordinatorURL, "--wireguard-key", key, "--fingerprint", wrongFP, pass)
	if !strings.Contains(out, "Parmak izleri eşleşmiyor") {
		t.Fatalf("wrong fingerprint must be rejected:\n%s", out)
	}
	h.run(exitUsage, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", coordinatorURL, "--wireguard-key", "bozuk", "--fingerprint", fp, pass)
	h.run(exitError, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", "port-yok", "--wireguard-key", key, "--fingerprint", fp, pass)

	out = h.run(exitOK, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", coordinatorURL, "--wireguard-key", key, "--fingerprint", strings.ToLower(fp), pass)
	if !strings.Contains(out, "Koordinatör değişti") || !strings.Contains(out, "sürüm 2") {
		t.Fatalf("unexpected set-coordinator output:\n%s", out)
	}
	if out := h.run(exitOK, "network", "show", "--dir", h.netDir); !strings.Contains(out, "Koordinatör:             "+coordinatorURL) {
		t.Fatalf("coordinator missing from network show:\n%s", out)
	}
}

func TestBundleAndJoin(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	coordDir := filepath.Join(t.TempDir(), "koordinator")
	coordKey, coordFP := h.coordinatorKeygen(coordDir)
	h.run(exitOK, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", coordinatorURL, "--wireguard-key", coordKey, "--fingerprint", coordFP, pass)

	laptopDir := filepath.Join(t.TempDir(), "laptop")
	req, fp := h.keygen(laptopDir, "laptop")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)

	out := h.run(exitOK, "bundle", "--dir", h.netDir)
	bundle := bundleLine.FindString(out)
	root := rootFPLine.FindStringSubmatch(out)
	if bundle == "" || len(root) != 2 {
		t.Fatalf("bundle output missing bundle or root fingerprint:\n%s", out)
	}

	out = h.run(exitError, "join", "--state-dir", laptopDir, "--bundle", bundle, "--root-fingerprint", wrongFP)
	if !strings.Contains(out, "Kök anahtar parmak izi eşleşmiyor") {
		t.Fatalf("wrong root fingerprint must be rejected:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(laptopDir, "anchor.json")); err == nil {
		t.Fatal("a rejected bundle must not create an anchor")
	}

	out = h.run(exitOK, "join", "--state-dir", laptopDir, "--bundle", bundle, "--root-fingerprint", root[1])
	if !strings.Contains(out, "Bu cihaz ağda kayıtlı: laptop.openscale.internal") {
		t.Fatalf("unexpected device join output:\n%s", out)
	}

	bundleFile := filepath.Join(t.TempDir(), "paket.txt")
	if err := os.WriteFile(bundleFile, []byte(bundle+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitOK, "join", "--state-dir", coordDir, "--bundle", "@"+bundleFile, "--root-fingerprint", root[1])
	if !strings.Contains(out, "ağın koordinatörü") {
		t.Fatalf("unexpected coordinator join output:\n%s", out)
	}

	// A device that is not in the document is told so.
	strangerDir := filepath.Join(t.TempDir(), "yabanci")
	h.keygen(strangerDir, "yabanci")
	out = h.run(exitOK, "join", "--state-dir", strangerDir, "--bundle", bundle, "--root-fingerprint", root[1])
	if !strings.Contains(out, "bu cihaz belgede yok") {
		t.Fatalf("unexpected stranger join output:\n%s", out)
	}
}

func TestUpAndCoordinatorRunRequireJoin(t *testing.T) {
	h := newHarness(t)
	empty := t.TempDir()
	out := h.run(exitError, "up", "--state-dir", empty)
	if !strings.Contains(out, "henüz bir ağa katılmamış") {
		t.Fatalf("unexpected up output:\n%s", out)
	}
	out = h.run(exitError, "coordinator", "run", "--state-dir", empty)
	if !strings.Contains(out, "henüz bir ağa katılmamış") {
		t.Fatalf("unexpected coordinator run output:\n%s", out)
	}
	h.run(exitUsage, "coordinator", "run")
	h.run(exitUsage, "up", "--state-dir", empty, "--listen-port", "70000")
}

func TestUpValidatesExitOptions(t *testing.T) {
	h := newHarness(t)
	empty := t.TempDir()
	for _, bad := range []string{"http://dns.ornek/dns-query", "tls://", "https:///yol", "dns.ornek"} {
		out := h.run(exitUsage, "up", "--state-dir", empty, "--exit-dns-upstream", bad)
		if !strings.Contains(out, "--exit-dns-upstream") {
			t.Fatalf("unexpected output for %q:\n%s", bad, out)
		}
	}
	out := h.run(exitUsage, "up", "--state-dir", empty, "--netfilter-mode", "pf")
	if !strings.Contains(out, "--netfilter-mode") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	// Valid options pass validation; the missing network fails next.
	for _, ok := range []string{"9.9.9.9", "tls://dns.quad9.net", "https://dns.quad9.net/dns-query"} {
		h.run(exitError, "up", "--state-dir", empty, "--exit-dns-upstream", ok, "--netfilter-mode", "iptables")
	}
}
