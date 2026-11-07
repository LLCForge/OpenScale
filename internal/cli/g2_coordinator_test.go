package cli

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/srvaudit"
)

func TestCoordinatorHardenCommand(t *testing.T) {
	h := newHarness(t)
	dir := filepath.Join(filepath.Dir(h.netDir), "koord")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.run(exitUsage, "coordinator", "harden", "--state-dir", dir)
	out := h.run(exitOK, "coordinator", "harden", "--state-dir", dir, "--spa", "on", "--no-metadata", "on", "--retention", "5", "--emergency-priority", "off")
	if !strings.Contains(out, "eski istemciler") || !strings.Contains(out, "en çok 5 dakika") {
		t.Fatalf("output:\n%s", out)
	}
	hd, err := coordinator.LoadHardening(dir)
	if err != nil || !hd.SPA || !hd.NoMetadata || hd.RetentionMinutes != 5 || !hd.NoEmergencyPriority {
		t.Fatalf("%+v %v", hd, err)
	}
	h.run(exitOK, "coordinator", "harden", "--state-dir", dir, "--no-metadata", "off")
	if hd, _ := coordinator.LoadHardening(dir); hd.NoMetadata || hd.RetentionMinutes != 0 || !hd.SPA {
		t.Fatalf("after off: %+v", hd)
	}
	h.run(exitUsage, "coordinator", "harden", "--state-dir", dir, "--spa", "belki")
	h.run(exitError, "coordinator", "harden", "--state-dir", dir, "--retention", "99", "--no-metadata", "on")
}

func TestCoordinatorRAMSeedCommand(t *testing.T) {
	h := newHarness(t)
	base := filepath.Dir(h.netDir)
	seed, state := filepath.Join(base, "tohum"), filepath.Join(base, "ram")
	if err := os.MkdirAll(seed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "anchor.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := h.run(exitOK, "coordinator", "ram-seed", "--seed", seed, "--state-dir", state); !strings.Contains(out, "anchor.json") {
		t.Fatalf("output:\n%s", out)
	}
	if out := h.run(exitOK, "coordinator", "ram-seed", "--seed", seed, "--state-dir", state); !strings.Contains(out, "zaten dolu") {
		t.Fatalf("second run:\n%s", out)
	}
}

func TestCanarySignAndVerifyCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	base := filepath.Dir(h.netDir)
	stmt, out := filepath.Join(base, "beyan.txt"), filepath.Join(base, "kanarya.json")
	if err := os.WriteFile(stmt, []byte("Bu tarihe kadar gizli bir talep almadım.\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitUsage, "canary", "sign", "--dir", h.netDir, "--statement-file", stmt, "--out", out, "--days", "120", pass)
	h.run(exitOK, "canary", "sign", "--dir", h.netDir, "--statement-file", stmt, "--out", out, "--days", "30", pass)
	got := h.run(exitOK, "canary", "verify", "--dir", h.netDir, "--file", out)
	if !strings.Contains(got, "geçerli") || !strings.Contains(got, "gizli bir talep") {
		t.Fatalf("verify:\n%s", got)
	}
	// Thirty-one days later the canary is reported as not renewed.
	start := h.env.Now()
	h.env.Now = func() time.Time { return start.Add(31 * 24 * time.Hour) }
	if got := h.run(exitError, "canary", "verify", "--dir", h.netDir, "--file", out); !strings.Contains(got, "yenilenmedi") {
		t.Fatalf("expired:\n%s", got)
	}
	// Tampering is caught.
	data, _ := os.ReadFile(out)
	data[len(data)/2] ^= 1
	_ = os.WriteFile(out, data, 0o600)
	h.env.Now = func() time.Time { return start }
	h.run(exitError, "canary", "verify", "--dir", h.netDir, "--file", out)
}

// cliFakeSSH is a no-op SSHSystem for the command test.
type cliFakeSSH struct{ ran []string }

func (f *cliFakeSSH) WriteFile(string, []byte) error { return nil }
func (f *cliFakeSSH) Remove(string) error            { return nil }
func (f *cliFakeSSH) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.ran = append(f.ran, name+" "+strings.Join(args, " "))
	return nil, nil
}
func (f *cliFakeSSH) HostAddrs() ([]netip.Addr, error)  { return nil, nil }
func (f *cliFakeSSH) SessionSource() (netip.Addr, bool) { return netip.Addr{}, false }
func (f *cliFakeSSH) Listeners() []srvaudit.Listener    { return nil }
func (f *cliFakeSSH) Sleep(time.Duration)               {}

func TestServerSSHTunnelOnlyRevertAndFlags(t *testing.T) {
	h := newHarness(t)
	fake := &cliFakeSSH{}
	old := sshSystem
	sshSystem = func() (srvaudit.SSHSystem, error) { return fake, nil }
	t.Cleanup(func() { sshSystem = old })
	h.run(exitUsage, "server", "ssh-tunnel-only", "--apply", "--revert")
	root := filepath.Dir(h.netDir)
	h.run(exitOK, "server", "ssh-tunnel-only", "--revert", "--root", root)
	if len(fake.ran) == 0 || !strings.Contains(strings.Join(fake.ran, ";"), "reload sshd") {
		t.Fatalf("revert ran %v", fake.ran)
	}
	// Without a joined device the tunnel range is unknown: nothing happens.
	h.run(exitError, "server", "ssh-tunnel-only", "--apply", "--state-dir", filepath.Join(root, "yok"), "--root", root)
}

func TestServerProviderCheckCommand(t *testing.T) {
	h := newHarness(t)
	root := filepath.Join(filepath.Dir(h.netDir), "kok")
	for name, body := range map[string]string{"proc/sys/kernel/random/boot_id": "a\n", "proc/sys/kernel/osrelease": "6.1\n", "proc/cmdline": "ro\n"} {
		p := filepath.Join(root, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(filepath.Dir(h.netDir), "iz.json")
	if out := h.run(exitOK, "server", "provider-check", "--root", root, "--state", state); !strings.Contains(out, "İlk denetim") {
		t.Fatalf("first:\n%s", out)
	}
	_ = os.WriteFile(filepath.Join(root, "proc/sys/kernel/random/boot_id"), []byte("b\n"), 0o600)
	if out := h.run(exitOK, "server", "provider-check", "--root", root, "--state", state); !strings.Contains(out, "yeniden başlatıldı") {
		t.Fatalf("reboot:\n%s", out)
	}
}
