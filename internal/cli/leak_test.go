package cli

import (
	"context"
	"flag"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// fakeLeak records what the leak commands would do; no test touches the
// host firewall, WFP, nftables or systemd.
type fakeLeak struct {
	installed   bool
	installs    []osnet.KillSwitchConfig
	removed     int
	boot        string
	captive     []netip.Addr
	captiveFor  time.Duration
	revoked     int
	restoreSeen bool
}

func withLeakOps(t *testing.T, goos string, elevated bool) *fakeLeak {
	t.Helper()
	f := &fakeLeak{}
	saved := leakOps
	leakOps = leakSysOps{
		supported: func() bool { return true },
		elevated:  func() bool { return elevated },
		install: func(c osnet.KillSwitchConfig) error {
			f.installs = append(f.installs, c)
			f.installed = true
			return nil
		},
		remove:        func() error { f.removed++; f.installed = false; return nil },
		installed:     func() (bool, error) { return f.installed, nil },
		restore:       func() (bool, error) { return f.restoreSeen, nil },
		bootSupported: func() bool { return true },
		bootEnable:    func(exe string) error { f.boot = "on " + exe; return nil },
		bootDisable:   func() error { f.boot = "off"; return nil },
		bootEnabled:   func() (bool, error) { return strings.HasPrefix(f.boot, "on"), nil },
		allowCaptive: func(a []netip.Addr, d time.Duration) error {
			f.captive, f.captiveFor = a, d
			return nil
		},
		revokeCaptive: func() error { f.revoked++; return nil },
		gateways: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("203.0.113.1")}, nil
		},
		hostFirewall: func(context.Context, string, string) ([]osnet.HostFirewallFinding, error) {
			return []osnet.HostFirewallFinding{{Tool: "ufw", Message: "ufw engelliyor", Fix: "sudo ufw allow in on OpenScale"}}, nil
		},
		executable: func() (string, error) { return "/usr/bin/openscale", nil },
		leakGuard:  func() (bool, error) { return false, nil },
		resolvers:  func() ([]osnet.SystemResolver, error) { return nil, nil },
		localAddrs: func(string) []netip.Addr { return nil },
		goos:       goos,
	}
	t.Cleanup(func() { leakOps = saved })
	return f
}

func TestKillSwitchCaptiveCommand(t *testing.T) {
	f := withLeakOps(t, "linux", false)
	h := newHarness(t)
	h.run(exitError, "killswitch", "captive")
	if f.captive != nil {
		t.Fatal("exception opened without root")
	}
	f = withLeakOps(t, "linux", true)
	out := h.run(exitOK, "killswitch", "captive", "--sure", "2m")
	// Only the local gateway, never the public next hop.
	if len(f.captive) != 1 || f.captive[0] != netip.MustParseAddr("192.168.1.1") || f.captiveFor != 2*time.Minute {
		t.Fatalf("captive %v for %s", f.captive, f.captiveFor)
	}
	if !strings.Contains(out, "http://192.168.1.1/") || !strings.Contains(out, "kendiliğinden kapanır") {
		t.Fatalf("output %q", out)
	}
	h.run(exitUsage, "killswitch", "captive", "--sure", "1h")
	h.run(exitUsage, "killswitch", "captive", "--addr", "8.8.8.8")
	h.run(exitOK, "killswitch", "captive", "--addr", "10.0.0.5")
	if len(f.captive) != 2 || f.captive[1] != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("extra address not added: %v", f.captive)
	}
	h.run(exitOK, "killswitch", "captive", "--off")
	if f.revoked != 1 {
		t.Fatal("not revoked")
	}
}

func TestKillSwitchBootCommand(t *testing.T) {
	f := withLeakOps(t, "linux", true)
	h := newHarness(t)
	h.run(exitOK, "killswitch", "boot", "on")
	if f.boot != "on /usr/bin/openscale" {
		t.Fatalf("boot %q", f.boot)
	}
	if out := h.run(exitOK, "killswitch", "boot", "status"); !strings.Contains(out, "açık") {
		t.Fatalf("status %q", out)
	}
	h.run(exitOK, "killswitch", "boot", "off")
	if f.boot != "off" {
		t.Fatalf("boot %q", f.boot)
	}
	h.run(exitUsage, "killswitch", "boot", "maybe")
	h.run(exitUsage, "killswitch", "boot")

	f = withLeakOps(t, "windows", true)
	if out := h.run(exitOK, "killswitch", "boot", "on"); !strings.Contains(out, "kalıcıdır") || f.boot != "" {
		t.Fatalf("windows boot: %q %q", out, f.boot)
	}
}

func TestKillSwitchRestoreCommand(t *testing.T) {
	f := withLeakOps(t, "linux", true)
	h := newHarness(t)
	if out := h.run(exitOK, "killswitch", "restore"); !strings.Contains(out, "Kayıtlı kill switch yok") {
		t.Fatalf("restore without config: %q", out)
	}
	f.restoreSeen = true
	if out := h.run(exitOK, "killswitch", "restore"); !strings.Contains(out, "geri yüklendi") {
		t.Fatalf("restore: %q", out)
	}
	withLeakOps(t, "linux", false)
	h.run(exitError, "killswitch", "restore")
}

func parseUpLeak(t *testing.T, args ...string) *upLeakFlags {
	t.Helper()
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	l := addUpLeakFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestUpLeakFlags(t *testing.T) {
	f := withLeakOps(t, "linux", true)
	if err := parseUpLeak(t, "--kill-switch").validate(""); err == nil {
		t.Fatal("--kill-switch without --exit-node accepted")
	}
	if err := parseUpLeak(t, "--exit-allow-lan").validate("vps"); err == nil {
		t.Fatal("--exit-allow-lan without --kill-switch accepted")
	}
	if err := parseUpLeak(t, "--host-firewall", "always").validate(""); err == nil {
		t.Fatal("bad --host-firewall accepted")
	}
	l := parseUpLeak(t, "--kill-switch", "--exit-allow-lan")
	if err := l.validate("vps"); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	if err := l.prepare(h.env, "OpenScale"); err != nil {
		t.Fatal(err)
	}
	if len(f.installs) != 1 || f.installs[0] != (osnet.KillSwitchConfig{Interface: "OpenScale", AllowLAN: true}) {
		t.Fatalf("installs %+v", f.installs)
	}
	// While running, leaving the exit node removes the kill switch; when
	// the program stops it stays.
	ctx, cancel := context.WithCancel(context.Background())
	r := l.exitRouter(ctx, &nopRouter{})
	if err := r.Disable(); err != nil || f.removed != 1 {
		t.Fatalf("removed=%d err=%v", f.removed, err)
	}
	f.installed = true
	cancel()
	if err := r.Disable(); err != nil || f.removed != 1 {
		t.Fatalf("stop removed the kill switch: %d", f.removed)
	}
	l.done(h.env)
	if !strings.Contains(h.stdout.String(), "yerinde bırakıldı") {
		t.Fatalf("no notice: %q", h.stdout.String())
	}
	h.stderr.Reset()
	l.checkHostFirewall(context.Background(), h.env, "OpenScale")
	if !strings.Contains(h.stderr.String(), "sudo ufw allow in on OpenScale") {
		t.Fatalf("firewall warning missing: %q", h.stderr.String())
	}

	// Without --kill-switch the router is untouched, and a kill switch
	// left behind is reported.
	plain := parseUpLeak(t)
	inner := &nopRouter{}
	if plain.exitRouter(context.Background(), inner) != inner {
		t.Fatal("router wrapped without --kill-switch")
	}
	h.stderr.Reset()
	if err := plain.prepare(h.env, "OpenScale"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stderr.String(), "killswitch off") {
		t.Fatalf("left-over kill switch not reported: %q", h.stderr.String())
	}
}

type nopRouter struct{}

func (*nopRouter) Enable(trust.Device, *trust.Document, string, conn.Bind) error { return nil }
func (*nopRouter) Disable() error                                                { return nil }
