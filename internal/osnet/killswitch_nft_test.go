package osnet

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

func TestNftKillSwitchScript(t *testing.T) {
	s, err := nftKillSwitchScript(KillSwitchConfig{Interface: "OpenScale"})
	if err != nil {
		t.Fatal(err)
	}
	// Atomic replacement: create, delete, recreate in one nft -f.
	if !strings.HasPrefix(s, "table inet openscale_killswitch\ndelete table inet openscale_killswitch\ntable inet openscale_killswitch {") {
		t.Fatalf("script does not replace the table atomically:\n%s", s)
	}
	for _, want := range []string{
		`oifname "lo" accept`,
		`oifname "OpenScale" accept`,
		`iifname "OpenScale" accept`,
		"meta mark 0x4f53 accept",
		"udp sport 68 udp dport 67 accept",
		"udp sport 546 udp dport 547 accept",
		"nd-neighbor-solicit",
		"ct state established,related accept",
		"ip daddr @captive4 tcp dport { 80, 443 } accept",
		"flags timeout",
		"hook output", "hook input", "hook forward",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "192.168.0.0/16") {
		t.Fatal("local network permitted although AllowLAN is off")
	}
	// Every chain ends with a drop: deny by default.
	if n := strings.Count(s, "counter drop\n\t}"); n != 3 {
		t.Fatalf("%d chains end in drop, want 3:\n%s", n, s)
	}

	lan, err := nftKillSwitchScript(KillSwitchConfig{Interface: "OpenScale", AllowLAN: true})
	if err != nil {
		t.Fatal(err)
	}
	// The DNS drops come before the local network permit (first match wins).
	drop := strings.Index(lan, "udp dport { 53, 853 } drop")
	permit := strings.Index(lan, "255.255.255.255/32 } accept")
	if drop < 0 || permit < 0 || drop > permit {
		t.Fatalf("LAN DNS must be dropped before the LAN permit:\n%s", lan)
	}
	if !strings.Contains(lan, "fc00::/7") {
		t.Fatal("IPv6 local ranges missing")
	}

	before, err := nftKillSwitchScript(KillSwitchConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(before, `oifname "OpenScale"`) || strings.Contains(before, `oifname ""`) {
		t.Fatalf("tunnel permit without a tunnel:\n%s", before)
	}
	for _, bad := range []string{`a"b`, "a b", "eth0;", "x{", strings.Repeat("a", 16), "a/b"} {
		if _, err := nftKillSwitchScript(KillSwitchConfig{Interface: bad}); err == nil {
			t.Fatalf("interface %q accepted", bad)
		}
	}
}

func TestNftLeakGuardScript(t *testing.T) {
	s, err := nftLeakGuardScript("OpenScale")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet openscale_leakguard",
		`oifname { "lo", "OpenScale" } accept`,
		"meta mark 0x4f53 accept",
		"udp dport { 53, 853 } counter drop",
		"tcp dport { 53, 853 } counter drop",
		"ip6 daddr 2000::/3 counter drop",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("leak guard lacks %q:\n%s", want, s)
		}
	}
	if strings.Index(s, "accept") > strings.Index(s, "drop") {
		t.Fatal("permits must come before the drops")
	}
	if _, err := nftLeakGuardScript(""); err == nil {
		t.Fatal("empty interface accepted")
	}
}

func TestCaptiveValidation(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	if _, err := validCaptive([]netip.Addr{gw}, CaptiveDefaultDuration); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, -time.Second, CaptiveMaxDuration + time.Second} {
		if _, err := validCaptive([]netip.Addr{gw}, d); err == nil {
			t.Fatalf("duration %s accepted", d)
		}
	}
	for _, a := range []string{"8.8.8.8", "203.0.113.1", "fe80::1", "2001:db8::1", "127.0.0.1"} {
		if _, err := validCaptive([]netip.Addr{netip.MustParseAddr(a)}, time.Minute); err == nil {
			t.Fatalf("%s accepted for a captive exception", a)
		}
	}
	if _, err := validCaptive(nil, time.Minute); err == nil {
		t.Fatal("no address accepted")
	}
	args := nftCaptiveArgs([]netip.Addr{gw, netip.MustParseAddr("10.0.0.1")}, 5*time.Minute)
	if got := strings.Join(args, " "); got != "add element inet openscale_killswitch captive4 { 192.168.1.1 timeout 300s, 10.0.0.1 timeout 300s }" {
		t.Fatalf("captive args = %q", got)
	}
}

func TestCaptivePlanOpensOnlyWebToGateway(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	plan := append(killSwitchPlan(true, false), captivePlan([]netip.Addr{gw})...)
	if len(plan) > maxKillSwitchFilters {
		t.Fatal("plan too large")
	}
	for _, r := range captivePlan([]netip.Addr{gw}) {
		if !r.Permit || r.IPv6 || r.Inbound || r.Protocol != protoTCP || (r.RemotePort != 80 && r.RemotePort != 443) || r.Prefix.Bits() != 32 {
			t.Fatalf("bad captive rule %+v", r)
		}
		if r.Weight <= ksWeightBlock || r.Weight >= ksWeightLAN {
			t.Fatalf("captive weight %d out of order", r.Weight)
		}
	}
	web := ksConn{protocol: protoTCP, localPort: 50000, remotePort: 443, remote: gw}
	if ok, _ := ksDecide(plan, web); !ok {
		t.Fatal("portal page blocked during the exception")
	}
	web.remote = netip.MustParseAddr("203.0.113.7")
	if ok, _ := ksDecide(plan, web); ok {
		t.Fatal("exception opened the internet")
	}
}

type fakeRouter struct {
	enabled, disabled int
	err               error
}

func (f *fakeRouter) Enable(trust.Device, *trust.Document, string, conn.Bind) error {
	f.enabled++
	return f.err
}
func (f *fakeRouter) Disable() error { f.disabled++; return nil }

func TestKillSwitchGuard(t *testing.T) {
	var installed []KillSwitchConfig
	removed := 0
	stopping := false
	inner := &fakeRouter{}
	g := &KillSwitchGuard{Inner: inner, AllowLAN: true, Stopping: func() bool { return stopping },
		Install: func(c KillSwitchConfig) error { installed = append(installed, c); return nil },
		Remove:  func() error { removed++; return nil }}
	if err := g.Prepare("OpenScale"); err != nil {
		t.Fatal(err)
	}
	if err := g.Enable(trust.Device{}, nil, "OpenScale", nil); err != nil {
		t.Fatal(err)
	}
	if len(installed) != 2 || installed[1] != (KillSwitchConfig{Interface: "OpenScale", AllowLAN: true}) || inner.enabled != 1 {
		t.Fatalf("installed=%+v enabled=%d", installed, inner.enabled)
	}
	// Leaving the exit node removes the kill switch after the routes.
	if err := g.Disable(); err != nil || removed != 1 || inner.disabled != 1 {
		t.Fatalf("disable: removed=%d disabled=%d err=%v", removed, inner.disabled, err)
	}
	// A stop keeps it.
	stopping = true
	if err := g.Disable(); err != nil || removed != 1 {
		t.Fatalf("stop removed the kill switch (removed=%d)", removed)
	}
	// A failed install never enables the routes.
	g.Install = func(KillSwitchConfig) error { return errors.New("nft yok") }
	if err := g.Enable(trust.Device{}, nil, "OpenScale", nil); err == nil || inner.enabled != 1 {
		t.Fatalf("routes enabled without kill switch (err=%v)", err)
	}
}

func TestNftInputDrops(t *testing.T) {
	rs := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
table inet openscale_killswitch {
	chain input {
		type filter hook input priority filter - 5; policy drop;
	}
}
table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
	}
}
`
	got := nftInputDrops(rs, "OpenScale")
	if len(got) != 1 || got[0] != "inet filter input" {
		t.Fatalf("drops = %v", got)
	}
	allowed := strings.Replace(rs, "ct state established,related accept", `iifname "OpenScale" accept`, 1)
	if got := nftInputDrops(allowed, "OpenScale"); len(got) != 0 {
		t.Fatalf("table permitting the tunnel reported: %v", got)
	}
}

func TestUFWBlocks(t *testing.T) {
	status := "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n"
	if !ufwBlocks(status, "OpenScale") {
		t.Fatal("blocking ufw not found")
	}
	if ufwBlocks(status+"Anywhere on OpenScale       ALLOW IN    Anywhere\n", "OpenScale") {
		t.Fatal("ufw rule for the tunnel ignored")
	}
	if ufwBlocks("Status: inactive\n", "OpenScale") {
		t.Fatal("inactive ufw reported")
	}
	for _, m := range []string{HostFirewallAuto, HostFirewallWarn, HostFirewallOff} {
		if ValidHostFirewallMode(m) != nil {
			t.Fatal(m)
		}
	}
	if ValidHostFirewallMode("yes") == nil {
		t.Fatal("bad mode accepted")
	}
}
