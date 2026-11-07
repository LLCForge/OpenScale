//go:build linux

package osnet

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

var testTor = TorRoute{
	Overlay:   "OpenScale",
	OverlayV4: netip.MustParsePrefix("100.80.0.0/16"),
	OverlayV6: netip.MustParsePrefix("fd7a:1:2::/48"),
	Self4:     netip.MustParseAddr("100.80.0.1"),
	TransPort: 9040,
	DNSPort:   5353,
}

func TestTorRouterPlan(t *testing.T) {
	f := newFakeSys()
	r := &TorRouter{ops: f.ops()}
	ctx := context.Background()
	if err := r.Apply(ctx, testTor); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	if len(cmds) != 1 || cmds[0] != "nft -f -" {
		t.Fatalf("commands %v", cmds)
	}
	script := f.stdin[0]
	for _, want := range []string{
		"delete table inet openscale_tor",
		"type nat hook prerouting priority dstnat - 5;",
		`iifname "OpenScale" ip saddr 100.80.0.0/16 ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,`,
		"meta l4proto tcp redirect to :9040",
		// UDP, ICMP and every other IPv4 packet bound for the internet.
		`iifname "OpenScale" ip saddr 100.80.0.0/16 ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop`,
		// All IPv6 internet traffic.
		`iifname "OpenScale" ip6 saddr fd7a:1:2::/48 ip6 daddr != { ::1/128, fc00::/7, fe80::/10, ff00::/8 } drop`,
		// Only redirected connections reach TransPort.
		`iifname != "lo" tcp dport 9040 ct status dnat accept`,
		`iifname != "lo" tcp dport 9040 drop`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script lacks %q:\n%s", want, script)
		}
	}
	// The exit node's own traffic: nothing matches outside the OpenScale
	// interface except the TransPort guard.
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "drop") || strings.Contains(line, "redirect") {
			if !strings.Contains(line, `iifname "OpenScale"`) && !strings.Contains(line, "tcp dport 9040") {
				t.Fatalf("rule matches the host's own traffic: %s", line)
			}
		}
	}
	// No DNS is redirected to Tor by the filter: members' DNS goes through
	// the exit DNS forwarder, and UDP is dropped.
	if strings.Contains(script, "udp") || strings.Contains(script, "5353") {
		t.Fatalf("filter touches UDP or DNSPort:\n%s", script)
	}

	f.reset()
	if err := r.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.commands(), "nft delete table inet openscale_tor")
}

func TestTorRouterRefuses(t *testing.T) {
	f := newFakeSys()
	r := &TorRouter{ops: f.ops()}
	ctx := context.Background()
	bad := testTor
	bad.DNSPort = bad.TransPort
	if err := r.Apply(ctx, bad); err == nil {
		t.Fatal("same ports accepted")
	}
	bad = testTor
	bad.Overlay = "eth0; rm"
	if err := r.Apply(ctx, bad); err == nil {
		t.Fatal("bad interface name accepted")
	}
	f.have["nft"] = false
	if err := r.Apply(ctx, testTor); err == nil {
		t.Fatal("applied without nft")
	}
	if len(f.commands()) != 0 {
		t.Fatalf("commands run: %v", f.commands())
	}
}

func TestTorRouterProbe(t *testing.T) {
	f := newFakeSys()
	r := &TorRouter{ops: f.ops()}
	if h := r.Probe(testTor); h.Up() || h.Err == nil {
		t.Fatalf("probe without /proc %+v", h)
	}
	f.files["/proc/net/tcp"] = testProcTCP
	f.files["/proc/net/udp"] = testProcUDP
	if h := r.Probe(testTor); !h.Up() || h.Err != nil {
		t.Fatalf("probe %+v", h)
	}
}

func TestRecoverRemovesTorTable(t *testing.T) {
	f := newFakeSys()
	removeTorTable(context.Background(), f.ops())
	indexOf(t, f.commands(), "nft delete table inet openscale_tor")
}
