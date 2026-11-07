//go:build linux

package osnet

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

var testUpstream = UpstreamRoute{
	Interface: "os-up0",
	MTU:       1420,
	Address4:  netip.MustParseAddr("10.68.12.34"),
	Address6:  netip.MustParseAddr("fc00:bbbb:bbbb:bb01::5:c21"),
	Overlay:   "OpenScale",
	OverlayV4: netip.MustParsePrefix("100.80.0.0/16"),
	OverlayV6: netip.MustParsePrefix("fd7a:1:2::/48"),
}

func newTestUpstreamRouter() (*UpstreamRouter, *fakeSys) {
	f := newFakeSys()
	f.files["/proc/net/if_inet6"] = "fe800000000000000000000000000001 02 40 20 80 eth0\n"
	return &UpstreamRouter{ops: f.ops()}, f
}

func TestUpstreamRouterFailClosed(t *testing.T) {
	u, f := newTestUpstreamRouter()
	ctx := context.Background()

	// Drop routing before any tunnel exists.
	blocked := testUpstream
	blocked.Address4, blocked.Address6 = netip.Addr{}, netip.Addr{}
	if err := u.Apply(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	nft := indexOf(t, cmds, "nft -f -")
	drop4 := indexOf(t, cmds, "ip -4 route replace unreachable default metric 65535 table 20308")
	drop6 := indexOf(t, cmds, "ip -6 route replace unreachable default metric 65535 table 20308")
	indexOf(t, cmds, "ip -4 route replace 100.80.0.0/16 dev OpenScale table 20308")
	indexOf(t, cmds, "ip -6 route replace fd7a:1:2::/48 dev OpenScale table 20308")
	rule4 := indexOf(t, cmds, "ip -4 rule add priority 5251 fwmark 0x4f56 lookup 20308")
	indexOf(t, cmds, "ip -6 rule add priority 5251 fwmark 0x4f56 lookup 20308")
	// The filter, then the drop routes, then the rules that use them.
	if nft > drop4 || drop4 > rule4 || drop6 > rule4 {
		t.Fatalf("order:\n%s", strings.Join(cmds, "\n"))
	}
	for _, c := range cmds {
		if strings.Contains(c, "default dev") || strings.Contains(c, " from ") {
			t.Fatalf("tunnel route without a tunnel: %s", c)
		}
	}
	script := f.stdin[0]
	for _, want := range []string{
		`iifname "OpenScale" ip saddr 100.80.0.0/16 ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10,`,
		`meta mark set 0x4f56 ct mark set meta mark`,
		`iifname != "OpenScale" ct mark 0x4f56 meta mark set ct mark`,
		`oifname "os-up0" meta mark != 0x4f56 drop`,
		`iifname "OpenScale" meta mark 0x4f56 oifname != "os-up0" drop`,
		`iifname "os-up0" ct state { established, related } accept`,
		`iifname "os-up0" drop`,
		`oifname "os-up0" meta mark 0x4f56 masquerade`,
		`tcp option maxseg size set rt mtu`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script lacks %q:\n%s", want, script)
		}
	}
	// rp_filter is loose (2) in the fake host: no src_valid_mark change.
	if f.value("net/ipv4/conf/all/src_valid_mark") != "0" {
		t.Fatal("src_valid_mark raised with loose rp_filter")
	}

	// The tunnel comes up: addresses, the "from" rules and default routes.
	f.reset()
	if err := u.Apply(ctx, testUpstream); err != nil {
		t.Fatal(err)
	}
	cmds = f.commands()
	for _, want := range []string{
		"ip link set dev os-up0 mtu 1420 up",
		"ip -4 addr replace 10.68.12.34/32 dev os-up0",
		"ip -6 addr replace fc00:bbbb:bbbb:bb01::5:c21/128 dev os-up0 nodad",
		"ip -4 rule add priority 5250 from 10.68.12.34 lookup 20308",
		"ip -6 rule add priority 5250 from fc00:bbbb:bbbb:bb01::5:c21 lookup 20308",
		"ip -4 route replace default dev os-up0 metric 1 table 20308",
		"ip -6 route replace default dev os-up0 metric 1 table 20308",
	} {
		indexOf(t, cmds, want)
	}
	if slices.Contains(cmds, "ip -4 rule add priority 5251 fwmark 0x4f56 lookup 20308") {
		t.Fatal("mark rule added twice")
	}
	// A fail-closed upstream never goes direct.
	if err := u.SetDirect(ctx, true); err == nil {
		t.Fatal("fail-closed upstream switched to direct")
	}

	f.reset()
	if err := u.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	cmds = f.commands()
	indexOf(t, cmds, "ip -4 rule del priority 5250")
	indexOf(t, cmds, "ip -6 rule del priority 5251")
	indexOf(t, cmds, "ip -4 route flush table 20308")
	indexOf(t, cmds, "nft delete table inet openscale_upstream")
}

func TestUpstreamRouterFailOpen(t *testing.T) {
	u, f := newTestUpstreamRouter()
	ctx := context.Background()
	r := testUpstream
	r.FailOpen = true
	r.Address6 = netip.Addr{} // provider without IPv6
	if err := u.Apply(ctx, r); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	indexOf(t, cmds, "ip -4 route del unreachable default metric 65535 table 20308")
	// IPv6 without a provider address stays dropped even fail-open.
	indexOf(t, cmds, "ip -6 route replace unreachable default metric 65535 table 20308")
	if slices.Contains(cmds, "ip -6 route replace default dev os-up0 metric 1 table 20308") {
		t.Fatal("IPv6 routed into a tunnel without an IPv6 address")
	}
	if strings.Contains(f.stdin[0], `oifname != "os-up0" drop`) {
		t.Fatal("fail-open kept the filter barrier")
	}
	f.reset()
	if err := u.SetDirect(ctx, true); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.commands(), "ip -4 route del default dev os-up0 metric 1 table 20308")
	f.reset()
	if err := u.SetDirect(ctx, false); err != nil {
		t.Fatal(err)
	}
	indexOf(t, f.commands(), "ip -4 route replace default dev os-up0 metric 1 table 20308")
}

func TestUpstreamRouterStrictRPAndValidation(t *testing.T) {
	u, f := newTestUpstreamRouter()
	f.files["/proc/sys/net/ipv4/conf/all/rp_filter"] = "1\n"
	ctx := context.Background()
	if err := u.Apply(ctx, testUpstream); err != nil {
		t.Fatal(err)
	}
	if f.value("net/ipv4/conf/all/src_valid_mark") != "1" {
		t.Fatal("strict rp_filter without src_valid_mark")
	}
	if err := u.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if f.value("net/ipv4/conf/all/src_valid_mark") != "0" {
		t.Fatal("src_valid_mark not restored")
	}

	for _, bad := range []func(*UpstreamRoute){
		func(r *UpstreamRoute) { r.Interface = "x;rm" },
		func(r *UpstreamRoute) { r.Interface = r.Overlay },
		func(r *UpstreamRoute) { r.MTU = 9000 },
		func(r *UpstreamRoute) { r.Address4 = netip.MustParseAddr("fd00::1") },
		func(r *UpstreamRoute) { r.OverlayV4 = netip.Prefix{} },
	} {
		r := testUpstream
		bad(&r)
		if err := u.Apply(ctx, r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	f.have["nft"] = false
	if err := (&UpstreamRouter{ops: f.ops()}).Apply(ctx, testUpstream); err == nil {
		t.Fatal("applied without nft")
	}
}
