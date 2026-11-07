//go:build windows

package osnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func fakeWindowsSubnet() (*SubnetRouter, *[]string) {
	var cmds []string
	r := &SubnetRouter{
		run: func(_ context.Context, name string, args ...string) error {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil
		},
		defaultRoute: func(string) (uint32, netip.Addr, error) { return 7, netip.MustParseAddr("192.168.0.1"), nil },
	}
	return r, &cmds
}

func TestWindowsSubnetClientRoutes(t *testing.T) {
	r, cmds := fakeWindowsSubnet()
	lan := netip.MustParsePrefix("192.168.1.0/24")
	ula := netip.MustParsePrefix("fd12::/48")
	if err := r.Apply(RouteConfig{Interface: "OpenScale", Client: []netip.Prefix{lan, ula}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"netsh interface ipv4 add route prefix=192.168.1.0/24 interface=OpenScale store=active metric=1",
		"netsh interface ipv6 add route prefix=fd12::/48 interface=OpenScale store=active metric=1",
	} {
		if !slices.Contains(*cmds, want) {
			t.Fatalf("missing %q in %v", want, *cmds)
		}
	}
	*cmds = nil
	if err := r.Apply(RouteConfig{Interface: "OpenScale", Client: []netip.Prefix{ula}}); err != nil {
		t.Fatal(err)
	}
	if len(*cmds) != 1 || (*cmds)[0] != "netsh interface ipv4 delete route prefix=192.168.1.0/24 interface=OpenScale" {
		t.Fatalf("diff apply: %v", *cmds)
	}
	// Windows is never a router.
	if err := r.Apply(RouteConfig{Interface: "OpenScale", Client: []netip.Prefix{ula}, Own: []netip.Prefix{lan},
		Overlay4: netip.MustParsePrefix("100.80.0.0/16"), Overlay6: netip.MustParsePrefix("fd00::/48")}); !errors.Is(err, ErrRouterUnsupported) {
		t.Fatalf("router on Windows: %v", err)
	}
	*cmds = nil
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if len(*cmds) != 1 || !strings.Contains((*cmds)[0], "delete route prefix=fd12::/48") {
		t.Fatalf("close: %v", *cmds)
	}
}

func TestWindowsExitExceptions(t *testing.T) {
	r, cmds := fakeWindowsSubnet()
	ex := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	// Without an active exit node nothing happens.
	if err := r.Apply(RouteConfig{Interface: "OpenScale", ExitExcept: ex}); err != nil || len(*cmds) != 0 {
		t.Fatalf("inactive exit: %v %v", err, *cmds)
	}
	if err := r.Apply(RouteConfig{Interface: "OpenScale", ExitActive: true, ExitExcept: ex}); err != nil {
		t.Fatal(err)
	}
	if len(*cmds) != 1 || (*cmds)[0] != "netsh interface ipv4 add route prefix=203.0.113.0/24 interface=7 nexthop=192.168.0.1 store=active metric=1" {
		t.Fatalf("exception: %v", *cmds)
	}
	*cmds = nil
	if err := r.Apply(RouteConfig{Interface: "OpenScale"}); err != nil {
		t.Fatal(err)
	}
	if len(*cmds) != 1 || !strings.Contains((*cmds)[0], "delete route prefix=203.0.113.0/24 interface=7") {
		t.Fatalf("exception removal: %v", *cmds)
	}
}
