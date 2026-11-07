package osnet

import (
	"net/netip"
	"testing"
)

func countKind(plan []ksRule, kind ksMatchKind) int {
	n := 0
	for _, r := range plan {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

// Every one of the four layers must end in a default block and carry the
// same permits.
func TestKillSwitchPlanCoversAllLayers(t *testing.T) {
	for _, tc := range []struct{ tunnel, lan bool }{{false, false}, {true, false}, {true, true}, {false, true}} {
		plan := killSwitchPlan(tc.tunnel, tc.lan)
		if len(plan) > maxKillSwitchFilters {
			t.Fatalf("%+v: %d filters exceed the fixed key range", tc, len(plan))
		}
		type layer struct{ v6, in bool }
		blocks := map[layer]int{}
		perLayer := map[layer]int{}
		for _, r := range plan {
			l := layer{r.IPv6, r.Inbound}
			perLayer[l]++
			if r.Kind == ksMatchAll {
				if r.Permit || r.Weight != ksWeightBlock {
					t.Fatalf("default rule must be the lowest block: %+v", r)
				}
				blocks[l]++
			}
		}
		if len(perLayer) != 4 {
			t.Fatalf("%+v: plan uses %d layers, want 4", tc, len(perLayer))
		}
		for l, n := range blocks {
			if n != 1 {
				t.Fatalf("%+v: layer %+v has %d default blocks", tc, l, n)
			}
		}
		if len(blocks) != 4 {
			t.Fatalf("%+v: a layer has no default block", tc)
		}
		if got := countKind(plan, ksMatchLoopback); got != 4 {
			t.Fatalf("loopback permits = %d", got)
		}
		if got := countKind(plan, ksMatchApp); got != 4 {
			t.Fatalf("program permits = %d", got)
		}
		wantTunnel := 0
		if tc.tunnel {
			wantTunnel = 4
		}
		if got := countKind(plan, ksMatchTunnel); got != wantTunnel {
			t.Fatalf("%+v: tunnel permits = %d, want %d", tc, got, wantTunnel)
		}
		wantLAN := 0
		if tc.lan {
			wantLAN = 2 * (len(lanPrefixes4) + len(lanPrefixes6))
		}
		if got := countKind(plan, ksMatchRemotePrefix); got != wantLAN {
			t.Fatalf("%+v: LAN permits = %d, want %d", tc, got, wantLAN)
		}
		if got := countKind(plan, ksMatchRemotePrefixPort); got != 2*wantLAN { // 53 and 853
			t.Fatalf("%+v: LAN DNS blocks = %d, want %d", tc, got, wantLAN)
		}
	}
}

func TestKillSwitchPlanSystemExceptions(t *testing.T) {
	plan := killSwitchPlan(true, false)
	dhcp, dhcp6, ndp := 0, 0, 0
	for _, r := range plan {
		switch r.Kind {
		case ksMatchUDPPorts:
			if r.Protocol != protoUDP || !r.Permit || r.Weight != ksWeightSystem {
				t.Fatalf("bad DHCP rule %+v", r)
			}
			switch {
			case !r.IPv6 && r.LocalPort == 68 && r.RemotePort == 67:
				dhcp++
			case r.IPv6 && r.LocalPort == 546 && r.RemotePort == 547:
				dhcp6++
			default:
				t.Fatalf("bad DHCP ports %+v", r)
			}
		case ksMatchICMPTypes:
			if !r.IPv6 || r.Protocol != protoICMPv6 || r.ICMPLow != 133 || r.ICMPHigh != 137 || !r.Permit {
				t.Fatalf("bad neighbor discovery rule %+v", r)
			}
			ndp++
		}
	}
	if dhcp != 2 || dhcp6 != 2 || ndp != 2 {
		t.Fatalf("DHCP rules %d, DHCPv6 rules %d, neighbor discovery rules %d; want 2 each", dhcp, dhcp6, ndp)
	}
}

// ksConn is one connection as the WFP ALE layers see it.
type ksConn struct {
	ipv6, inbound, loopback, tunnel, app bool
	protocol                             uint8
	localPort, remotePort                uint16
	remote                               netip.Addr
}

// ksMatches mirrors the conditions killswitch_windows.go builds for r.
func ksMatches(r ksRule, c ksConn) bool {
	if r.IPv6 != c.ipv6 || r.Inbound != c.inbound {
		return false
	}
	switch r.Kind {
	case ksMatchAll:
		return true
	case ksMatchLoopback:
		return c.loopback
	case ksMatchTunnel:
		return c.tunnel
	case ksMatchApp:
		return c.app
	case ksMatchUDPPorts:
		return c.protocol == r.Protocol && c.localPort == r.LocalPort && c.remotePort == r.RemotePort
	case ksMatchICMPTypes:
		return c.protocol == r.Protocol && c.localPort >= uint16(r.ICMPLow) && c.localPort <= uint16(r.ICMPHigh)
	case ksMatchRemotePrefix:
		return r.Prefix.Contains(c.remote)
	case ksMatchRemotePrefixPort:
		// Protocol 0 matches every protocol; the captive portal permits
		// (killswitch_captive_windows.go) also match TCP.
		return r.Prefix.Contains(c.remote) && c.remotePort == r.RemotePort && (r.Protocol == 0 || r.Protocol == c.protocol)
	}
	return false
}

// ksDecide applies WFP's rule inside one sublayer: the matching filter with
// the highest weight decides. It reports false when nothing matches, which
// cannot happen with a default block in every layer.
func ksDecide(plan []ksRule, c ksConn) (permit, matched bool) {
	best := -1
	for _, r := range plan {
		if !ksMatches(r, c) || int(r.Weight) <= best {
			continue
		}
		best, permit = int(r.Weight), r.Permit
	}
	return permit, best >= 0
}

// The kill switch must never cut OpenScale off from its coordinator: the
// device could not learn a new document or reach a relay, and with a
// coordinator given by name it could not even resolve it. openscale.exe
// resolves the name with Go's own resolver, so the DNS query is the
// program's own connection too.
func TestKillSwitchKeepsCoordinatorReachable(t *testing.T) {
	coordinators := []netip.Addr{
		netip.MustParseAddr("203.0.113.7"),  // public VPS
		netip.MustParseAddr("192.168.1.20"), // coordinator at home, same LAN
		netip.MustParseAddr("2001:db8::7"),
	}
	resolvers := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("1.1.1.1")}
	for _, tc := range []struct{ tunnel, lan bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		plan := killSwitchPlan(tc.tunnel, tc.lan)
		for _, in := range []bool{false, true} {
			for _, a := range coordinators {
				c := ksConn{ipv6: a.Is6(), inbound: in, app: true, protocol: protoUDP, localPort: 50000, remotePort: 41820, remote: a}
				if ok, _ := ksDecide(plan, c); !ok {
					t.Fatalf("%+v: OpenScale cannot reach the coordinator %s (inbound %v)", tc, a, in)
				}
			}
			for _, a := range resolvers {
				c := ksConn{ipv6: a.Is6(), inbound: in, app: true, protocol: protoUDP, localPort: 50001, remotePort: dnsPort, remote: a}
				if ok, _ := ksDecide(plan, c); !ok {
					t.Fatalf("%+v: OpenScale cannot resolve the coordinator through %s", tc, a)
				}
				// The same query from another program (the Windows DNS
				// client) stays blocked: DNS leaves only through the tunnel.
				c.app = false
				if ok, matched := ksDecide(plan, c); ok || !matched {
					t.Fatalf("%+v: DNS from another program to %s must be blocked", tc, a)
				}
			}
		}
		// Other programs never reach the internet past the filters.
		web := ksConn{protocol: 6, localPort: 50002, remotePort: 443, remote: netip.MustParseAddr("203.0.113.7")}
		if ok, _ := ksDecide(plan, web); ok {
			t.Fatalf("%+v: another program reached the internet", tc)
		}
		// DHCPv6 keeps IPv6 addressing alive.
		dhcp6 := ksConn{ipv6: true, protocol: protoUDP, localPort: 546, remotePort: 547, remote: netip.MustParseAddr("ff02::1:2")}
		if ok, _ := ksDecide(plan, dhcp6); !ok {
			t.Fatalf("%+v: DHCPv6 blocked", tc)
		}
	}
}

// DNS to a local resolver must lose against nothing but the tunnel, the
// program and loopback: it outweighs the local network permit.
func TestKillSwitchPlanBlocksLANDNS(t *testing.T) {
	plan := killSwitchPlan(true, true)
	for _, r := range plan {
		switch r.Kind {
		case ksMatchRemotePrefixPort:
			if r.Permit || (r.RemotePort != dnsPort && r.RemotePort != dotPort) {
				t.Fatalf("LAN DNS rule must block port 53 or 853: %+v", r)
			}
			if r.Weight <= ksWeightLAN || r.Weight >= ksWeightApp {
				t.Fatalf("LAN DNS block weight %d out of order", r.Weight)
			}
		case ksMatchRemotePrefix:
			if !r.Permit || r.Weight != ksWeightLAN {
				t.Fatalf("bad LAN permit %+v", r)
			}
		}
		if (r.Kind == ksMatchRemotePrefix || r.Kind == ksMatchRemotePrefixPort) && r.Prefix.Addr().Is6() != r.IPv6 {
			t.Fatalf("prefix family does not match the layer: %+v", r)
		}
	}
	// The overlay and public addresses are never local.
	for _, a := range []string{"100.80.0.1", "8.8.8.8", "2001:db8::1"} {
		addr := netip.MustParseAddr(a)
		for _, p := range append(append([]netip.Prefix{}, lanPrefixes4...), lanPrefixes6...) {
			if p.Contains(addr) {
				t.Fatalf("%s must not be a local range (%s)", a, p)
			}
		}
	}
}

func TestKillSwitchWeightsOrdered(t *testing.T) {
	order := []uint8{ksWeightLoopback, ksWeightTunnel, ksWeightApp, ksWeightSystem, ksWeightLANDNS, ksWeightLAN, ksWeightCaptive, ksWeightBlock}
	for i := 1; i < len(order); i++ {
		if order[i] >= order[i-1] {
			t.Fatalf("weights not strictly descending: %v", order)
		}
	}
	if order[0] > 15 {
		t.Fatal("FWP_UINT8 weights must stay in 0..15")
	}
}
