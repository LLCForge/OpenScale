package testnet

import (
	"net/netip"
	"testing"
)

var (
	natIn    = netip.MustParseAddrPort("192.168.1.2:41641")
	natPeer1 = netip.MustParseAddrPort("203.0.113.1:5000")
	natPeer2 = netip.MustParseAddrPort("203.0.113.1:6000")
	natOther = netip.MustParseAddrPort("198.51.100.9:5000")
)

func TestNATMappingBehaviours(t *testing.T) {
	pub := netip.MustParseAddr("192.0.2.10")
	ei := NewNAT(pub, MapEndpointIndependent, FilterEndpointIndependent, 1)
	a, _ := ei.Outbound(natIn, natPeer1)
	b, _ := ei.Outbound(natIn, natPeer2)
	if a != b || a.Addr() != pub {
		t.Fatalf("endpoint-independent mapping gave %v and %v", a, b)
	}
	seq := NewNAT(pub, MapSequential, FilterAddressPort, 1)
	a, _ = seq.Outbound(natIn, natPeer1)
	b, _ = seq.Outbound(natIn, natPeer2)
	again, _ := seq.Outbound(natIn, natPeer1)
	if b.Port() != a.Port()+1 || again != a {
		t.Fatalf("sequential mapping gave %v, %v, %v", a, b, again)
	}
	rnd := NewNAT(pub, MapRandom, FilterAddress, 1)
	seen := map[uint16]bool{}
	for p := uint16(1); p <= 200; p++ {
		ap, _ := rnd.Outbound(natIn, netip.AddrPortFrom(natPeer1.Addr(), p))
		if seen[ap.Port()] || ap.Port() < natFirstPort {
			t.Fatalf("random mapping reused or low port %v", ap)
		}
		seen[ap.Port()] = true
	}
	if rnd.Mappings() != 200 {
		t.Fatalf("%d mappings", rnd.Mappings())
	}
}

func TestNATFilteringBehaviours(t *testing.T) {
	pub := netip.MustParseAddr("192.0.2.10")
	for _, c := range []struct {
		f                     NATFiltering
		samePort, otherPort   bool
		otherAddr, unmappedOK bool
	}{
		{FilterEndpointIndependent, true, true, true, false},
		{FilterAddress, true, true, false, false},
		{FilterAddressPort, true, false, false, false},
	} {
		n := NewNAT(pub, MapEndpointIndependent, c.f, 1)
		src, _ := n.Outbound(natIn, natPeer1)
		check := func(from netip.AddrPort, port uint16, want bool) {
			t.Helper()
			to, ok := n.Inbound(from, port)
			if ok != want || (ok && to != natIn) {
				t.Fatalf("filter %d: from %v to port %d = %v %v", c.f, from, port, to, ok)
			}
		}
		check(natPeer1, src.Port(), c.samePort)
		check(natPeer2, src.Port(), c.otherPort)
		check(natOther, src.Port(), c.otherAddr)
		check(natPeer1, src.Port()+1, c.unmappedOK)
	}
}

func TestNATNetDelivers(t *testing.T) {
	a := NewNAT(netip.MustParseAddr("192.0.2.10"), MapEndpointIndependent, FilterAddressPort, 1)
	b := NewNAT(netip.MustParseAddr("192.0.2.20"), MapEndpointIndependent, FilterAddressPort, 2)
	w := NewNATNet(a, b)
	bIn := netip.MustParseAddrPort("10.0.0.2:51820")
	// b first opens its mapping toward a's public port (hole punching).
	aPub, _ := a.Outbound(natIn, netip.MustParseAddrPort("192.0.2.20:1"))
	bPub, _ := b.Outbound(bIn, aPub)
	if _, _, ok := w.Send(a, natIn, bPub); !ok {
		t.Fatal("punched hole did not let the packet in")
	}
	if _, _, ok := w.Send(a, natIn, netip.AddrPortFrom(bPub.Addr(), bPub.Port()+1)); ok {
		t.Fatal("packet to an unmapped port passed")
	}
	if w.Sent() != 2 {
		t.Fatalf("sent %d", w.Sent())
	}
}
