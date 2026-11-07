package trust

import (
	"errors"
	"net/netip"
	"testing"
)

func readdressDoc() *Document {
	return &Document{
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd00:1:2:3::/64"),
		Coordinator: &Coordinator{Endpoint: "vps.example:4039",
			IPv4: netip.MustParseAddr("100.80.0.1"), IPv6: netip.MustParseAddr("fd00:1:2:3::1")},
		Devices: []Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.2"), IPv6: netip.MustParseAddr("fd00:1:2:3::2")},
			{Name: "nas", IPv4: netip.MustParseAddr("100.80.7.9"), IPv6: netip.MustParseAddr("fd00:1:2:3::3")},
		},
		Invites: []Invite{{ID: "inv1", IPv4: netip.MustParseAddr("100.80.0.4")}},
	}
}

func TestReaddressKeepsHostPart(t *testing.T) {
	doc := readdressDoc()
	moves, err := doc.Readdress(netip.MustParsePrefix("10.44.0.0/16"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if len(moves) != 4 {
		t.Fatalf("moves = %+v", moves)
	}
	if got := doc.Devices[1].IPv4; got != netip.MustParseAddr("10.44.7.9") {
		t.Fatalf("nas = %s", got)
	}
	if doc.Coordinator.IPv4 != netip.MustParseAddr("10.44.0.1") || doc.Invites[0].IPv4 != netip.MustParseAddr("10.44.0.4") {
		t.Fatalf("coordinator/invite not moved: %s %s", doc.Coordinator.IPv4, doc.Invites[0].IPv4)
	}
	if doc.Devices[0].IPv6 != netip.MustParseAddr("fd00:1:2:3::2") {
		t.Fatal("IPv6 changed although its prefix did not")
	}
}

func TestReaddressNarrowAndWiden(t *testing.T) {
	doc := readdressDoc()
	// 100.80.7.9 does not fit a /24: it gets the lowest free address.
	moves, err := doc.Readdress(netip.MustParsePrefix("10.1.2.0/24"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Devices[1].IPv4; got != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("nas = %s (moves %+v)", got, moves)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range []netip.Addr{doc.Coordinator.IPv4, doc.Devices[0].IPv4, doc.Devices[1].IPv4, doc.Invites[0].IPv4} {
		if seen[a] || !isHostAddr(doc.IPv4Prefix, a) || a == doc.DNSResolverIPv4() {
			t.Fatalf("bad or duplicate address %s", a)
		}
		seen[a] = true
	}
	// Widening keeps every address.
	doc = readdressDoc()
	moves, err = doc.Readdress(netip.MustParsePrefix("100.64.0.0/10"), netip.Prefix{})
	if err != nil || len(moves) != 0 {
		t.Fatalf("widen: moves=%+v err=%v", moves, err)
	}
}

func TestReaddressRefusesStaleReferencesAndNoop(t *testing.T) {
	doc := readdressDoc()
	doc.Hosts = []NamedAddress{{Name: "lab", Prefix: netip.MustParsePrefix("100.80.9.0/24")}}
	doc.Rules = []Rule{{From: []string{"100.80.0.2/32"}, To: []string{"nas"}}}
	_, err := doc.Readdress(netip.MustParsePrefix("10.44.0.0/16"), netip.Prefix{})
	if !errors.Is(err, ErrReaddressStale) {
		t.Fatalf("err = %v", err)
	}
	if doc := readdressDoc(); func() error { _, err := doc.Readdress(doc.IPv4Prefix, netip.Prefix{}); return err }() == nil {
		t.Fatal("same range accepted")
	}
	if _, err := readdressDoc().Readdress(netip.MustParsePrefix("10.0.0.0/31"), netip.Prefix{}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
	// A range too small for every address fails instead of overlapping.
	if _, err := readdressDoc().Readdress(netip.MustParsePrefix("10.9.9.0/30"), netip.Prefix{}); err == nil {
		t.Fatal("overfull range accepted")
	}
}

func TestReaddressIPv6(t *testing.T) {
	doc := readdressDoc()
	if _, err := doc.Readdress(netip.Prefix{}, netip.MustParsePrefix("fd99:aa::/64")); err != nil {
		t.Fatal(err)
	}
	if doc.Devices[0].IPv6 != netip.MustParseAddr("fd99:aa::2") || doc.Devices[0].IPv4 != netip.MustParseAddr("100.80.0.2") {
		t.Fatalf("got %s %s", doc.Devices[0].IPv6, doc.Devices[0].IPv4)
	}
}
