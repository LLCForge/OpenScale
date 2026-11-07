package filter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Subnet routing in the filter (ADR-0133).

var (
	lanNet   = netip.MustParsePrefix("192.168.1.0/24")
	nasIP    = netip.MustParseAddr("192.168.1.10")
	otherLAN = netip.MustParseAddr("192.168.2.10")
)

func routedFilterDoc() *trust.Document {
	end := time.Now().Add(time.Hour)
	return &trust.Document{
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		Devices: []trust.Device{
			{Name: "laptop", IPv4: laptopIP, ExpiresAt: end},
			{Name: "masaustu", IPv4: masaustuIP, ExpiresAt: end, Routes: []netip.Prefix{lanNet}},
			{Name: "telefon", IPv4: telefonIP, ExpiresAt: end},
		},
		Rules: []trust.Rule{
			{From: []string{"laptop"}, To: []string{"192.168.1.0/24"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}},
			{From: []string{"*"}, To: []string{"*"}, Protocol: trust.ProtocolTCP, Ports: []string{"80"}},
		},
	}
}

func routedFilterFor(self string) *Filter {
	d := routedFilterDoc()
	f := New(time.Now)
	dev, _ := d.DeviceByName(self)
	f.Update(d, dev)
	return f
}

func TestRoutedClientNeedsExplicitRule(t *testing.T) {
	laptop := routedFilterFor("laptop")
	if !laptop.Outbound(tcp(laptopIP, nasIP, 50000, 445, packet.TCPSyn)) {
		t.Fatal("laptop -> NAS:445 has a rule and must pass")
	}
	if !laptop.Inbound(tcp(nasIP, laptopIP, 445, 50000, packet.TCPAck)) {
		t.Fatal("the NAS reply must pass")
	}
	if laptop.Inbound(tcp(nasIP, laptopIP, 445, 50001, packet.TCPSyn)) {
		t.Fatal("the NAS may not open connections without a rule")
	}
	if laptop.Outbound(tcp(laptopIP, nasIP, 50002, 80, packet.TCPSyn)) {
		t.Fatal("the wildcard rule must not reach routed hosts")
	}
	if laptop.Outbound(tcp(laptopIP, otherLAN, 50003, 445, packet.TCPSyn)) {
		t.Fatal("addresses outside the routes must be refused")
	}
	telefon := routedFilterFor("telefon")
	if telefon.Outbound(tcp(telefonIP, nasIP, 50000, 445, packet.TCPSyn)) {
		t.Fatal("telefon has no route rule")
	}
}

func TestRoutedRouterForwardsOnlyAllowed(t *testing.T) {
	router := routedFilterFor("masaustu")
	if !router.Inbound(tcp(laptopIP, nasIP, 50000, 445, packet.TCPSyn)) {
		t.Fatal("router must forward laptop -> NAS:445")
	}
	if !router.Outbound(tcp(nasIP, laptopIP, 445, 50000, packet.TCPAck)) {
		t.Fatal("router must forward the NAS reply")
	}
	if router.Inbound(tcp(telefonIP, nasIP, 50000, 445, packet.TCPSyn)) {
		t.Fatal("telefon may not reach the NAS")
	}
	if router.Inbound(tcp(laptopIP, nasIP, 50001, 22, packet.TCPSyn)) {
		t.Fatal("only the allowed port")
	}
	if router.Outbound(tcp(nasIP, telefonIP, 445, 50000, packet.TCPSyn)) {
		t.Fatal("the NAS may not open connections to members without a rule")
	}
	if router.Inbound(tcp(laptopIP, otherLAN, 50002, 445, packet.TCPSyn)) {
		t.Fatal("router must not forward outside its routes")
	}
	router.SetShields(true)
	if router.Inbound(tcp(laptopIP, nasIP, 50003, 445, packet.TCPSyn)) {
		t.Fatal("shields refuse new routed flows")
	}
}

func TestRoutedWithoutRoutesUnchanged(t *testing.T) {
	// A filter without routes behaves exactly as before.
	f := filterFor("laptop")
	if f.Outbound(tcp(laptopIP, nasIP, 50000, 445, packet.TCPSyn)) {
		t.Fatal("no routes: private destinations stay refused")
	}
}

func TestExternalExitDNSReplies(t *testing.T) {
	f := filterFor("laptop")
	dns := netip.MustParseAddr("10.66.0.1")
	f.SetExit(dns, false)
	q, err := packet.BuildUDP4(laptopIP, dns, 40000, 53, []byte("q"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Outbound(q) {
		t.Fatal("DNS to the plain WireGuard exit's resolver must pass")
	}
	r, _ := packet.BuildUDP4(dns, laptopIP, 53, 40000, []byte("a"))
	if !f.Inbound(r) {
		t.Fatal("its reply must pass")
	}
	other, _ := packet.BuildUDP4(laptopIP, dns, 40001, 80, []byte("x"))
	if f.Outbound(other) {
		t.Fatal("only DNS goes to the resolver address")
	}
}
