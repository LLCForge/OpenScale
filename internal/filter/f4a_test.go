package filter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Ranges in groups and exit_users in the packet filter (#277, ADR-0232).

func rangeFilterFor(self string) *Filter {
	end := time.Now().Add(time.Hour)
	d := &trust.Document{
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		Devices: []trust.Device{
			{Name: "laptop", IPv4: laptopIP, ExpiresAt: end},
			{Name: "masaustu", IPv4: masaustuIP, ExpiresAt: end, Routes: []netip.Prefix{lanNet}},
			{Name: "telefon", IPv4: telefonIP, ExpiresAt: end},
		},
		Groups: []trust.Group{
			{Name: "kameralar", Members: []string{"192.168.1.8/29"}},
			{Name: "yonetim", Members: []string{netip.PrefixFrom(laptopIP, 32).String()}},
		},
		Rules: []trust.Rule{
			{From: []string{"group:yonetim"}, To: []string{"group:kameralar"}, Protocol: trust.ProtocolTCP, Ports: []string{"554"}},
		},
	}
	f := New(time.Now)
	dev, _ := d.DeviceByName(self)
	f.Update(d, dev)
	return f
}

func TestF4AGroupRangesInFilter(t *testing.T) {
	laptop := rangeFilterFor("laptop")
	if !laptop.Outbound(tcp(laptopIP, nasIP, 50000, 554, packet.TCPSyn)) {
		t.Fatal("laptop (by address) -> camera range must pass")
	}
	if laptop.Outbound(tcp(laptopIP, otherLAN, 50001, 554, packet.TCPSyn)) {
		t.Fatal("outside the camera range must stay closed")
	}
	telefon := rangeFilterFor("telefon")
	if telefon.Outbound(tcp(telefonIP, nasIP, 50000, 554, packet.TCPSyn)) {
		t.Fatal("telefon is not in the management range")
	}
	router := rangeFilterFor("masaustu")
	if !router.Inbound(tcp(laptopIP, nasIP, 50002, 554, packet.TCPSyn)) {
		t.Fatal("the router must forward the group range rule")
	}
	if router.Outbound(tcp(nasIP, laptopIP, 554, 50003, packet.TCPSyn)) {
		t.Fatal("cameras may not open connections to members")
	}
}
