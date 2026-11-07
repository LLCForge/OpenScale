package filter

import (
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Rule language extensions in the packet filter (ADR-0120).

func TestFilterICMPTypesAndCIDR(t *testing.T) {
	d := doc()
	d.Rules = []trust.Rule{
		{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP, ICMPTypes: []string{"echo"}},
		{From: []string{"100.80.0.1/32"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}},
		{From: []string{"masaustu"}, To: []string{"telefon"}, Protocol: trust.ProtocolUDP, Ports: []string{"9"}, Bidirectional: true},
	}
	m := filterWith(t, d, "masaustu")
	if !m.Inbound(echo(telefonIP, masaustuIP, 8, 1)) {
		t.Fatal("echo request allowed by type must pass")
	}
	if m.Inbound(echo(telefonIP, masaustuIP, 13, 2)) {
		t.Fatal("timestamp request must not pass an echo-only rule")
	}
	if !m.Inbound(tcp(laptopIP, masaustuIP, 40000, 22, tcpSYN)) || m.Inbound(tcp(telefonIP, masaustuIP, 40001, 22, tcpSYN)) {
		t.Fatal("CIDR source must match only the device holding the address")
	}
	if !m.Inbound(udp(telefonIP, masaustuIP, 9, 9)) {
		t.Fatal("bidirectional rule must admit the reverse direction")
	}
}

func TestFilterTimeWindowEndsFlows(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	d := doc()
	d.Rules = []trust.Rule{
		{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"3389"}, NotAfter: now.Add(30 * time.Minute)},
		{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"3389"}},
	}
	f := New(clock)
	self, _ := d.DeviceByName("masaustu")
	f.Update(d, self)
	if !f.Inbound(tcp(telefonIP, masaustuIP, 40000, 3389, tcpSYN)) || !f.Inbound(tcp(laptopIP, masaustuIP, 40001, 3389, tcpSYN)) {
		t.Fatal("both connections must open inside the window")
	}
	now = now.Add(31 * time.Minute)
	if f.Inbound(tcp(telefonIP, masaustuIP, 40000, 3389, tcpACK)) {
		t.Fatal("a connection of a closed window must end")
	}
	if !f.Inbound(tcp(laptopIP, masaustuIP, 40001, 3389, tcpACK)) {
		t.Fatal("a connection another rule allows must continue")
	}
	if f.Inbound(tcp(telefonIP, masaustuIP, 40002, 3389, tcpSYN)) {
		t.Fatal("no new connection after the window")
	}
}
