package filter

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// rawIP builds a minimal IPv4 packet with any protocol number and an
// 8-byte payload.
func rawIP(src, dst netip.Addr, proto uint8) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	return pkt
}

// udp builds a minimal IPv4/UDP packet.
func udp(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[9] = packet.ProtoUDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	return pkt
}

func filterWith(t *testing.T, d *trust.Document, self string) *Filter {
	t.Helper()
	f := New(time.Now)
	dev, ok := d.DeviceByName(self)
	if !ok {
		t.Fatalf("no device %q", self)
	}
	f.Update(d, dev)
	return f
}

// The filter must decide exactly like trust.Document.AllowsIP: deny rules
// win, disabled rules are skipped, numeric protocols match their packets,
// tags and groups resolve (ADR-0021).
func TestFilterAppliesExtendedRules(t *testing.T) {
	d := doc()
	d.Devices[0].Tags = []string{"is"}    // laptop
	d.Devices[2].Tags = []string{"mobil"} // telefon
	d.Groups = []trust.Group{{Name: "sunucular", Members: []string{"masaustu"}}}
	d.Rules = []trust.Rule{
		// Broad allow from tag:is to the group, any protocol ...
		{From: []string{"tag:is"}, To: []string{"group:sunucular"}, Protocol: trust.ProtocolAny},
		// ... except SSH, which is denied whatever the order.
		{From: []string{"*"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}, Action: trust.RuleDeny},
		// GRE from the phone by number.
		{From: []string{"tag:mobil"}, To: []string{"masaustu"}, Protocol: trust.Protocol("47")},
		// A disabled rule opens nothing.
		{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"80"}, Disabled: true},
	}
	m := filterWith(t, d, "masaustu")

	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"tag to group tcp/443", tcp(laptopIP, masaustuIP, 40000, 443, tcpSYN), true},
		{"deny wins over any", tcp(laptopIP, masaustuIP, 40001, 22, tcpSYN), false},
		{"tag to group udp", udp(laptopIP, masaustuIP, 40002, 5353), true},
		{"numeric protocol 47 from tag", rawIP(telefonIP, masaustuIP, 47), true},
		{"numeric rule does not open protocol 50", rawIP(telefonIP, masaustuIP, 50), false},
		{"disabled rule", tcp(telefonIP, masaustuIP, 40003, 80, tcpSYN), false},
		{"no rule for phone tcp", tcp(telefonIP, masaustuIP, 40004, 443, tcpSYN), false},
	}
	for _, c := range cases {
		info, err := packet.Parse(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var port uint16
		if info.Proto == packet.ProtoTCP || info.Proto == packet.ProtoUDP {
			port = info.DstPort
		}
		src := map[netip.Addr]string{laptopIP: "laptop", telefonIP: "telefon"}[info.Src]
		if want := d.AllowsIP(src, "masaustu", info.Proto, port); want != c.want {
			t.Fatalf("%s: test expects %v but the document says %v", c.name, c.want, want)
		}
		if got := m.Inbound(c.pkt); got != c.want {
			t.Errorf("%s: inbound = %v, want %v", c.name, got, c.want)
		}
	}

	// The sending side refuses the same traffic before it enters the tunnel.
	l := filterWith(t, d, "laptop")
	if l.Outbound(tcp(laptopIP, masaustuIP, 40010, 22, tcpSYN)) {
		t.Fatal("outbound SSH passed although a deny rule covers it")
	}
	if !l.Outbound(tcp(laptopIP, masaustuIP, 40011, 443, tcpSYN)) {
		t.Fatal("outbound tcp/443 refused")
	}
	p := filterWith(t, d, "telefon")
	if !p.Outbound(rawIP(telefonIP, masaustuIP, 47)) {
		t.Fatal("outbound GRE refused")
	}
}

// Before ADR-0021 an unknown protocol passed only "any" rules; that stays.
func TestOtherProtocolsStillNeedAnyOrNumber(t *testing.T) {
	m := filterFor("masaustu") // rules: tcp/3389 and icmp only
	if m.Inbound(rawIP(laptopIP, masaustuIP, 47)) {
		t.Fatal("GRE passed without an any or numeric rule")
	}
	d := doc()
	d.Rules = append(d.Rules, trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolAny})
	m = filterWith(t, d, "masaustu")
	if !m.Inbound(rawIP(laptopIP, masaustuIP, 132)) {
		t.Fatal("SCTP refused although an any rule allows it")
	}
}

// ICMPv6 echo matches an "icmp" rule.
func TestICMPRuleCoversICMPv6(t *testing.T) {
	d := doc()
	laptop6, masaustu6 := netip.MustParseAddr("fd7a::1"), netip.MustParseAddr("fd7a::2")
	d.Devices[0].IPv6, d.Devices[1].IPv6 = laptop6, masaustu6
	m := filterWith(t, d, "masaustu")
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 8)
	pkt[6] = packet.ProtoICMPv6
	pkt[7] = 64
	s, dd := laptop6.As16(), masaustu6.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], dd[:])
	pkt[40] = 128 // echo request
	if !m.Inbound(pkt) {
		t.Fatal("ICMPv6 echo refused although an icmp rule allows it")
	}
}

// An exit node forwards a member's new internet flow only when the document
// lets that member use exit nodes (exit_users, ADR-0021).
func TestExitNodeChecksExitUsers(t *testing.T) {
	d := doc()
	users := []string{"laptop"}
	d.ExitUsers = &users
	f := filterWith(t, d, "masaustu")
	f.SetExit(netip.Addr{}, true)
	internet := netip.MustParseAddr("93.184.216.34")
	if !f.Inbound(tcp(laptopIP, internet, 50000, 443, tcpSYN)) {
		t.Fatal("allowed exit user refused")
	}
	if f.Inbound(tcp(telefonIP, internet, 50001, 443, tcpSYN)) {
		t.Fatal("device outside exit_users forwarded to the internet")
	}
	if f.Inbound(echo(telefonIP, internet, packet.ICMPv4EchoRequest, 9)) {
		t.Fatal("ping from a device outside exit_users forwarded")
	}
	// A reply cannot open a flow for the refused device either.
	if f.Outbound(tcp(internet, telefonIP, 443, 50001, tcpSYN|tcpACK)) {
		t.Fatal("reply forwarded for a flow that was never opened")
	}
	// An empty list means nobody, even after an update.
	none := []string{}
	d.ExitUsers = &none
	self, _ := d.DeviceByName("masaustu")
	f.Update(d, self)
	if f.Inbound(tcp(laptopIP, internet, 50002, 443, tcpSYN)) {
		t.Fatal("empty exit_users let a device through")
	}
	// Without the field every device may, as before.
	d.ExitUsers = nil
	f.Update(d, self)
	if !f.Inbound(tcp(telefonIP, internet, 50003, 443, tcpSYN)) {
		t.Fatal("missing exit_users must keep the old behaviour")
	}
}

// Revoking exit permission cuts flows that are already open: the update
// clears the table and the next packet cannot reopen it.
func TestExitPermissionRevocationCutsFlows(t *testing.T) {
	d := doc()
	f := filterWith(t, d, "masaustu")
	f.SetExit(netip.Addr{}, true)
	internet := netip.MustParseAddr("93.184.216.34")
	if !f.Inbound(tcp(laptopIP, internet, 50000, 443, tcpSYN)) {
		t.Fatal("flow not opened")
	}
	none := []string{"telefon"}
	d.ExitUsers = &none
	self, _ := d.DeviceByName("masaustu")
	f.Update(d, self)
	if f.Inbound(tcp(laptopIP, internet, 50000, 443, tcpACK)) {
		t.Fatal("flow survived the loss of exit permission")
	}
}

func TestLimitsValidationAndUse(t *testing.T) {
	if _, err := (Limits{}).WithDefaults(); err != nil {
		t.Fatalf("zero limits: %v", err)
	}
	for _, bad := range []Limits{
		{TCPTimeout: time.Second},
		{UDPTimeout: 2 * time.Hour},
		{ICMPTimeout: time.Millisecond},
		{OtherTimeout: 48 * time.Hour},
		{MaxFlows: 10},
		{MaxFragments: 1 << 30},
		{MaxFlows: -1},
	} {
		if _, err := bad.WithDefaults(); !errors.Is(err, ErrLimits) {
			t.Errorf("%+v accepted", bad)
		}
	}
	now := time.Now()
	f := New(func() time.Time { return now })
	if err := f.SetLimits(Limits{UDPTimeout: 15 * time.Second, MaxFlows: MinFlowLimit}); err != nil {
		t.Fatal(err)
	}
	if l := f.Limits(); l.TCPTimeout != tcpTimeout || l.UDPTimeout != 15*time.Second || l.MaxFlows != MinFlowLimit {
		t.Fatalf("limits = %+v", l)
	}
	d := doc()
	d.Rules = append(d.Rules, trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolUDP, Ports: []string{"1-65535"}})
	self, _ := d.DeviceByName("laptop")
	f.Update(d, self)
	if !f.Outbound(udp(laptopIP, masaustuIP, 40000, 53)) {
		t.Fatal("udp refused")
	}
	now = now.Add(16 * time.Second)
	if f.Inbound(udp(masaustuIP, laptopIP, 53, 40000)) {
		t.Fatal("udp flow outlived the configured timeout")
	}
	// The table limit applies to new flows.
	for i := range MinFlowLimit {
		if !f.Outbound(udp(laptopIP, masaustuIP, uint16(10000+i), 53)) {
			t.Fatalf("flow %d refused before the limit", i)
		}
	}
	if f.Outbound(udp(laptopIP, masaustuIP, 9999, 53)) {
		t.Fatal("flow accepted beyond the configured table size")
	}
}

// FuzzFilterExtendedRules feeds arbitrary packets through filters with
// deny, numeric, tag and exit rules: nothing panics, and a packet the
// document denies never opens a flow.
func FuzzFilterExtendedRules(f *testing.F) {
	f.Add(tcp(laptopIP, masaustuIP, 40000, 22, tcpSYN))
	f.Add(rawIP(telefonIP, masaustuIP, 47))
	f.Add(udp(laptopIP, masaustuIP, 1, 53))
	f.Add(echo(laptopIP, masaustuIP, packet.ICMPv4EchoRequest, 1))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		d := doc()
		d.Devices[0].Tags = []string{"is"}
		d.Rules = []trust.Rule{
			{From: []string{"tag:is"}, To: []string{"masaustu"}, Protocol: trust.ProtocolAny},
			{From: []string{"*"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}, Action: trust.RuleDeny},
			{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: trust.Protocol("47")},
		}
		users := []string{"laptop"}
		d.ExitUsers = &users
		self, _ := d.DeviceByName("masaustu")
		m := New(time.Now)
		m.Update(d, self)
		m.SetExit(netip.Addr{}, true)
		in := m.Inbound(pkt)
		_ = m.Outbound(pkt)
		info, err := packet.Parse(pkt)
		if err != nil || !in || info.Fragment || info.MoreFragments || info.IsICMPError() {
			return
		}
		if info.Proto == packet.ProtoTCP && info.DstPort == 22 && info.Dst == masaustuIP {
			t.Fatalf("denied ssh passed: %+v", info)
		}
		if info.Src == telefonIP && !m.internet(info.Dst) && info.Proto != 47 {
			t.Fatalf("phone passed without a rule: %+v", info)
		}
	})
}
