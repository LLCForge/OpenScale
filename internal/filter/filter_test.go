package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

var (
	laptopIP   = netip.MustParseAddr("100.80.0.1")
	masaustuIP = netip.MustParseAddr("100.80.0.2")
	telefonIP  = netip.MustParseAddr("100.80.0.3")
)

func doc() *trust.Document {
	return &trust.Document{
		Devices: []trust.Device{
			{Name: "laptop", IPv4: laptopIP},
			{Name: "masaustu", IPv4: masaustuIP},
			{Name: "telefon", IPv4: telefonIP},
		},
		Rules: []trust.Rule{
			{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"3389"}},
			{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP},
		},
	}
}

// tcp builds a minimal IPv4/TCP packet.
func tcp(src, dst netip.Addr, sport, dport uint16, flags uint8) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[9] = packet.ProtoTCP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	pkt[32] = 5 << 4
	pkt[33] = flags
	return pkt
}

func filterFor(self string) *Filter {
	d := doc()
	f := New(time.Now)
	dev, _ := d.DeviceByName(self)
	f.Update(d, dev)
	return f
}

func TestInboundRequiresRule(t *testing.T) {
	masaustu := filterFor("masaustu")
	if !masaustu.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("laptop -> masaustu:3389 must be allowed")
	}
	if masaustu.Inbound(tcp(laptopIP, masaustuIP, 50001, 22, packet.TCPSyn)) {
		t.Fatal("laptop -> masaustu:22 must be denied")
	}
	if masaustu.Inbound(tcp(telefonIP, masaustuIP, 50002, 3389, packet.TCPSyn)) {
		t.Fatal("telefon has no rule and must be denied")
	}
	if !masaustu.Outbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("reply on an allowed connection must pass")
	}
	if masaustu.Outbound(tcp(masaustuIP, laptopIP, 40000, 3389, packet.TCPSyn)) {
		t.Fatal("masaustu may not open a connection to laptop")
	}
}

func TestOutboundTracksReplies(t *testing.T) {
	laptop := filterFor("laptop")
	if laptop.Inbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("unsolicited packet must be dropped")
	}
	if !laptop.Outbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("allowed outbound connection must pass")
	}
	if !laptop.Inbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("reply to tracked connection must pass")
	}
	if !laptop.Outbound(tuntest.Ping(masaustuIP, laptopIP)) {
		t.Fatal("ICMP to masaustu must pass")
	}
}

// echo builds an ICMPv4 echo request or reply with an identifier.
func echo(src, dst netip.Addr, icmpType uint8, id uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[9] = packet.ProtoICMPv4
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	pkt[20] = icmpType
	binary.BigEndian.PutUint16(pkt[24:26], id)
	return pkt
}

// A peer must not be able to ping back just because it was pinged first:
// ICMP has no ports, so a naive flow key would treat its request as a reply.
func TestICMPRequestsNeverRideOnTrackedFlows(t *testing.T) {
	laptop, masaustu := filterFor("laptop"), filterFor("masaustu")
	req := echo(laptopIP, masaustuIP, packet.ICMPv4EchoRequest, 7)
	if !laptop.Outbound(req) || !masaustu.Inbound(req) {
		t.Fatal("laptop -> masaustu echo request must pass")
	}
	reply := echo(masaustuIP, laptopIP, packet.ICMPv4EchoReply, 7)
	if !masaustu.Outbound(reply) || !laptop.Inbound(reply) {
		t.Fatal("echo reply with the same identifier must pass")
	}
	reverse := echo(masaustuIP, laptopIP, packet.ICMPv4EchoRequest, 7)
	if masaustu.Outbound(reverse) || laptop.Inbound(reverse) {
		t.Fatal("masaustu has no rule to ping laptop")
	}
	if laptop.Inbound(echo(masaustuIP, laptopIP, packet.ICMPv4EchoReply, 8)) {
		t.Fatal("unsolicited echo reply must be dropped")
	}
}

func TestSpoofedSourceAndUpdateClearsState(t *testing.T) {
	laptop := filterFor("laptop")
	if laptop.Outbound(tcp(telefonIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("packet with a foreign source address must be dropped")
	}
	laptop.Outbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn))
	if laptop.Flows() != 1 {
		t.Fatalf("flows = %d", laptop.Flows())
	}
	d := doc()
	d.Rules = nil
	self, _ := d.DeviceByName("laptop")
	laptop.Update(d, self)
	if laptop.Inbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("removing the rule must cut existing connections")
	}
	laptop.Clear()
	if laptop.Outbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("cleared filter must drop everything")
	}
}

func TestFlowsExpire(t *testing.T) {
	now := time.Now()
	d := doc()
	f := New(func() time.Time { return now })
	self, _ := d.DeviceByName("laptop")
	f.Update(d, self)
	f.Outbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn))
	now = now.Add(tcpTimeout + time.Second)
	if f.Inbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("expired flow must not admit packets")
	}
}

func TestMalformedDropped(t *testing.T) {
	f := filterFor("laptop")
	if f.Inbound([]byte{0x45, 0, 0}) || f.Outbound(nil) {
		t.Fatal("malformed packets must be dropped")
	}
}

func TestExitClientAllowsOnlyRepliesFromInternet(t *testing.T) {
	f := filterFor("laptop")
	internet := netip.MustParseAddr("93.184.216.34")
	out := tcp(laptopIP, internet, 50000, 443, tcpSYN)
	if f.Outbound(out) {
		t.Fatal("internet traffic allowed without an exit node")
	}
	f.SetExit(masaustuIP, false)
	if !f.Outbound(out) {
		t.Fatal("internet traffic through the exit node refused")
	}
	if !f.Inbound(tcp(internet, laptopIP, 443, 50000, tcpSYN|tcpACK)) {
		t.Fatal("reply from the internet refused")
	}
	if f.Inbound(tcp(internet, laptopIP, 443, 50001, tcpSYN)) {
		t.Fatal("unsolicited internet connection accepted")
	}
	if f.Outbound(tcp(laptopIP, netip.MustParseAddr("192.168.1.10"), 50002, 80, tcpSYN)) {
		t.Fatal("private address treated as internet")
	}
	if f.Outbound(tcp(laptopIP, netip.MustParseAddr("100.64.1.1"), 50003, 80, tcpSYN)) {
		t.Fatal("shared address space treated as internet")
	}
	// DNS to the exit node is allowed even without a rule; other ports are not.
	if !f.Outbound(tcp(laptopIP, masaustuIP, 50010, 53, tcpSYN)) {
		t.Fatal("DNS to the exit node refused")
	}
	if f.Outbound(tcp(laptopIP, masaustuIP, 50011, 25, tcpSYN)) {
		t.Fatal("non-DNS port to the exit node allowed without a rule")
	}
}

func TestExitServerForwardsMembersOnly(t *testing.T) {
	f := filterFor("masaustu")
	internet := netip.MustParseAddr("93.184.216.34")
	in := tcp(laptopIP, internet, 50000, 443, tcpSYN)
	if f.Inbound(in) {
		t.Fatal("forwarding without the exit role")
	}
	f.SetExit(netip.Addr{}, true)
	if !f.Inbound(in) {
		t.Fatal("member traffic not forwarded")
	}
	if !f.Outbound(tcp(internet, laptopIP, 443, 50000, tcpSYN|tcpACK)) {
		t.Fatal("reply to member not forwarded")
	}
	if f.Outbound(tcp(internet, laptopIP, 443, 50001, tcpSYN)) {
		t.Fatal("internet opened a connection to a member")
	}
	if f.Inbound(tcp(laptopIP, netip.MustParseAddr("10.0.0.5"), 50004, 22, tcpSYN)) {
		t.Fatal("member reached the exit node's private network")
	}
}

const (
	tcpSYN = 0x02
	tcpACK = 0x10
)
