package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

var (
	laptopIP6   = netip.MustParseAddr("fd7a:0:0:1::1")
	masaustuIP6 = netip.MustParseAddr("fd7a:0:0:1::2")
	telefonIP6  = netip.MustParseAddr("fd7a:0:0:1::3")
	internetIP  = netip.MustParseAddr("93.184.216.34")
	routerIP    = netip.MustParseAddr("203.0.113.7")
)

// doc6 is doc() with IPv6 addresses and overlay prefixes.
func doc6() *trust.Document {
	d := doc()
	d.IPv4Prefix = netip.MustParsePrefix("100.80.0.0/16")
	d.IPv6Prefix = netip.MustParsePrefix("fd7a:0:0:1::/64")
	for i, a := range []netip.Addr{laptopIP6, masaustuIP6, telefonIP6} {
		d.Devices[i].IPv6 = a
	}
	d.Rules = append(d.Rules, trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolUDP, Ports: []string{"5000"}})
	return d
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func filter6For(self string, c *clock) *Filter {
	d := doc6()
	f := New(c.Now)
	dev, _ := d.DeviceByName(self)
	f.Update(d, dev)
	return f
}

// ipv4 builds an IPv4 packet; offset is in 8-byte units.
func ipv4(src, dst netip.Addr, proto uint8, id uint16, more bool, offset uint16, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	flags := offset & 0x1fff
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flags)
	pkt[8] = 64
	pkt[9] = proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)
	return pkt
}

// ipv6 builds an IPv6 packet, with a fragment header when frag is true.
func ipv6(src, dst netip.Addr, proto uint8, frag bool, id uint32, more bool, offset uint16, payload []byte) []byte {
	body := payload
	next := proto
	if frag {
		fh := make([]byte, 8)
		fh[0] = proto
		v := offset << 3
		if more {
			v |= 1
		}
		binary.BigEndian.PutUint16(fh[2:4], v)
		binary.BigEndian.PutUint32(fh[4:8], id)
		body = append(fh, payload...)
		next = 44
	}
	pkt := make([]byte, 40+len(body))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(body)))
	pkt[6] = next
	pkt[7] = 64
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	copy(pkt[40:], body)
	return pkt
}

// udpSeg is a UDP header claiming length total, followed by data.
func udpSeg(sport, dport uint16, total int, data []byte) []byte {
	seg := make([]byte, 8, 8+len(data))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint16(seg[4:6], uint16(total))
	return append(seg, data...)
}

func tcpSeg(sport, dport uint16, flags uint8) []byte {
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	seg[12] = 5 << 4
	seg[13] = flags
	return seg
}

// icmpError wraps the start of orig in an ICMP error of the given type.
func icmpError(src, dst netip.Addr, typ, code uint8, orig []byte) []byte {
	quote := orig
	if len(quote) > 48 {
		quote = quote[:48]
	}
	msg := append([]byte{typ, code, 0, 0, 0, 0, 0x05, 0x00}, quote...)
	if src.Is4() {
		return ipv4(src, dst, packet.ProtoICMPv4, 99, false, 0, msg)
	}
	return ipv6(src, dst, packet.ProtoICMPv6, false, 0, false, 0, msg)
}

func TestFragmentsFollowFirstFragmentIPv4(t *testing.T) {
	c := &clock{now: time.Now()}
	masaustu := filter6For("masaustu", c)
	data := make([]byte, 16)
	first := ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 77, true, 0, udpSeg(40000, 5000, 8+16+24, data))
	middle := ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 77, true, 3, make([]byte, 16))
	last := ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 77, false, 5, make([]byte, 8))

	if masaustu.Inbound(middle) {
		t.Fatal("a fragment without its first fragment must be dropped")
	}
	if !masaustu.Inbound(first) {
		t.Fatal("allowed first fragment refused")
	}
	if !masaustu.Inbound(middle) || !masaustu.Inbound(last) {
		t.Fatal("later fragments of an allowed packet refused")
	}
	if masaustu.Inbound(last) {
		t.Fatal("the last fragment closes the packet; a replay must be dropped")
	}

	// Another identification, protocol or source does not inherit it.
	if !masaustu.Inbound(ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 78, true, 0, udpSeg(40001, 5000, 64, data))) {
		t.Fatal("second allowed first fragment refused")
	}
	for name, p := range map[string][]byte{
		"other id":     ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 79, false, 3, data),
		"other proto":  ipv4(laptopIP, masaustuIP, packet.ProtoTCP, 78, false, 3, data),
		"other source": ipv4(telefonIP, masaustuIP, packet.ProtoUDP, 78, false, 3, data),
	} {
		if masaustu.Inbound(p) {
			t.Fatalf("%s: fragment accepted", name)
		}
	}
	// The verdict is per direction.
	if masaustu.Outbound(ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 78, false, 3, data)) {
		t.Fatal("an inbound verdict must not open the outbound direction")
	}

	// The verdict expires.
	c.now = c.now.Add(fragTimeout + time.Second)
	if masaustu.Inbound(ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 78, false, 3, data)) {
		t.Fatal("expired fragment verdict still applied")
	}
}

func TestRefusedFirstFragmentDropsTheRest(t *testing.T) {
	c := &clock{now: time.Now()}
	masaustu := filter6For("masaustu", c)
	// Port 22 has no rule.
	first := ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 5, true, 0, udpSeg(40000, 22, 64, make([]byte, 16)))
	if masaustu.Inbound(first) {
		t.Fatal("first fragment to a closed port accepted")
	}
	if masaustu.Inbound(ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 5, false, 3, make([]byte, 16))) {
		t.Fatal("rest of a refused packet accepted")
	}
	// A first fragment too short for the transport header is malformed.
	if masaustu.Inbound(ipv4(laptopIP, masaustuIP, packet.ProtoTCP, 6, true, 0, make([]byte, 8))) {
		t.Fatal("tiny first fragment accepted")
	}
}

func TestFragmentsOfTrackedTCPAndUpdateClears(t *testing.T) {
	c := &clock{now: time.Now()}
	laptop := filter6For("laptop", c)
	if !laptop.Outbound(ipv4(laptopIP, masaustuIP, packet.ProtoTCP, 1, false, 0, tcpSeg(50000, 3389, tcpSYN))) {
		t.Fatal("SYN refused")
	}
	// The reply comes back fragmented.
	if !laptop.Inbound(ipv4(masaustuIP, laptopIP, packet.ProtoTCP, 900, true, 0, tcpSeg(3389, 50000, tcpACK))) {
		t.Fatal("first fragment of a reply refused")
	}
	d := doc6()
	self, _ := d.DeviceByName("laptop")
	laptop.Update(d, self)
	if laptop.Inbound(ipv4(masaustuIP, laptopIP, packet.ProtoTCP, 900, false, 3, make([]byte, 8))) {
		t.Fatal("a new document must forget fragment verdicts")
	}
}

func TestFragmentTableIsBounded(t *testing.T) {
	c := &clock{now: time.Now()}
	masaustu := filter6For("masaustu", c)
	for i := range MaxFragments {
		masaustu.frags[fragKey{inbound: true, src: telefonIP, dst: masaustuIP, proto: packet.ProtoUDP, id: uint32(i) + 1000}] = c.now.Add(fragTimeout)
	}
	first := ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 1, true, 0, udpSeg(40000, 5000, 64, make([]byte, 16)))
	if masaustu.Inbound(first) {
		t.Fatal("a full table must refuse new fragmented packets")
	}
	c.now = c.now.Add(fragTimeout + time.Second)
	if !masaustu.Inbound(first) {
		t.Fatal("expired entries must make room")
	}
	if len(masaustu.frags) != 1 {
		t.Fatalf("expired entries left: %d", len(masaustu.frags))
	}
}

func TestFragmentsFollowFirstFragmentIPv6(t *testing.T) {
	c := &clock{now: time.Now()}
	masaustu := filter6For("masaustu", c)
	first := ipv6(laptopIP6, masaustuIP6, packet.ProtoUDP, true, 0xdeadbeef, true, 0, udpSeg(40000, 5000, 200, make([]byte, 24)))
	rest := ipv6(laptopIP6, masaustuIP6, packet.ProtoUDP, true, 0xdeadbeef, false, 4, make([]byte, 16))
	if masaustu.Inbound(rest) {
		t.Fatal("IPv6 fragment without its first fragment accepted")
	}
	if !masaustu.Inbound(first) || !masaustu.Inbound(rest) {
		t.Fatal("allowed IPv6 fragments refused")
	}
	other := ipv6(laptopIP6, masaustuIP6, packet.ProtoUDP, true, 0xdeadbef0, false, 4, make([]byte, 16))
	if masaustu.Inbound(other) {
		t.Fatal("IPv6 fragment with another identification accepted")
	}
	// An atomic fragment (offset 0, no more fragments) is a whole packet.
	atomic := ipv6(laptopIP6, masaustuIP6, packet.ProtoUDP, true, 1, false, 0, udpSeg(40000, 5000, 8, nil))
	if !masaustu.Inbound(atomic) {
		t.Fatal("atomic fragment refused")
	}
	if len(masaustu.frags) != 0 {
		t.Fatalf("finished packets left %d entries", len(masaustu.frags))
	}
}

func TestICMPErrorsFollowTheirFlow(t *testing.T) {
	c := &clock{now: time.Now()}
	laptop := filter6For("laptop", c)
	syn := ipv4(laptopIP, masaustuIP, packet.ProtoTCP, 1, false, 0, tcpSeg(50000, 3389, tcpSYN))
	if !laptop.Outbound(syn) {
		t.Fatal("SYN refused")
	}
	// Fragmentation needed from the peer itself, about the tracked flow.
	if !laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, syn)) {
		t.Fatal("fragmentation needed for a tracked flow dropped")
	}
	if !laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 3, syn)) {
		t.Fatal("port unreachable for a tracked flow dropped")
	}
	untracked := ipv4(laptopIP, masaustuIP, packet.ProtoTCP, 2, false, 0, tcpSeg(50001, 3389, tcpSYN))
	if laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, untracked)) {
		t.Fatal("error about an untracked flow passed")
	}
	// A third device may not report about the laptop's flow to masaustu.
	if laptop.Inbound(icmpError(telefonIP, laptopIP, 3, 1, syn)) {
		t.Fatal("error from an uninvolved peer passed")
	}
	// The error must go to the quoted packet's sender.
	if laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, ipv4(masaustuIP, laptopIP, packet.ProtoTCP, 3, false, 0, tcpSeg(3389, 50000, tcpACK)))) {
		t.Fatal("error quoting a packet the laptop did not send passed")
	}
	// No errors about errors, and nothing from a truncated quote.
	if laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, icmpError(laptopIP, masaustuIP, 3, 3, syn))) {
		t.Fatal("error about an error passed")
	}
	if laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, syn[:24])) {
		t.Fatal("error with a truncated quote passed")
	}
	// Errors do not keep a flow alive.
	c.now = c.now.Add(tcpTimeout + time.Second)
	if laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, syn)) {
		t.Fatal("error about an expired flow passed")
	}
}

func TestOutboundICMPErrorForInboundFlow(t *testing.T) {
	c := &clock{now: time.Now()}
	masaustu := filter6For("masaustu", c)
	req := ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 1, false, 0, udpSeg(40000, 5000, 8, nil))
	if !masaustu.Inbound(req) {
		t.Fatal("allowed UDP refused")
	}
	if !masaustu.Outbound(icmpError(masaustuIP, laptopIP, 3, 3, req)) {
		t.Fatal("port unreachable back to the sender dropped")
	}
	if masaustu.Outbound(icmpError(masaustuIP, telefonIP, 3, 3, req)) {
		t.Fatal("error sent to someone other than the sender passed")
	}
}

func TestICMPv6PacketTooBig(t *testing.T) {
	c := &clock{now: time.Now()}
	laptop := filter6For("laptop", c)
	out := ipv6(laptopIP6, masaustuIP6, packet.ProtoUDP, false, 0, false, 0, udpSeg(40000, 5000, 8, nil))
	if !laptop.Outbound(out) {
		t.Fatal("allowed IPv6 UDP refused")
	}
	if !laptop.Inbound(icmpError(masaustuIP6, laptopIP6, packet.ICMPv6PacketTooBig, 0, out)) {
		t.Fatal("packet too big for a tracked flow dropped")
	}
	if !laptop.Inbound(icmpError(masaustuIP6, laptopIP6, packet.ICMPv6DestUnreachable, 4, out)) {
		t.Fatal("IPv6 unreachable for a tracked flow dropped")
	}
	other := ipv6(laptopIP6, masaustuIP6, packet.ProtoUDP, false, 0, false, 0, udpSeg(40000, 6000, 8, nil))
	if laptop.Inbound(icmpError(masaustuIP6, laptopIP6, packet.ICMPv6PacketTooBig, 0, other)) {
		t.Fatal("packet too big for an untracked flow passed")
	}
	// An ICMPv6 error must quote an IPv6 packet.
	if laptop.Inbound(icmpError(masaustuIP6, laptopIP6, packet.ICMPv6PacketTooBig, 0, ipv4(laptopIP, masaustuIP, packet.ProtoUDP, 1, false, 0, udpSeg(40000, 5000, 8, nil)))) {
		t.Fatal("ICMPv6 error quoting IPv4 passed")
	}
}

func TestICMPErrorsForEchoFlows(t *testing.T) {
	c := &clock{now: time.Now()}
	laptop := filter6For("laptop", c)
	req := echo(laptopIP, masaustuIP, packet.ICMPv4EchoRequest, 42)
	if !laptop.Outbound(req) {
		t.Fatal("echo request refused")
	}
	if !laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, req)) {
		t.Fatal("error about a tracked echo dropped")
	}
	if laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, echo(laptopIP, masaustuIP, packet.ICMPv4EchoRequest, 43))) {
		t.Fatal("error about another echo identifier passed")
	}
	// Echo requests still never ride on tracked flows.
	if laptop.Inbound(echo(masaustuIP, laptopIP, packet.ICMPv4EchoRequest, 42)) {
		t.Fatal("reverse echo request passed")
	}
}

func TestICMPErrorsThroughExitNode(t *testing.T) {
	c := &clock{now: time.Now()}
	laptop := filter6For("laptop", c)
	laptop.SetExit(masaustuIP, false)
	out := ipv4(laptopIP, internetIP, packet.ProtoTCP, 1, false, 0, tcpSeg(50000, 443, tcpSYN))
	if !laptop.Outbound(out) {
		t.Fatal("internet traffic through the exit refused")
	}
	// A router on the internet path reports a smaller MTU.
	if !laptop.Inbound(icmpError(routerIP, laptopIP, 3, 4, out)) {
		t.Fatal("fragmentation needed from an internet router dropped")
	}
	// So may the exit node itself.
	if !laptop.Inbound(icmpError(masaustuIP, laptopIP, 3, 4, out)) {
		t.Fatal("fragmentation needed from the exit node dropped")
	}
	// Another peer may not.
	if laptop.Inbound(icmpError(telefonIP, laptopIP, 3, 4, out)) {
		t.Fatal("error from a non-exit peer about internet traffic passed")
	}
	// A private address is never an internet router.
	if laptop.Inbound(icmpError(netip.MustParseAddr("192.168.1.1"), laptopIP, 3, 4, out)) {
		t.Fatal("error from a private address passed")
	}

	// The exit node forwards an internet router's error to the member.
	exit := filter6For("masaustu", c)
	exit.SetExit(netip.Addr{}, true)
	if !exit.Inbound(out) {
		t.Fatal("member traffic not forwarded")
	}
	if !exit.Outbound(icmpError(routerIP, laptopIP, 3, 4, out)) {
		t.Fatal("exit node dropped an error for a forwarded flow")
	}
	if exit.Outbound(icmpError(routerIP, telefonIP, 3, 4, out)) {
		t.Fatal("exit node sent an error to the wrong member")
	}
	unrelated := ipv4(telefonIP, internetIP, packet.ProtoTCP, 1, false, 0, tcpSeg(50000, 443, tcpSYN))
	if exit.Outbound(icmpError(routerIP, telefonIP, 3, 4, unrelated)) {
		t.Fatal("exit node forwarded an error for an unknown flow")
	}
}

func TestShieldsRefuseIncomingConnections(t *testing.T) {
	c := &clock{now: time.Now()}
	masaustu := filter6For("masaustu", c)
	laptop := filter6For("laptop", c)
	in := tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)
	if !masaustu.Inbound(in) {
		t.Fatal("rule-allowed connection refused without shields")
	}
	masaustu.SetShields(true)
	if masaustu.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPAck)) {
		t.Fatal("a connection opened before the shields went up must end")
	}
	if masaustu.Inbound(tcp(laptopIP, masaustuIP, 50001, 3389, packet.TCPSyn)) {
		t.Fatal("shields let a new connection in despite the rule")
	}
	if masaustu.Inbound(echo(laptopIP, masaustuIP, packet.ICMPv4EchoRequest, 1)) {
		t.Fatal("shields let a ping in")
	}

	// Replies to this device's own connections still pass.
	laptop.SetShields(true)
	if !laptop.Outbound(tcp(laptopIP, masaustuIP, 50002, 3389, packet.TCPSyn)) {
		t.Fatal("outgoing connection refused with shields up")
	}
	if !laptop.Inbound(tcp(masaustuIP, laptopIP, 3389, 50002, packet.TCPSyn|packet.TCPAck)) {
		t.Fatal("reply refused with shields up")
	}
	if !laptop.Outbound(echo(laptopIP, masaustuIP, packet.ICMPv4EchoRequest, 9)) ||
		!laptop.Inbound(echo(masaustuIP, laptopIP, packet.ICMPv4EchoReply, 9)) {
		t.Fatal("own ping refused with shields up")
	}

	masaustu.SetShields(false)
	if !masaustu.Inbound(tcp(laptopIP, masaustuIP, 50003, 3389, packet.TCPSyn)) {
		t.Fatal("rules must apply again once the shields are down")
	}
}
