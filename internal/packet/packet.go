// Package packet parses the IP headers the daemon needs for filtering and
// builds the UDP datagrams used by the control protocol. Every length is
// checked before use; anything that cannot be parsed is rejected so callers
// can fail closed.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// IP protocol numbers.
const (
	ProtoICMPv4 uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// TCP flags.
const (
	TCPFin uint8 = 0x01
	TCPSyn uint8 = 0x02
	TCPRst uint8 = 0x04
	TCPAck uint8 = 0x10
)

const (
	ipv4HeaderMin   = 20
	ipv6HeaderLen   = 40
	udpHeaderLen    = 8
	tcpHeaderMin    = 20
	maxIPv6ExtChain = 8
)

// ErrMalformed is returned for packets that cannot be parsed safely.
var ErrMalformed = errors.New("malformed packet")

// Info is the parsed view of an IP packet.
type Info struct {
	Src, Dst netip.Addr
	Proto    uint8
	// SrcPort and DstPort are set for TCP and UDP.
	SrcPort, DstPort uint16
	// TCPFlags is set for TCP.
	TCPFlags uint8
	// Payload is the UDP payload (UDP only).
	Payload []byte
	// Fragment is true for non-first fragments, which carry no ports.
	Fragment bool
	// MoreFragments is the "more fragments" flag; together with Fragment
	// false it marks the first fragment of a fragmented packet. FragID is
	// the fragment identification (16 bits for IPv4, 32 for IPv6).
	MoreFragments bool
	FragID        uint32
	// ICMPType and ICMPCode are set for ICMPv4 and ICMPv6; ICMPID is the
	// echo identifier for echo requests and replies.
	ICMPType uint8
	ICMPCode uint8
	ICMPID   uint16
	// Embedded is the start of the original packet quoted by an ICMP
	// error (destination unreachable, packet too big); see ParseEmbedded.
	Embedded []byte
}

// FirstFragment reports whether the packet is the first fragment of a
// fragmented packet: it carries the ports, the others do not.
func (i Info) FirstFragment() bool { return i.MoreFragments && !i.Fragment }

// ICMP echo types.
const (
	ICMPv4EchoReply   uint8 = 0
	ICMPv4EchoRequest uint8 = 8
	ICMPv6EchoRequest uint8 = 128
	ICMPv6EchoReply   uint8 = 129
)

// ICMP error types whose quoted packet the filter matches to a flow.
const (
	ICMPv4DestUnreachable uint8 = 3
	ICMPv6DestUnreachable uint8 = 1
	ICMPv6PacketTooBig    uint8 = 2
)

// IsICMPError reports whether the packet is a destination unreachable
// (including "fragmentation needed") or an ICMPv6 packet too big message.
func (i Info) IsICMPError() bool {
	return (i.Proto == ProtoICMPv4 && i.ICMPType == ICMPv4DestUnreachable) ||
		(i.Proto == ProtoICMPv6 && (i.ICMPType == ICMPv6DestUnreachable || i.ICMPType == ICMPv6PacketTooBig))
}

// IsEchoRequest reports whether the packet is an ICMP echo request.
func (i Info) IsEchoRequest() bool {
	return (i.Proto == ProtoICMPv4 && i.ICMPType == ICMPv4EchoRequest) || (i.Proto == ProtoICMPv6 && i.ICMPType == ICMPv6EchoRequest)
}

// IsEchoReply reports whether the packet is an ICMP echo reply.
func (i Info) IsEchoReply() bool {
	return (i.Proto == ProtoICMPv4 && i.ICMPType == ICMPv4EchoReply) || (i.Proto == ProtoICMPv6 && i.ICMPType == ICMPv6EchoReply)
}

// IsICMP reports whether the packet is ICMPv4 or ICMPv6.
func (i Info) IsICMP() bool { return i.Proto == ProtoICMPv4 || i.Proto == ProtoICMPv6 }

// Parse parses an IPv4 or IPv6 packet.
func Parse(pkt []byte) (Info, error) {
	if len(pkt) == 0 {
		return Info{}, ErrMalformed
	}
	switch pkt[0] >> 4 {
	case 4:
		return parse4(pkt)
	case 6:
		return parse6(pkt)
	default:
		return Info{}, ErrMalformed
	}
}

func parse4(pkt []byte) (Info, error) {
	if len(pkt) < ipv4HeaderMin {
		return Info{}, ErrMalformed
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < ipv4HeaderMin || total < ihl || total > len(pkt) {
		return Info{}, ErrMalformed
	}
	info := Info{
		Src:   netip.AddrFrom4([4]byte(pkt[12:16])),
		Dst:   netip.AddrFrom4([4]byte(pkt[16:20])),
		Proto: pkt[9],
	}
	flags := binary.BigEndian.Uint16(pkt[6:8])
	info.MoreFragments = flags&0x2000 != 0
	if info.MoreFragments || flags&0x1fff != 0 {
		info.FragID = uint32(binary.BigEndian.Uint16(pkt[4:6]))
	}
	if flags&0x1fff != 0 {
		info.Fragment = true
		return info, nil
	}
	return parseTransport(info, pkt[ihl:total])
}

func parse6(pkt []byte) (Info, error) {
	if len(pkt) < ipv6HeaderLen {
		return Info{}, ErrMalformed
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if ipv6HeaderLen+payloadLen > len(pkt) {
		return Info{}, ErrMalformed
	}
	info := Info{
		Src: netip.AddrFrom16([16]byte(pkt[8:24])),
		Dst: netip.AddrFrom16([16]byte(pkt[24:40])),
	}
	next := pkt[6]
	body := pkt[ipv6HeaderLen : ipv6HeaderLen+payloadLen]
	for i := 0; i < maxIPv6ExtChain; i++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(body) < 8 {
				return Info{}, ErrMalformed
			}
			extLen := (int(body[1]) + 1) * 8
			if extLen > len(body) {
				return Info{}, ErrMalformed
			}
			next, body = body[0], body[extLen:]
		case 44: // fragment
			if len(body) < 8 {
				return Info{}, ErrMalformed
			}
			offset := binary.BigEndian.Uint16(body[2:4]) >> 3
			info.MoreFragments = body[3]&1 != 0
			info.FragID = binary.BigEndian.Uint32(body[4:8])
			next, body = body[0], body[8:]
			if offset != 0 {
				info.Proto = next
				info.Fragment = true
				return info, nil
			}
		default:
			info.Proto = next
			return parseTransport(info, body)
		}
	}
	return Info{}, ErrMalformed
}

func parseTransport(info Info, seg []byte) (Info, error) {
	switch info.Proto {
	case ProtoTCP:
		if len(seg) < tcpHeaderMin {
			return Info{}, ErrMalformed
		}
		dataOff := int(seg[12]>>4) * 4
		if dataOff < tcpHeaderMin || dataOff > len(seg) {
			return Info{}, ErrMalformed
		}
		info.SrcPort = binary.BigEndian.Uint16(seg[0:2])
		info.DstPort = binary.BigEndian.Uint16(seg[2:4])
		info.TCPFlags = seg[13]
	case ProtoUDP:
		if len(seg) < udpHeaderLen {
			return Info{}, ErrMalformed
		}
		udpLen := int(binary.BigEndian.Uint16(seg[4:6]))
		info.SrcPort = binary.BigEndian.Uint16(seg[0:2])
		info.DstPort = binary.BigEndian.Uint16(seg[2:4])
		if info.MoreFragments {
			// The datagram continues in later fragments: the length covers
			// all of them, and no caller may read a partial payload.
			if udpLen < udpHeaderLen {
				return Info{}, ErrMalformed
			}
			break
		}
		if udpLen < udpHeaderLen || udpLen > len(seg) {
			return Info{}, ErrMalformed
		}
		info.Payload = seg[udpHeaderLen:udpLen]
	case ProtoICMPv4, ProtoICMPv6:
		if len(seg) < 4 {
			return Info{}, ErrMalformed
		}
		info.ICMPType, info.ICMPCode = seg[0], seg[1]
		if info.IsEchoRequest() || info.IsEchoReply() {
			if len(seg) < 8 {
				return Info{}, ErrMalformed
			}
			info.ICMPID = binary.BigEndian.Uint16(seg[4:6])
		}
		if info.IsICMPError() {
			if len(seg) < 8 {
				return Info{}, ErrMalformed
			}
			info.Embedded = seg[8:]
		}
	}
	return info, nil
}

// embeddedTransportLen is what an ICMP error must quote of the original
// transport header: the ports, or the ICMP type and echo identifier.
const embeddedTransportLen = 8

// ParseEmbedded parses the original packet quoted inside an ICMP error.
// The quote is usually cut short, so lengths in the quoted headers are
// not checked against it; only the addresses, the protocol and the first
// eight bytes of the transport header are read.
func ParseEmbedded(b []byte) (Info, error) {
	if len(b) == 0 {
		return Info{}, ErrMalformed
	}
	var info Info
	var seg []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < ipv4HeaderMin {
			return Info{}, ErrMalformed
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < ipv4HeaderMin || len(b) < ihl {
			return Info{}, ErrMalformed
		}
		info.Src = netip.AddrFrom4([4]byte(b[12:16]))
		info.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		info.Proto = b[9]
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			info.Fragment = true
			return info, nil
		}
		seg = b[ihl:]
	case 6:
		if len(b) < ipv6HeaderLen {
			return Info{}, ErrMalformed
		}
		info.Src = netip.AddrFrom16([16]byte(b[8:24]))
		info.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		next, body := b[6], b[ipv6HeaderLen:]
	chain:
		for i := 0; ; i++ {
			if i == maxIPv6ExtChain {
				return Info{}, ErrMalformed
			}
			switch next {
			case 0, 43, 60:
				if len(body) < 8 {
					return Info{}, ErrMalformed
				}
				extLen := (int(body[1]) + 1) * 8
				if extLen > len(body) {
					return Info{}, ErrMalformed
				}
				next, body = body[0], body[extLen:]
			case 44:
				if len(body) < 8 {
					return Info{}, ErrMalformed
				}
				offset := binary.BigEndian.Uint16(body[2:4]) >> 3
				next, body = body[0], body[8:]
				if offset != 0 {
					info.Proto, info.Fragment = next, true
					return info, nil
				}
			default:
				break chain
			}
		}
		info.Proto, seg = next, body
	default:
		return Info{}, ErrMalformed
	}
	switch info.Proto {
	case ProtoTCP, ProtoUDP:
		if len(seg) < embeddedTransportLen {
			return Info{}, ErrMalformed
		}
		info.SrcPort = binary.BigEndian.Uint16(seg[0:2])
		info.DstPort = binary.BigEndian.Uint16(seg[2:4])
	case ProtoICMPv4, ProtoICMPv6:
		if len(seg) < embeddedTransportLen {
			return Info{}, ErrMalformed
		}
		info.ICMPType, info.ICMPCode = seg[0], seg[1]
		if info.IsEchoRequest() || info.IsEchoReply() {
			info.ICMPID = binary.BigEndian.Uint16(seg[4:6])
		}
	}
	return info, nil
}

// BuildUDP4 returns an IPv4/UDP packet with valid checksums.
func BuildUDP4(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, errors.New("BuildUDP4 needs IPv4 addresses")
	}
	total := ipv4HeaderMin + udpHeaderLen + len(payload)
	if total > 0xffff {
		return nil, errors.New("payload too large")
	}
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total)) //nolint:gosec // bounded above
	pkt[6] = 0x40                                       // don't fragment
	pkt[8] = 64                                         // TTL
	pkt[9] = ProtoUDP
	s4, d4 := src.As4(), dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^checksum(pkt[:ipv4HeaderMin], 0))

	udp := pkt[ipv4HeaderMin:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp))) //nolint:gosec // bounded above
	copy(udp[udpHeaderLen:], payload)

	var pseudo [12]byte
	copy(pseudo[0:4], s4[:])
	copy(pseudo[4:8], d4[:])
	pseudo[9] = ProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp))) //nolint:gosec // bounded above
	sum := ^checksum(udp, uint32(checksum(pseudo[:], 0)))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt, nil
}

// checksum computes the one's complement sum used by IP, UDP and TCP.
func checksum(b []byte, initial uint32) uint16 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) //nolint:gosec // folded to 16 bits above
}
