package packet

import "encoding/binary"

// TCP header option kinds used by ClampMSS.
const (
	tcpOptEnd = 0
	tcpOptNOP = 1
	tcpOptMSS = 2
	// tcpOptMSSLen is the fixed length of the MSS option.
	tcpOptMSSLen = 4
)

// MSSLimit returns the largest TCP maximum segment size that fits a tunnel
// of the given MTU: MTU minus the minimal IP and TCP headers (40 bytes for
// IPv4, 60 for IPv6). It returns 0 when the MTU is too small to matter.
func MSSLimit(mtu int, ipv6 bool) int {
	overhead := ipv4HeaderMin + tcpHeaderMin
	if ipv6 {
		overhead = ipv6HeaderLen + tcpHeaderMin
	}
	if mtu <= overhead {
		return 0
	}
	return min(mtu-overhead, 0xffff)
}

// ClampMSS lowers the MSS option of a TCP SYN (or SYN-ACK) to MSSLimit for
// the tunnel MTU, so neither end of a connection crossing the tunnel sends
// segments that would have to be fragmented. It edits pkt in place, keeps
// the TCP checksum consistent with an incremental update (RFC 1624), and
// reports whether it changed the packet. Anything it cannot parse fully,
// fragments included, is left untouched.
func ClampMSS(pkt []byte, mtu int) bool {
	if len(pkt) == 0 {
		return false
	}
	var seg []byte
	var ipv6 bool
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < ipv4HeaderMin || pkt[9] != ProtoTCP {
			return false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < ipv4HeaderMin || total < ihl || total > len(pkt) {
			return false
		}
		// Any fragment (more-fragments flag or a non-zero offset) is
		// skipped: the checksum covers bytes this packet does not hold.
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			return false
		}
		seg = pkt[ihl:total]
	case 6:
		if len(pkt) < ipv6HeaderLen {
			return false
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if ipv6HeaderLen+payloadLen > len(pkt) {
			return false
		}
		next, body := pkt[6], pkt[ipv6HeaderLen:ipv6HeaderLen+payloadLen]
		for i := 0; next != ProtoTCP; i++ {
			if i == maxIPv6ExtChain {
				return false
			}
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(body) < 8 {
					return false
				}
				extLen := (int(body[1]) + 1) * 8
				if extLen > len(body) {
					return false
				}
				next, body = body[0], body[extLen:]
			default: // fragments and anything else are left alone
				return false
			}
		}
		seg, ipv6 = body, true
	default:
		return false
	}
	limit := MSSLimit(mtu, ipv6)
	if limit == 0 || len(seg) < tcpHeaderMin || seg[13]&TCPSyn == 0 {
		return false
	}
	dataOff := int(seg[12]>>4) * 4
	if dataOff < tcpHeaderMin || dataOff > len(seg) {
		return false
	}
	changed := false
	for i := tcpHeaderMin; i < dataOff; {
		kind := seg[i]
		if kind == tcpOptEnd {
			break
		}
		if kind == tcpOptNOP {
			i++
			continue
		}
		if i+1 >= dataOff {
			break
		}
		l := int(seg[i+1])
		if l < 2 || i+l > dataOff {
			break // malformed options: stop, never guess
		}
		if kind == tcpOptMSS && l == tcpOptMSSLen {
			off := i + 2
			old := binary.BigEndian.Uint16(seg[off : off+2])
			if int(old) > limit {
				nw := uint16(limit) //nolint:gosec // MSSLimit caps at 0xffff
				binary.BigEndian.PutUint16(seg[off:off+2], nw)
				if off%2 == 1 {
					// A field at an odd offset straddles two checksum
					// words; its one's complement contribution is the
					// byte-swapped value.
					old, nw = old<<8|old>>8, nw<<8|nw>>8
				}
				cs := binary.BigEndian.Uint16(seg[16:18])
				binary.BigEndian.PutUint16(seg[16:18], adjustChecksum(cs, old, nw))
				changed = true
			}
		}
		i += l
	}
	return changed
}

// adjustChecksum updates a one's complement checksum after a 16-bit word
// changed from old to nw (RFC 1624, equation 3).
func adjustChecksum(cs, old, nw uint16) uint16 {
	sum := uint32(^cs) + uint32(^old) + uint32(nw)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum) //nolint:gosec // folded to 16 bits above
}
