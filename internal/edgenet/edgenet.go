// Package edgenet reads what an edge device can learn about the local
// network without changing anything (P11, ADR-0154): the link-layer
// address of the default gateway from the neighbour table (#466) and the
// system's metered connection hint (#385). It sends no packet, opens no
// socket and keeps nothing on disk.
package edgenet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// maxNeighbors bounds one neighbour table read.
const maxNeighbors = 4096

// Neighbor is one complete IPv4 neighbour table entry.
type Neighbor struct {
	Addr netip.Addr
	MAC  string
}

// validMAC accepts a 6-byte unicast address that is not all zero; it
// returns the canonical lower-case form.
func validMAC(hw net.HardwareAddr) (string, bool) {
	if len(hw) != 6 || hw[0]&1 != 0 {
		return "", false
	}
	zero := true
	for _, b := range hw {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "", false
	}
	return hw.String(), true
}

// atfComplete is ATF_COM in /proc/net/arp flags.
const atfComplete = 0x2

// ParseProcARP reads Linux /proc/net/arp: "IP address, HW type, Flags,
// HW address, Mask, Device". Incomplete and malformed lines are skipped.
func ParseProcARP(data []byte) []Neighbor {
	var out []Neighbor
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() && len(out) < maxNeighbors {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || !a.Is4() {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&atfComplete == 0 {
			continue
		}
		hw, err := net.ParseMAC(f[3])
		if err != nil {
			continue
		}
		if mac, ok := validMAC(hw); ok {
			out = append(out, Neighbor{Addr: a, MAC: mac})
		}
	}
	return out
}

// MIB_IPNETROW: index, physical address length, physical address (8),
// IPv4 address (network order), type.
const (
	ipNetRowSize    = 24
	ipNetTypeOther  = 1
	ipNetTypeInvald = 2
)

// ParseIPNetTable decodes a Windows MIB_IPNETTABLE buffer. Invalid,
// incomplete and malformed rows are skipped; the row count is bounded by
// the buffer.
func ParseIPNetTable(table []byte) []Neighbor {
	if len(table) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(table))
	rows := table[4:]
	if n < 0 || n > len(rows)/ipNetRowSize {
		n = len(rows) / ipNetRowSize
	}
	n = min(n, maxNeighbors)
	var out []Neighbor
	for i := range n {
		row := rows[i*ipNetRowSize : (i+1)*ipNetRowSize]
		hwLen := binary.LittleEndian.Uint32(row[4:8])
		typ := binary.LittleEndian.Uint32(row[20:24])
		if hwLen != 6 || typ == ipNetTypeInvald || typ == ipNetTypeOther {
			continue
		}
		mac, ok := validMAC(net.HardwareAddr(row[8:14]))
		if !ok {
			continue
		}
		a := netip.AddrFrom4([4]byte{row[16], row[17], row[18], row[19]})
		out = append(out, Neighbor{Addr: a, MAC: mac})
	}
	return out
}

// GatewayMAC returns the neighbour table entry of gw, if any.
func GatewayMAC(neighbors []Neighbor, gw netip.Addr) (string, bool) {
	gw = gw.Unmap()
	for _, n := range neighbors {
		if n.Addr == gw {
			return n.MAC, true
		}
	}
	return "", false
}

// Neighbors reads the IPv4 neighbour table of this computer. It returns
// nil when the table cannot be read.
func Neighbors() []Neighbor { return neighbors() }

// Metered reports the system's metered connection hint; known is false
// when the system does not say.
func Metered() (metered, known bool) { return meteredHint() }
