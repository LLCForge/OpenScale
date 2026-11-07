// Package surface lists the sockets the running OpenScale process has
// open (#521, ADR-0154): every listening TCP socket and every bound UDP
// socket, read from the operating system's own tables and filtered to
// this process. The caller explains each entry; this package only reads.
package surface

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// maxSockets bounds one listing.
const maxSockets = 1024

// Socket is one socket of this process.
type Socket struct {
	Proto string // "tcp" or "udp"
	Addr  netip.Addr
	Port  uint16
}

// Own returns the sockets of this process, sorted. ok is false when the
// tables cannot be read on this system.
func Own() (sockets []Socket, ok bool) {
	s, ok := own()
	sortSockets(s)
	return s, ok
}

func sortSockets(s []Socket) {
	slices.SortFunc(s, func(a, b Socket) int {
		if c := strings.Compare(a.Proto, b.Proto); c != 0 {
			return c
		}
		if a.Port != b.Port {
			return int(a.Port) - int(b.Port)
		}
		return a.Addr.Compare(b.Addr)
	})
}

// ProcEntry is one row of /proc/net/{tcp,udp}{,6}.
type ProcEntry struct {
	Addr  netip.Addr
	Port  uint16
	State string
	Inode uint64
}

// ParseProcNet reads one Linux /proc/net socket table. Malformed lines
// are skipped.
func ParseProcNet(data []byte) []ProcEntry {
	var out []ProcEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() && len(out) < maxSockets*8 {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		ap, ok := parseProcAddrPort(f[1])
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		out = append(out, ProcEntry{Addr: ap.Addr(), Port: ap.Port(), State: f[3], Inode: inode})
	}
	return out
}

// parseProcAddrPort decodes "0100007F:1F90" or the 32-digit IPv6 form;
// each 32-bit word of the address is in host (little-endian) order.
func parseProcAddrPort(s string) (netip.AddrPort, bool) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(out[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	a, ok := netip.AddrFromSlice(out)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true
}

// SocketInode parses a /proc/<pid>/fd link target "socket:[12345]".
func SocketInode(link string) (uint64, bool) {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	num, ok := strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return n, err == nil && n != 0
}

// tcpListen is TCP_LISTEN in /proc/net/tcp.
const tcpListen = "0A"

// FilterProc keeps the entries whose inode this process owns: listening
// TCP sockets, and UDP sockets in any state.
func FilterProc(proto string, entries []ProcEntry, own map[uint64]bool) []Socket {
	var out []Socket
	for _, e := range entries {
		if !own[e.Inode] || (proto == "tcp" && e.State != tcpListen) {
			continue
		}
		out = append(out, Socket{Proto: proto, Addr: e.Addr, Port: e.Port})
	}
	return out
}

// Windows owner-PID table rows (iphlpapi): MIB_TCPROW_OWNER_PID,
// MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID.
const (
	tcp4RowSize = 24
	tcp6RowSize = 56
	udp4RowSize = 12
	udp6RowSize = 28
)

// winTable is how one table is laid out.
type winTable struct {
	proto   string
	rowSize int
	v6      bool
	portOff int
	pidOff  int
	addrOff int
}

var (
	// The TCP tables are read with TCP_TABLE_OWNER_PID_LISTENER, so every
	// row is a listener; Windows does not fill the state field reliably
	// for this class, so it is not read.
	winTCP4 = winTable{proto: "tcp", rowSize: tcp4RowSize, portOff: 8, pidOff: 20, addrOff: 4}
	winTCP6 = winTable{proto: "tcp", rowSize: tcp6RowSize, v6: true, portOff: 20, pidOff: 52, addrOff: 0}
	winUDP4 = winTable{proto: "udp", rowSize: udp4RowSize, portOff: 4, pidOff: 8, addrOff: 0}
	winUDP6 = winTable{proto: "udp", rowSize: udp6RowSize, v6: true, portOff: 20, pidOff: 24, addrOff: 0}
)

// parseWinTable decodes one owner-PID table and keeps the rows of pid.
// The row count is bounded by the buffer.
func parseWinTable(t winTable, table []byte, pid uint32) []Socket {
	if len(table) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(table))
	rows := table[4:]
	if n < 0 || n > len(rows)/t.rowSize {
		n = len(rows) / t.rowSize
	}
	var out []Socket
	for i := 0; i < n && len(out) < maxSockets; i++ {
		row := rows[i*t.rowSize : (i+1)*t.rowSize]
		if binary.LittleEndian.Uint32(row[t.pidOff:]) != pid {
			continue
		}
		var a netip.Addr
		if t.v6 {
			var raw [16]byte
			copy(raw[:], row[t.addrOff:t.addrOff+16])
			a = netip.AddrFrom16(raw).Unmap()
		} else {
			a = netip.AddrFrom4([4]byte(row[t.addrOff : t.addrOff+4]))
		}
		port := uint16(row[t.portOff])<<8 | uint16(row[t.portOff+1])
		out = append(out, Socket{Proto: t.proto, Addr: a, Port: port})
	}
	return out
}

// ParseWindowsTable decodes a Windows owner-PID table for tests and fuzzing:
// kind is "tcp4", "tcp6", "udp4" or "udp6".
func ParseWindowsTable(kind string, table []byte, pid uint32) []Socket {
	switch kind {
	case "tcp4":
		return parseWinTable(winTCP4, table, pid)
	case "tcp6":
		return parseWinTable(winTCP6, table, pid)
	case "udp4":
		return parseWinTable(winUDP4, table, pid)
	case "udp6":
		return parseWinTable(winUDP6, table, pid)
	}
	return nil
}
