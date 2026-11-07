//go:build windows

package sysinfo

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHelper             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHelper.NewProc("GetExtendedTcpTable")
)

const (
	winAFInet              = 2
	winAFInet6             = 23
	tcpTableOwnerPIDListen = 3  // TCP_TABLE_OWNER_PID_LISTENER
	tcpRowOwnerPID4Size    = 24 // MIB_TCPROW_OWNER_PID
	tcpRowOwnerPID6Size    = 56 // MIB_TCP6ROW_OWNER_PID
	winErrInsufficientBuf  = 122
	maxWinTCPTable         = 8 << 20
	maxWinTCPTableAttempts = 4
)

func listeningSockets() []listenEntry {
	var out []listenEntry
	if t := winTCPTable(winAFInet); t != nil {
		out = append(out, parseWinListen4(t)...)
	}
	if t := winTCPTable(winAFInet6); t != nil {
		out = append(out, parseWinListen6(t)...)
	}
	return out
}

// winTCPTable reads the listening sockets of one address family.
func winTCPTable(family uint32) []byte {
	size := uint32(16 << 10)
	for i := 0; i < maxWinTCPTableAttempts; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDListen, 0)
		switch r {
		case 0:
			if int(size) > len(buf) {
				return nil
			}
			return buf[:size]
		case winErrInsufficientBuf:
			if size > maxWinTCPTable {
				return nil
			}
			size += 4 << 10
		default:
			return nil
		}
	}
	return nil
}

// tableRows returns the row count bounded by the buffer.
func tableRows(table []byte, rowSize int) (int, []byte) {
	if len(table) < 4 {
		return 0, nil
	}
	n := int(binary.LittleEndian.Uint32(table))
	rows := table[4:]
	if n < 0 || n > len(rows)/rowSize {
		n = len(rows) / rowSize
	}
	return n, rows
}

// winPort decodes a port stored in network order in the low 16 bits of a
// DWORD.
func winPort(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// parseWinListen4 decodes MIB_TCPTABLE_OWNER_PID: state, local address,
// local port, remote address, remote port, owning process.
func parseWinListen4(table []byte) []listenEntry {
	n, rows := tableRows(table, tcpRowOwnerPID4Size)
	out := make([]listenEntry, 0, n)
	for i := 0; i < n; i++ {
		row := rows[i*tcpRowOwnerPID4Size : (i+1)*tcpRowOwnerPID4Size]
		a := netip.AddrFrom4([4]byte{row[4], row[5], row[6], row[7]})
		out = append(out, listenEntry{addr: a, port: winPort(row[8:12])})
	}
	return out
}

// parseWinListen6 decodes MIB_TCP6TABLE_OWNER_PID: local address (16),
// scope, local port, remote address (16), scope, remote port, state,
// owning process.
func parseWinListen6(table []byte) []listenEntry {
	n, rows := tableRows(table, tcpRowOwnerPID6Size)
	out := make([]listenEntry, 0, n)
	for i := 0; i < n; i++ {
		row := rows[i*tcpRowOwnerPID6Size : (i+1)*tcpRowOwnerPID6Size]
		var raw [16]byte
		copy(raw[:], row[0:16])
		out = append(out, listenEntry{addr: netip.AddrFrom16(raw), port: winPort(row[20:24])})
	}
	return out
}
