//go:build windows

package peercred

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet               = 2
	tcpTableOwnerPIDAll  = 5
	tcpRowOwnerPIDSize   = 24 // MIB_TCPROW_OWNER_PID: six DWORDs
	maxTableAttempts     = 4
	errInsufficientBuf   = 122 // ERROR_INSUFFICIENT_BUFFER
	maxTCPTableBytes     = 16 << 20
	processQueryLimited  = windows.PROCESS_QUERY_LIMITED_INFORMATION
	tokenQueryPermission = windows.TOKEN_QUERY
)

// Lookup returns the process that owns the client end of the loopback
// connection client -> server. Only IPv4 is looked up: the local API
// listens on 127.0.0.1.
func Lookup(client, server netip.AddrPort) (Identity, error) {
	if !client.Addr().Is4() || !server.Addr().Is4() {
		return Identity{}, ErrNotFound
	}
	table, err := tcpTable()
	if err != nil {
		return Identity{}, err
	}
	pid, ok := findOwner(table, client, server)
	if !ok {
		return Identity{}, ErrNotFound
	}
	return identify(pid)
}

// tcpTable reads MIB_TCPTABLE_OWNER_PID for IPv4.
func tcpTable() ([]byte, error) {
	size := uint32(64 << 10)
	for i := 0; i < maxTableAttempts; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
		switch r {
		case 0:
			return buf[:size], nil
		case errInsufficientBuf:
			if size > maxTCPTableBytes {
				return nil, errors.New("TCP table too large")
			}
			size += 4 << 10
			continue
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", windows.Errno(r))
		}
	}
	return nil, errors.New("GetExtendedTcpTable: table keeps growing")
}

// findOwner scans the table for the row whose local end is client and
// remote end is server.
func findOwner(table []byte, client, server netip.AddrPort) (uint32, bool) {
	if len(table) < 4 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(table))
	rows := table[4:]
	if n < 0 || n > len(rows)/tcpRowOwnerPIDSize {
		n = len(rows) / tcpRowOwnerPIDSize
	}
	for i := 0; i < n; i++ {
		row := rows[i*tcpRowOwnerPIDSize : (i+1)*tcpRowOwnerPIDSize]
		local := rowAddr(row[4:8], row[8:12])
		remote := rowAddr(row[12:16], row[16:20])
		if local == client && remote == server {
			return binary.LittleEndian.Uint32(row[20:24]), true
		}
	}
	return 0, false
}

// rowAddr decodes an address (network byte order in memory) and a port
// (network byte order in the low 16 bits of a DWORD).
func rowAddr(addr, port []byte) netip.AddrPort {
	a := netip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]})
	return netip.AddrPortFrom(a, uint16(port[0])<<8|uint16(port[1]))
}

// identify reads the token of the process.
func identify(pid uint32) (Identity, error) {
	id := Identity{PID: int(pid), UID: -1, Self: int(pid) == os.Getpid()}
	if id.Self {
		id.Admin = windows.GetCurrentProcessToken().IsElevated() || isSystem(windows.GetCurrentProcessToken())
		return id, nil
	}
	h, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return id, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, tokenQueryPermission, &tok); err != nil {
		return id, fmt.Errorf("open token of process %d: %w", pid, err)
	}
	defer tok.Close()
	id.Admin = tok.IsElevated() || isSystem(tok)
	id.Self = sameUser(tok)
	return id, nil
}

// sameUser reports whether tok belongs to the user running this process.
func sameUser(tok windows.Token) bool {
	theirs, err := tok.GetTokenUser()
	if err != nil {
		return false
	}
	ours, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return windows.EqualSid(theirs.User.Sid, ours.User.Sid)
}

func isSystem(tok windows.Token) bool {
	u, err := tok.GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// groupMember: Windows has no operator group (ADR-0050).
func groupMember(string, []string) bool { return false }
