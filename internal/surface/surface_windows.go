//go:build windows

package surface

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHelper             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHelper.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modIPHelper.NewProc("GetExtendedUdpTable")
)

const (
	afInet                 = 2
	afInet6                = 23
	tcpTableOwnerPIDListen = 3 // TCP_TABLE_OWNER_PID_LISTENER
	udpTableOwnerPID       = 1 // UDP_TABLE_OWNER_PID
	errInsufficientBuffer  = 122
	maxTable               = 8 << 20
	maxAttempts            = 4
)

func readTable(proc *windows.LazyProc, family, class uint32) ([]byte, bool) {
	if proc.Find() != nil {
		return nil, false
	}
	size := uint32(16 << 10)
	for range maxAttempts {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		switch r {
		case 0:
			if int(size) > len(buf) {
				return nil, false
			}
			return buf[:size], true
		case errInsufficientBuffer:
			if size > maxTable {
				return nil, false
			}
			size += 4 << 10
		default:
			return nil, false
		}
	}
	return nil, false
}

func own() ([]Socket, bool) {
	pid := uint32(os.Getpid())
	var out []Socket
	read := false
	for _, t := range []struct {
		proc   *windows.LazyProc
		family uint32
		class  uint32
		layout winTable
	}{
		{procGetExtendedTCPTable, afInet, tcpTableOwnerPIDListen, winTCP4},
		{procGetExtendedTCPTable, afInet6, tcpTableOwnerPIDListen, winTCP6},
		{procGetExtendedUDPTable, afInet, udpTableOwnerPID, winUDP4},
		{procGetExtendedUDPTable, afInet6, udpTableOwnerPID, winUDP6},
	} {
		table, ok := readTable(t.proc, t.family, t.class)
		if !ok {
			continue
		}
		read = true
		out = append(out, parseWinTable(t.layout, table, pid)...)
	}
	return out, read
}
