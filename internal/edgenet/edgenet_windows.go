//go:build windows

package edgenet

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHelper                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIPNetTable              = modIPHelper.NewProc("GetIpNetTable")
	procGetNetworkConnectivityHint = modIPHelper.NewProc("GetNetworkConnectivityHint")
)

const (
	errInsufficientBuffer = 122
	maxIPNetTable         = 1 << 20
	maxIPNetAttempts      = 4
)

func neighbors() []Neighbor {
	if procGetIPNetTable.Find() != nil {
		return nil
	}
	size := uint32(8 << 10)
	for range maxIPNetAttempts {
		buf := make([]byte, size)
		r, _, _ := procGetIPNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch r {
		case 0:
			if int(size) > len(buf) {
				return nil
			}
			return ParseIPNetTable(buf[:size])
		case errInsufficientBuffer:
			if size > maxIPNetTable {
				return nil
			}
			size += 4 << 10
		default: // ERROR_NO_DATA and others: nothing to read
			return nil
		}
	}
	return nil
}

// nlConnectivityHint is NL_NETWORK_CONNECTIVITY_HINT.
type nlConnectivityHint struct {
	level       int32
	cost        int32
	approaching byte
	over        byte
	roaming     byte
	_           byte
}

// NL_NETWORK_CONNECTIVITY_COST_HINT values.
const (
	costFixed    = 2
	costVariable = 3
)

// meteredHint asks GetNetworkConnectivityHint (Windows 10 2004 and later),
// the documented Win32 form of the "metered connection" setting.
func meteredHint() (bool, bool) {
	if procGetNetworkConnectivityHint.Find() != nil {
		return false, false
	}
	var h nlConnectivityHint
	r, _, _ := procGetNetworkConnectivityHint.Call(uintptr(unsafe.Pointer(&h)))
	if r != 0 {
		return false, false
	}
	switch {
	case h.cost == costFixed || h.cost == costVariable, h.over != 0, h.roaming != 0:
		return true, true
	case h.cost == 0:
		return false, false
	}
	return false, true
}
