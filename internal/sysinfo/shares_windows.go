//go:build windows

package sysinfo

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows shares (ADR-0226): NetShareEnum at level 1 gives the name, the
// type and the remark; the folder path (level 2) is never asked for. Only
// plain disk shares are kept: the administrative ones (C$, ADMIN$, IPC$)
// carry STYPE_SPECIAL, printers and devices another type.

var (
	modNetapi32         = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareEnum    = modNetapi32.NewProc("NetShareEnum")
	procNetApiBufFree   = modNetapi32.NewProc("NetApiBufferFree")
	maxPreferredLength  = uint32(0xFFFFFFFF)
	stypeMask           = uint32(0xFF)
	stypeDiskTree       = uint32(0)
	stypeSpecial        = uint32(0x80000000)
	netShareEnumMaxRead = 1024
)

// shareInfo1 is SHARE_INFO_1.
type shareInfo1 struct {
	netname *uint16
	typ     uint32
	remark  *uint16
}

func listShares() []Share {
	if procNetShareEnum.Find() != nil || procNetApiBufFree.Find() != nil {
		return nil
	}
	var (
		buf          *byte
		read, total  uint32
		resumeHandle uint32
	)
	r, _, _ := procNetShareEnum.Call(0, 1, uintptr(unsafe.Pointer(&buf)), uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resumeHandle)))
	if buf != nil {
		defer procNetApiBufFree.Call(uintptr(unsafe.Pointer(buf)))
	}
	if r != 0 || buf == nil || read == 0 {
		return nil
	}
	n := min(int(read), netShareEnumMaxRead)
	entries := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), n)
	var out []Share
	for _, e := range entries {
		if e.typ&stypeSpecial != 0 || e.typ&stypeMask != stypeDiskTree || e.netname == nil {
			continue
		}
		name := windows.UTF16PtrToString(e.netname)
		if name == "" || name[len(name)-1] == '$' {
			continue
		}
		s := Share{Name: name}
		if e.remark != nil {
			s.Comment = windows.UTF16PtrToString(e.remark)
		}
		out = append(out, s)
	}
	return out
}
