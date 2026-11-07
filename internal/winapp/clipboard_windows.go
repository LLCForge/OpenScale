//go:build windows

package winapp

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard    = modUser32.NewProc("OpenClipboard")
	procEmptyClipboard   = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData = modUser32.NewProc("SetClipboardData")
	procCloseClipboard   = modUser32.NewProc("CloseClipboard")
	procGlobalAlloc      = modKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = modKernel32.NewProc("GlobalUnlock")
	procGlobalFree       = modKernel32.NewProc("GlobalFree")
	procRtlMoveMemory    = modKernel32.NewProc("RtlMoveMemory")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	maxClipText   = 4096
)

// SetClipboardText puts s on the clipboard as Unicode text.
func SetClipboardText(s string) error {
	if len(s) > maxClipText {
		return errors.New("metin çok uzun")
	}
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return err
	}
	size := uintptr(len(u) * 2)
	h, _, callErr := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return callErr
	}
	p, _, callErr := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return callErr
	}
	// The locked block is copied with RtlMoveMemory so Go never turns the
	// foreign address into a Go pointer.
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), size)
	procGlobalUnlock.Call(h)

	if r, _, callErr := procOpenClipboard.Call(0); r == 0 {
		procGlobalFree.Call(h)
		return callErr
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	if r, _, callErr := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		procGlobalFree.Call(h)
		return callErr
	}
	// The clipboard owns h now.
	return nil
}
