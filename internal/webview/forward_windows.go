//go:build windows

package webview

import (
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFindWindowExW            = user32.NewProc("FindWindowExW")
	procSendMessageTimeoutW      = user32.NewProc("SendMessageTimeoutW")
	procAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")
	procIsIconic                 = user32.NewProc("IsIconic")
)

const (
	swRestore         = 9
	smtoAbortIfHung   = 0x0002
	forwardTimeout    = 3 * time.Second
	maxForwardPayload = maxURLBytes * 2
	// maxForwardCandidates bounds the walk over windows of the class; with
	// more than that the caller simply opens a new window.
	maxForwardCandidates = 16
)

// copyDataStruct is COPYDATASTRUCT.
type copyDataStruct struct {
	data  uintptr
	size  uint32
	bytes uintptr
}

// ForwardToOpenWindow hands u to the open OpenScale window of this
// desktop and brings it to the front. It returns ErrNoOpenWindow when no
// window is open whose process passes check, and another error when that
// window refused u.
//
// SECURITY FIX: CWE-346 Any process of the desktop can register the window
// class name, and u carries a one-time sign-in ticket. Every window of the
// class is looked at, so a foreign one cannot hide the real one, and
// nothing (not even the foreground right) reaches a process check refuses.
func ForwardToOpenWindow(u string, check TargetCheck) error {
	if len(u) == 0 || len(u) > maxURLBytes || check == nil {
		return ErrNoOpenWindow
	}
	var hwnd uintptr
	for range maxForwardCandidates {
		hwnd, _, _ = procFindWindowExW.Call(0, hwnd, uintptr(unsafe.Pointer(windowClassName)), 0)
		if hwnd == 0 {
			return ErrNoOpenWindow
		}
		var pid uint32
		if _, err := windows.GetWindowThreadProcessId(windows.HWND(hwnd), &pid); err != nil || pid == 0 {
			continue
		}
		if check(pid) != nil {
			continue
		}
		return sendForward(hwnd, pid, u)
	}
	return ErrNoOpenWindow
}

// sendForward gives u to a window whose process was verified.
func sendForward(hwnd uintptr, pid uint32, u string) error {
	text := utf16.Encode([]rune(u))
	cds := copyDataStruct{data: copyDataForward, size: uint32(len(text) * 2), bytes: uintptr(unsafe.Pointer(&text[0]))}
	// The window process may take the foreground from us.
	_, _, _ = procAllowSetForegroundWindow.Call(uintptr(pid))
	var result uintptr
	r, _, _ := procSendMessageTimeoutW.Call(hwnd, wmCopyData, 0, uintptr(unsafe.Pointer(&cds)),
		smtoAbortIfHung, uintptr(forwardTimeout/time.Millisecond), uintptr(unsafe.Pointer(&result)))
	if r == 0 {
		return ErrNoOpenWindow
	}
	if result != 1 {
		return errForwardRefused
	}
	// The window brings itself to the front (AllowSetForegroundWindow).
	return nil
}

func bringToFront(hwnd uintptr) {
	if iconic, _, _ := procIsIconic.Call(hwnd); iconic != 0 {
		_, _, _ = procShowWindow.Call(hwnd, swRestore)
	} else {
		_, _, _ = procShowWindow.Call(hwnd, swShow)
	}
	_, _, _ = procSetForegroundWindow.Call(hwnd)
}

// onForward handles WM_COPYDATA on the UI thread: 1 accepted, 0 refused.
func (w *win) onForward(lParam uintptr) uintptr {
	if lParam == 0 {
		return 0
	}
	cds := (*copyDataStruct)(ptrFromUintptr(lParam))
	if cds.data != copyDataForward || cds.size == 0 || cds.size%2 != 0 || cds.size > maxForwardPayload || cds.bytes == 0 {
		return 0
	}
	units := unsafe.Slice((*uint16)(ptrFromUintptr(cds.bytes)), cds.size/2)
	u := string(utf16.Decode(units))
	if !w.cfg.acceptForward(u) {
		w.cfg.emit("forward-refuse", u)
		return 0
	}
	w.cfg.emit("forward-accept", u)
	w.queueNavigation(u)
	if !w.cfg.hidden {
		bringToFront(w.hwnd)
	}
	return 1
}
