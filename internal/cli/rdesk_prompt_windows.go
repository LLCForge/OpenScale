//go:build windows

package cli

import (
	"context"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/rdesk"
)

// On-screen consent prompt and session notice of the remote desktop on the
// user's desktop (ADR-0055, ADR-0110): plain Win32 message boxes, shown on
// top of other windows.

const (
	mbOK            = 0x00000000
	mbYesNo         = 0x00000004
	mbIconWarning   = 0x00000030
	mbIconInfo      = 0x00000040
	mbDefButton2    = 0x00000100
	mbSystemModal   = 0x00001000
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	idYes           = 6
)

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxTmo = user32.NewProc("MessageBoxTimeoutW")
)

// messageBox shows a box and returns the button; with a timeout the box
// closes by itself (MessageBoxTimeoutW, present on every supported
// Windows) and the answer counts as "no".
func messageBox(text, caption string, flags uint32, timeout time.Duration) int {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(caption)
	if timeout > 0 && procMessageBoxTmo.Find() == nil {
		r, _, _ := procMessageBoxTmo.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), uintptr(flags), 0, uintptr(timeout.Milliseconds()))
		return int(r)
	}
	r, _ := windows.MessageBox(0, t, c, flags)
	return int(r)
}

// desktopConsent asks the person at this computer; no answer is a refusal.
func desktopConsent(ctx context.Context, req rdesk.ConsentRequest) bool {
	timeout := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-time.Second, time.Second)
	}
	ans := make(chan bool, 1)
	go func() {
		ans <- messageBox(consentText(req), "OpenScale uzak masaüstü isteği", mbYesNo|mbIconWarning|mbDefButton2|mbTopmost|mbSetForeground|mbSystemModal, timeout) == idYes
	}()
	select {
	case ok := <-ans:
		return ok && ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

// desktopIndicator shows a notice when a session starts; it never blocks
// the session.
func desktopIndicator(ev rdesk.SessionEvent) {
	if ev.Kind != rdesk.EventStart {
		return
	}
	go messageBox(indicatorText(ev), "OpenScale uzak masaüstü oturumu", mbOK|mbIconInfo|mbTopmost|mbSetForeground, 0)
}

// desktopPromptsAvailable reports whether consent can be asked here.
func desktopPromptsAvailable() bool { return true }
