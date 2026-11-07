//go:build windows

package winapp

import (
	"sync"

	"golang.org/x/sys/windows"
)

// Screen lock notifications for the tray (#501, ADR-0154). The tray's
// hidden window registers for WTS session changes of its own session;
// a lock and an unlock are passed to the callback set with OnSessionLock.

var (
	modWtsapi32                          = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSRegisterSessionNotification   = modWtsapi32.NewProc("WTSRegisterSessionNotification")
	procWTSUnRegisterSessionNotification = modWtsapi32.NewProc("WTSUnRegisterSessionNotification")
)

const (
	wmWTSSessionChange   = 0x02B1
	wtsSessionLock       = 0x7
	wtsSessionUnlock     = 0x8
	notifyForThisSession = 0
)

// sessionHandlers maps a *Tray to its lock callback.
var sessionHandlers sync.Map

// OnSessionLock sets the callback for screen lock (true) and unlock
// (false). It runs on its own goroutine.
func (t *Tray) OnSessionLock(fn func(locked bool)) {
	if fn == nil {
		sessionHandlers.Delete(t)
		return
	}
	sessionHandlers.Store(t, fn)
}

// registerSessionNotify asks for session change messages on hwnd and
// returns the function that stops them. A failure leaves the tray working
// without lock notifications.
func registerSessionNotify(hwnd uintptr) func() {
	if procWTSRegisterSessionNotification.Find() != nil {
		return func() {}
	}
	if r, _, _ := procWTSRegisterSessionNotification.Call(hwnd, notifyForThisSession); r == 0 {
		return func() {}
	}
	return func() { procWTSUnRegisterSessionNotification.Call(hwnd) }
}

// sessionChanged handles WM_WTSSESSION_CHANGE on the loop thread.
func (t *Tray) sessionChanged(wParam uintptr) {
	var locked bool
	switch wParam {
	case wtsSessionLock:
		locked = true
	case wtsSessionUnlock:
		locked = false
	default:
		return
	}
	if v, ok := sessionHandlers.Load(t); ok {
		go v.(func(bool))(locked)
	}
}
