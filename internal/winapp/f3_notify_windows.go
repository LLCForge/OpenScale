//go:build windows

package winapp

import (
	"sync"
	"time"
	"unsafe"
)

// Clickable notifications (#813) and the lock state of this session.
//
// A notification shown with NotifyAction runs its function when the
// person clicks it (NIN_BALLOONUSERCLICK). Windows shows one notification
// of an icon at a time, so the most recent action wins; it expires after
// a few minutes so an old click target cannot come back. The action only
// opens a window that asks again, so a click on a later plain notice is
// harmless.

const (
	ninBalloonUserClick = 0x0405 // WM_USER + 5
	balloonActionLife   = 3 * time.Minute

	wtsCurrentSession = 0xFFFFFFFF
	wtsSessionInfoEx  = 25
	wtsStateLock      = 0
	wtsStateUnlock    = 1
)

var (
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modWtsapi32.NewProc("WTSFreeMemory")
)

type balloonAction struct {
	fn func()
	at time.Time
}

var balloonActions sync.Map // *Tray -> balloonAction

// NotifyAction shows a notification whose click runs fn on its own
// goroutine.
func (t *Tray) NotifyAction(title, msg string, fn func()) {
	if fn != nil {
		balloonActions.Store(t, balloonAction{fn: fn, at: time.Now()})
	}
	t.Notify(title, msg)
}

// balloonClicked runs on the loop thread.
func (t *Tray) balloonClicked() {
	v, ok := balloonActions.LoadAndDelete(t)
	if !ok {
		return
	}
	a := v.(balloonAction)
	if time.Since(a.at) <= balloonActionLife {
		go a.fn()
	}
}

// wtsInfoExLevel1 is the start of WTSINFOEX_LEVEL1_W.
type wtsInfoExLevel1 struct {
	Level        uint32
	SessionID    uint32
	SessionState int32
	SessionFlags int32
}

// SessionLocked reports whether this session's screen is locked. When
// the state cannot be read it answers true, so callers that hide private
// text on the lock screen hide it.
func SessionLocked() bool {
	if procWTSQuerySessionInformationW.Find() != nil {
		return true
	}
	var info *wtsInfoExLevel1
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, wtsCurrentSession, wtsSessionInfoEx, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || info == nil {
		return true
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(info)))
	if n < uint32(unsafe.Sizeof(wtsInfoExLevel1{})) || info.Level != 1 {
		return true
	}
	return info.SessionFlags != wtsStateUnlock
}
