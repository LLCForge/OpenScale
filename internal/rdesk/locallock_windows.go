//go:build windows

package rdesk

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Screen blanking and local input lock on Windows (#119, ADR-0103).
//
// Blanking is a black, topmost, never-activated window over the whole
// virtual desktop that shows the session notice. It is excluded from
// screen capture with SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE,
// Windows 10 2004 and later), so the viewer keeps seeing the desktop.
// When the exclusion is not available blanking is refused: a blanked
// screen that the viewer also sees as black would be useless and the
// person at the device would not know why.
//
// The input lock installs low-level keyboard and mouse hooks that drop
// physical events and pass injected ones (the session's SendInput). The
// secure attention sequence (Ctrl+Alt+Del) never reaches hooks, so the
// person at the device can always interrupt; ending the session, closing
// the lock or the thread exiting removes the hooks.

var (
	procRegisterClassExW         = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW          = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW           = modUser32.NewProc("DefWindowProcW")
	procDestroyWindow            = modUser32.NewProc("DestroyWindow")
	procShowWindow               = modUser32.NewProc("ShowWindow")
	procSetWindowPos             = modUser32.NewProc("SetWindowPos")
	procGetMessageW              = modUser32.NewProc("GetMessageW")
	procTranslateMessage         = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW         = modUser32.NewProc("DispatchMessageW")
	procPostThreadMessageW       = modUser32.NewProc("PostThreadMessageW")
	procSetWindowDisplayAffinity = modUser32.NewProc("SetWindowDisplayAffinity")
	procSetWindowsHookExW        = modUser32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx      = modUser32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx           = modUser32.NewProc("CallNextHookEx")
	procBeginPaint               = modUser32.NewProc("BeginPaint")
	procEndPaint                 = modUser32.NewProc("EndPaint")
	procFillRect                 = modUser32.NewProc("FillRect")
	procDrawTextW                = modUser32.NewProc("DrawTextW")
	procGetClientRect            = modUser32.NewProc("GetClientRect")
	procInvalidateRect           = modUser32.NewProc("InvalidateRect")
	procGetStockObject           = modGdi32.NewProc("GetStockObject")
	procSetTextColor             = modGdi32.NewProc("SetTextColor")
	procSetBkMode                = modGdi32.NewProc("SetBkMode")
)

const (
	wsPopup           = 0x80000000
	wsExTopmost       = 0x00000008
	wsExToolWindow    = 0x00000080
	wsExNoActivate    = 0x08000000
	swHide            = 0
	swShowNoActivate  = 4
	swpNoActivate     = 0x0010
	swpShowWindow     = 0x0040
	hwndTopmost       = ^uintptr(0) // (HWND)-1
	wdaExcludeCapture = 0x00000011
	whKeyboardLL      = 13
	whMouseLL         = 14
	llkhfInjected     = 0x10
	llmhfInjected     = 0x01
	wmClose           = 0x0010
	wmPaint           = 0x000f
	wmMouseActivate   = 0x0021
	wmQuit            = 0x0012
	wmApp             = 0x8000
	maNoActivate      = 3
	blackBrush        = 4
	bkTransparent     = 1
	dtCenter          = 0x01
	dtVCenter         = 0x04
	dtSingleLine      = 0x20
	lockClassName     = "OpenScaleRemoteDesktopLock"
)

type lockWndClass struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type lockMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
	Private uint32
}

type paintStruct struct {
	Hdc       uintptr
	Erase     int32
	RcPaint   winRect
	Restore   int32
	IncUpdate int32
	Reserved  [32]byte
}

type kbdLLHook struct {
	VkCode, ScanCode, Flags, Time uint32
	ExtraInfo                     uintptr
}

type msLLHook struct {
	PtX, PtY               int32
	MouseData, Flags, Time uint32
	ExtraInfo              uintptr
}

var (
	lockClassOnce sync.Once
	lockClassErr  error
	lockClass     *uint16
	lockWndProcCB uintptr
	kbHookCB      uintptr
	msHookCB      uintptr
	// lockNotice is the text drawn on the blanked screen. Only one lock
	// can be active (one control session at a time).
	lockNotice atomic.Pointer[[]uint16]
	lockActive atomic.Bool
)

func registerLockClass(hinst windows.Handle) error {
	lockClassOnce.Do(func() {
		name, err := windows.UTF16PtrFromString(lockClassName)
		if err != nil {
			lockClassErr = err
			return
		}
		lockWndProcCB = windows.NewCallback(lockWndProc)
		kbHookCB = windows.NewCallback(lockKeyboardHook)
		msHookCB = windows.NewCallback(lockMouseHook)
		wc := lockWndClass{WndProc: lockWndProcCB, Instance: hinst, ClassName: name}
		wc.Size = uint32(unsafe.Sizeof(wc))
		atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 && !errors.Is(callErr, windows.ERROR_CLASS_ALREADY_EXISTS) {
			lockClassErr = fmt.Errorf("pencere sınıfı kaydedilemedi: %w", callErr)
			return
		}
		lockClass = name
	})
	return lockClassErr
}

func lockWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch uint32(msg) {
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			brush, _, _ := procGetStockObject.Call(blackBrush)
			procFillRect.Call(hdc, uintptr(unsafe.Pointer(&ps.RcPaint)), brush)
			if text := lockNotice.Load(); text != nil && len(*text) > 1 {
				var rc winRect
				procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
				procSetTextColor.Call(hdc, 0x00ffffff)
				procSetBkMode.Call(hdc, bkTransparent)
				procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&(*text)[0])), ^uintptr(0), uintptr(unsafe.Pointer(&rc)), dtCenter|dtVCenter|dtSingleLine)
			}
			procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		}
		return 0
	case wmClose:
		// Alt+F4 does not remove the overlay; ending the session does.
		return 0
	case wmMouseActivate:
		return maNoActivate
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func lockKeyboardHook(code, wparam, lparam uintptr) uintptr {
	if int32(code) == 0 && lockActive.Load() && lparam != 0 {
		if k := (*kbdLLHook)(ptrFromHandle(lparam)); k.Flags&llkhfInjected == 0 {
			return 1
		}
	}
	r, _, _ := procCallNextHookEx.Call(0, code, wparam, lparam)
	return r
}

func lockMouseHook(code, wparam, lparam uintptr) uintptr {
	if int32(code) == 0 && lockActive.Load() && lparam != 0 {
		if m := (*msLLHook)(ptrFromHandle(lparam)); m.Flags&llmhfInjected == 0 {
			return 1
		}
	}
	r, _, _ := procCallNextHookEx.Call(0, code, wparam, lparam)
	return r
}

type lockCmd struct {
	st     LockState
	notice string
	done   chan error
}

type winLocalLock struct {
	tid    uint32
	cmds   chan lockCmd
	exited chan struct{}
	once   sync.Once
}

// NewSystemLocalLock starts the overlay thread. The service passes it as
// Config.NewLocalLock only when the owner allows blanking.
func NewSystemLocalLock() (LocalLock, error) {
	l := &winLocalLock{cmds: make(chan lockCmd, 1), exited: make(chan struct{})}
	ready := make(chan error, 1)
	go l.loop(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return l, nil
}

func (l *winLocalLock) loop(ready chan<- error) {
	runtime.LockOSThread()
	// The thread is never unlocked; the runtime ends it with the
	// goroutine, which also removes any hook left behind.
	defer close(l.exited)
	if procSetThreadDpiAwarenessContext.Find() == nil {
		if r, _, _ := procSetThreadDpiAwarenessContext.Call(dpiAwarenessPerMonitorV2); r == 0 {
			_, _, _ = procSetThreadDpiAwarenessContext.Call(dpiAwarenessPerMonitor)
		}
	}
	var hinst windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &hinst); err != nil {
		ready <- err
		return
	}
	if err := registerLockClass(hinst); err != nil {
		ready <- err
		return
	}
	hwnd, _, callErr := procCreateWindowExW.Call(wsExTopmost|wsExToolWindow|wsExNoActivate,
		uintptr(unsafe.Pointer(lockClass)), 0, wsPopup, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
	if hwnd == 0 {
		ready <- fmt.Errorf("rdesk: kilit penceresi oluşturulamadı: %w", callErr)
		return
	}
	canBlank := false
	if procSetWindowDisplayAffinity.Find() == nil {
		r, _, _ := procSetWindowDisplayAffinity.Call(hwnd, wdaExcludeCapture)
		canBlank = r != 0
	}
	var kbHook, msHook uintptr
	unhook := func() {
		lockActive.Store(false)
		if kbHook != 0 {
			procUnhookWindowsHookEx.Call(kbHook)
			kbHook = 0
		}
		if msHook != 0 {
			procUnhookWindowsHookEx.Call(msHook)
			msHook = 0
		}
	}
	defer func() {
		unhook()
		procDestroyWindow.Call(hwnd)
	}()
	l.tid = windows.GetCurrentThreadId()
	ready <- nil

	apply := func(c lockCmd) error {
		if c.st.Blank && !canBlank {
			return fmt.Errorf("%w: ekran yakalamadan hariç tutma yok (Windows 10 2004 gerekir)", ErrUnsupported)
		}
		if c.st.Input && kbHook == 0 {
			kbHook, _, _ = procSetWindowsHookExW.Call(whKeyboardLL, kbHookCB, uintptr(hinst), 0)
			msHook, _, _ = procSetWindowsHookExW.Call(whMouseLL, msHookCB, uintptr(hinst), 0)
			if kbHook == 0 || msHook == 0 {
				unhook()
				return errors.New("rdesk: giriş kilidi kurulamadı")
			}
		}
		if !c.st.Input {
			unhook()
		}
		lockActive.Store(c.st.Input)
		if c.st.Blank {
			text, err := windows.UTF16FromString(c.notice)
			if err != nil {
				text = []uint16{0}
			}
			lockNotice.Store(&text)
			x, y := metric(smXVirtualScreen), metric(smYVirtualScreen)
			w, h := metric(smCXVirtualScreen), metric(smCYVirtualScreen)
			procSetWindowPos.Call(hwnd, hwndTopmost, uintptr(int32(x)), uintptr(int32(y)), uintptr(int32(w)), uintptr(int32(h)), swpNoActivate|swpShowWindow)
			procShowWindow.Call(hwnd, swShowNoActivate)
			procInvalidateRect.Call(hwnd, 0, 1)
		} else {
			procShowWindow.Call(hwnd, swHide)
		}
		return nil
	}

	var m lockMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		if m.HWnd == 0 && m.Message == wmApp {
			select {
			case c := <-l.cmds:
				c.done <- apply(c)
			default:
			}
			continue
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (l *winLocalLock) Set(st LockState, notice string) error {
	c := lockCmd{st: st, notice: notice, done: make(chan error, 1)}
	select {
	case l.cmds <- c:
	case <-l.exited:
		return errClosed
	}
	if r, _, err := procPostThreadMessageW.Call(uintptr(l.tid), wmApp, 0, 0); r == 0 {
		// Take the command back so it is not applied later.
		select {
		case <-l.cmds:
		default:
		}
		return fmt.Errorf("rdesk: kilit iş parçacığına ulaşılamadı: %w", err)
	}
	select {
	case err := <-c.done:
		return err
	case <-l.exited:
		return errClosed
	}
}

func (l *winLocalLock) Close() error {
	l.once.Do(func() {
		procPostThreadMessageW.Call(uintptr(l.tid), wmQuit, 0, 0)
	})
	<-l.exited
	return nil
}
