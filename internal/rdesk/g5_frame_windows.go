//go:build windows

package rdesk

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows "remotely connected" frame (#671) and kill shortcut (#672).
//
// The frame is one topmost, layered, click-through tool window over the
// virtual desktop. Its inside is painted in a color key and is therefore
// transparent; only a red border and a label at the top are visible. It
// takes no input (WS_EX_TRANSPARENT, never activated), ignores WM_CLOSE
// and a timer puts it back on top every second. It is excluded from
// screen capture when the system allows it, so the viewer's picture is
// not covered.

var (
	procSetLayeredWindowAttributes = modUser32.NewProc("SetLayeredWindowAttributes")
	procSetTimer                   = modUser32.NewProc("SetTimer")
	procRegisterHotKey             = modUser32.NewProc("RegisterHotKey")
	procUnregisterHotKey           = modUser32.NewProc("UnregisterHotKey")
	procCreateSolidBrush           = modGdi32.NewProc("CreateSolidBrush")
)

const (
	wsExLayered       = 0x00080000
	wsExTransparent   = 0x00000020
	lwaColorKey       = 0x00000001
	wmTimer           = 0x0113
	wmDisplayChange   = 0x007e
	wmHotkey          = 0x0312
	frameTimerID      = 1
	frameColorKey     = 0x00ff00ff // magenta, COLORREF 0x00BBGGRR
	frameRed          = 0x000000e0
	frameWhite        = 0x00ffffff
	frameBorder       = 6
	frameLabelW       = 640
	frameLabelH       = 34
	frameClassName    = "OpenScaleRemoteFrame"
	modAltWin         = 0x0001
	modControlWin     = 0x0002
	modShiftWin       = 0x0004
	modWinWin         = 0x0008
	modNoRepeatWin    = 0x4000
	killHotkeyID      = 0x4f53 // "OS"
	swpNoSize         = 0x0001
	swpNoMove         = 0x0002
	frameShowFlags    = swpNoActivate | swpShowWindow
	frameRefreshFlags = swpNoActivate | swpNoMove | swpNoSize | swpShowWindow
)

var (
	frameClassOnce sync.Once
	frameClassErr  error
	frameClass     *uint16
	frameProcCB    uintptr
	// frameTexts maps a frame window to its label.
	frameTexts sync.Map // uintptr -> []uint16
)

func registerFrameClass(hinst windows.Handle) error {
	frameClassOnce.Do(func() {
		name, err := windows.UTF16PtrFromString(frameClassName)
		if err != nil {
			frameClassErr = err
			return
		}
		frameProcCB = windows.NewCallback(frameWndProc)
		wc := lockWndClass{WndProc: frameProcCB, Instance: hinst, ClassName: name}
		wc.Size = uint32(unsafe.Sizeof(wc))
		atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 && !errors.Is(callErr, windows.ERROR_CLASS_ALREADY_EXISTS) {
			frameClassErr = fmt.Errorf("çerçeve pencere sınıfı kaydedilemedi: %w", callErr)
			return
		}
		frameClass = name
	})
	return frameClassErr
}

func fillRect(hdc uintptr, l, t, r, b int32, color uintptr) {
	brush, _, _ := procCreateSolidBrush.Call(color)
	if brush == 0 {
		return
	}
	rc := winRect{Left: l, Top: t, Right: r, Bottom: b}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), brush)
	procDeleteObject.Call(brush)
}

func frameWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch uint32(msg) {
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			var rc winRect
			procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			fillRect(hdc, rc.Left, rc.Top, rc.Right, rc.Bottom, frameColorKey)
			fillRect(hdc, rc.Left, rc.Top, rc.Right, rc.Top+frameBorder, frameRed)
			fillRect(hdc, rc.Left, rc.Bottom-frameBorder, rc.Right, rc.Bottom, frameRed)
			fillRect(hdc, rc.Left, rc.Top, rc.Left+frameBorder, rc.Bottom, frameRed)
			fillRect(hdc, rc.Right-frameBorder, rc.Top, rc.Right, rc.Bottom, frameRed)
			w := min(int32(frameLabelW), rc.Right-rc.Left)
			lx := rc.Left + (rc.Right-rc.Left-w)/2
			label := winRect{Left: lx, Top: rc.Top, Right: lx + w, Bottom: rc.Top + frameLabelH}
			fillRect(hdc, label.Left, label.Top, label.Right, label.Bottom, frameRed)
			if v, ok := frameTexts.Load(hwnd); ok {
				text := v.([]uint16)
				if len(text) > 1 {
					procSetTextColor.Call(hdc, frameWhite)
					procSetBkMode.Call(hdc, bkTransparent)
					procDrawTextW.Call(hdc, uintptr(unsafe.Pointer(&text[0])), ^uintptr(0), uintptr(unsafe.Pointer(&label)), dtCenter|dtVCenter|dtSingleLine)
				}
			}
			procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		}
		return 0
	case wmClose:
		// The frame goes only when the session ends.
		return 0
	case wmMouseActivate:
		return maNoActivate
	case wmTimer:
		procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0, frameRefreshFlags)
		return 0
	case wmDisplayChange:
		placeFrame(hwnd)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func placeFrame(hwnd uintptr) {
	x, y := metric(smXVirtualScreen), metric(smYVirtualScreen)
	w, h := metric(smCXVirtualScreen), metric(smCYVirtualScreen)
	procSetWindowPos.Call(hwnd, hwndTopmost, uintptr(int32(x)), uintptr(int32(y)), uintptr(int32(w)), uintptr(int32(h)), frameShowFlags)
	procInvalidateRect.Call(hwnd, 0, 1)
}

type winFrame struct {
	tid    uint32
	hwnd   uintptr // for SetText (f3_lang_windows.go)
	exited chan struct{}
	once   sync.Once
}

// NewSystemFrame shows the frame for one session. The service passes it
// as Config.NewFrame.
func NewSystemFrame(fi FrameInfo) (SessionFrame, error) {
	f := &winFrame{exited: make(chan struct{})}
	ready := make(chan error, 1)
	go f.loop(fi.Text(), ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return f, nil
}

func (f *winFrame) loop(text string, ready chan<- error) {
	runtime.LockOSThread()
	// Never unlocked: the runtime ends the thread with the goroutine.
	defer close(f.exited)
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
	if err := registerFrameClass(hinst); err != nil {
		ready <- err
		return
	}
	hwnd, _, callErr := procCreateWindowExW.Call(wsExTopmost|wsExToolWindow|wsExNoActivate|wsExLayered|wsExTransparent,
		uintptr(unsafe.Pointer(frameClass)), 0, wsPopup, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
	if hwnd == 0 {
		ready <- fmt.Errorf("rdesk: çerçeve penceresi oluşturulamadı: %w", callErr)
		return
	}
	defer func() {
		frameTexts.Delete(hwnd)
		procDestroyWindow.Call(hwnd)
	}()
	u, err := windows.UTF16FromString(text)
	if err != nil {
		u = []uint16{0}
	}
	frameTexts.Store(hwnd, u)
	if r, _, err := procSetLayeredWindowAttributes.Call(hwnd, frameColorKey, 0, lwaColorKey); r == 0 {
		ready <- fmt.Errorf("rdesk: çerçeve saydamlığı ayarlanamadı: %w", err)
		return
	}
	if procSetWindowDisplayAffinity.Find() == nil {
		_, _, _ = procSetWindowDisplayAffinity.Call(hwnd, wdaExcludeCapture)
	}
	placeFrame(hwnd)
	procShowWindow.Call(hwnd, swShowNoActivate)
	procSetTimer.Call(hwnd, frameTimerID, 1000, 0)
	f.tid = windows.GetCurrentThreadId()
	f.hwnd = hwnd
	ready <- nil
	var m lockMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (f *winFrame) Close() error {
	f.once.Do(func() {
		procPostThreadMessageW.Call(uintptr(f.tid), wmQuit, 0, 0)
	})
	<-f.exited
	return nil
}

// WatchKillHotkey registers h as a global shortcut of the interactive
// session and calls fn on every press until ctx ends. It fails when
// another program already owns the combination.
func WatchKillHotkey(ctx context.Context, h Hotkey, fn func()) error {
	if !h.Valid() {
		return errors.New("rdesk: geçersiz kısayol")
	}
	mods := uintptr(modNoRepeatWin)
	if h.Mods&HotkeyModControl != 0 {
		mods |= modControlWin
	}
	if h.Mods&HotkeyModAlt != 0 {
		mods |= modAltWin
	}
	if h.Mods&HotkeyModShift != 0 {
		mods |= modShiftWin
	}
	if h.Mods&HotkeyModSuper != 0 {
		mods |= modWinWin
	}
	ready := make(chan error, 1)
	var tid uint32
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(done)
		if r, _, err := procRegisterHotKey.Call(0, killHotkeyID, mods, uintptr(h.Key)); r == 0 {
			ready <- fmt.Errorf("rdesk: kısayol %s kaydedilemedi (başka bir program kullanıyor olabilir): %w", h, err)
			return
		}
		defer procUnregisterHotKey.Call(0, killHotkeyID)
		tid = windows.GetCurrentThreadId()
		ready <- nil
		var m lockMsg
		for {
			r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			if m.Message == wmHotkey && m.WParam == killHotkeyID {
				fn()
			}
		}
	}()
	if err := <-ready; err != nil {
		<-done
		return err
	}
	select {
	case <-ctx.Done():
		procPostThreadMessageW.Call(uintptr(tid), wmQuit, 0, 0)
		<-done
		return nil
	case <-done:
		return errors.New("rdesk: kısayol iş parçacığı beklenmedik biçimde bitti")
	}
}
