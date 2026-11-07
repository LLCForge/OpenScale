//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/secmem"
)

var (
	siUser32                  = windows.NewLazySystemDLL("user32.dll")
	siProcCreateDesktopW      = siUser32.NewProc("CreateDesktopW")
	siProcSwitchDesktop       = siUser32.NewProc("SwitchDesktop")
	siProcSetThreadDesktop    = siUser32.NewProc("SetThreadDesktop")
	siProcGetThreadDesktop    = siUser32.NewProc("GetThreadDesktop")
	siProcOpenInputDesktop    = siUser32.NewProc("OpenInputDesktop")
	siProcCloseDesktop        = siUser32.NewProc("CloseDesktop")
	siProcRegisterClassExW    = siUser32.NewProc("RegisterClassExW")
	siProcCreateWindowExW     = siUser32.NewProc("CreateWindowExW")
	siProcDefWindowProcW      = siUser32.NewProc("DefWindowProcW")
	siProcDestroyWindow       = siUser32.NewProc("DestroyWindow")
	siProcGetMessageW         = siUser32.NewProc("GetMessageW")
	siProcIsDialogMessageW    = siUser32.NewProc("IsDialogMessageW")
	siProcTranslateMessage    = siUser32.NewProc("TranslateMessage")
	siProcDispatchMessageW    = siUser32.NewProc("DispatchMessageW")
	siProcPostQuitMessage     = siUser32.NewProc("PostQuitMessage")
	siProcGetWindowTextW      = siUser32.NewProc("GetWindowTextW")
	siProcGetWindowTextLength = siUser32.NewProc("GetWindowTextLengthW")
	siProcSetWindowTextW      = siUser32.NewProc("SetWindowTextW")
	siProcSendMessageW        = siUser32.NewProc("SendMessageW")
	siProcSetFocus            = siUser32.NewProc("SetFocus")
	siProcShowWindow          = siUser32.NewProc("ShowWindow")
	siProcGetSystemMetrics    = siUser32.NewProc("GetSystemMetrics")
	siProcGetModuleHandleW    = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")
)

const (
	siDesktopReadObjects   = 0x0001
	siDesktopCreateWindow  = 0x0002
	siDesktopCreateMenu    = 0x0004
	siDesktopHookControl   = 0x0008
	siDesktopWriteObjects  = 0x0080
	siDesktopSwitchDesktop = 0x0100
	siDesktopAccess        = siDesktopReadObjects | siDesktopCreateWindow | siDesktopCreateMenu | siDesktopHookControl | siDesktopWriteObjects | siDesktopSwitchDesktop

	siWsOverlapped   = 0x00000000
	siWsCaption      = 0x00C00000
	siWsSysMenu      = 0x00080000
	siWsVisible      = 0x10000000
	siWsChild        = 0x40000000
	siWsTabStop      = 0x00010000
	siWsBorder       = 0x00800000
	siEsPassword     = 0x0020
	siEsAutoHScroll  = 0x0080
	siBsDefPush      = 0x0001
	siWmDestroy      = 0x0002
	siWmClose        = 0x0010
	siWmCommand      = 0x0111
	siWmSetText      = 0x000C
	siEmLimitText    = 0x00C5
	siIdOK           = 1
	siIdCancel       = 2
	siIdEdit         = 100
	siSwShow         = 5
	siSmCxScreen     = 0
	siSmCyScreen     = 1
	siSecureDeskName = "OpenScaleGuvenliGiris"
)

type siWndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type siWinMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      [2]int32
	private uint32
}

// promptState is the one prompt running (prompts are serialized).
var promptState struct {
	sync.Mutex
	edit      uintptr
	ok        bool
	class     *uint16
	proc      uintptr
	registerd bool
}

func secureWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch uint32(msg) {
	case siWmCommand:
		switch wParam & 0xffff {
		case siIdOK:
			promptState.ok = true
			siProcDestroyWindow.Call(hwnd)
			return 0
		case siIdCancel:
			siProcDestroyWindow.Call(hwnd)
			return 0
		}
	case siWmClose:
		siProcDestroyWindow.Call(hwnd)
		return 0
	case siWmDestroy:
		siProcPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := siProcDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

var secureProcOnce sync.Once

// ReadSecretSecureDesktop shows the passphrase prompt on a separate
// desktop and returns the passphrase in locked memory. The user's desktop
// is restored on every path.
func ReadSecretSecureDesktop(prompt string) (*secmem.Buffer, error) {
	if err := siProcCreateDesktopW.Find(); err != nil {
		return nil, ErrSecureInputUnavailable
	}
	promptState.Lock()
	defer promptState.Unlock()
	secureProcOnce.Do(func() { promptState.proc = windows.NewCallback(secureWndProc) })

	type result struct {
		buf *secmem.Buffer
		err error
	}
	done := make(chan result, 1)
	go func() {
		// Desktop and window belong to one OS thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		b, err := runSecurePrompt(promptText(prompt))
		done <- result{b, err}
	}()
	r := <-done
	return r.buf, r.err
}

func runSecurePrompt(prompt string) (*secmem.Buffer, error) {
	tid := windows.GetCurrentThreadId()
	oldThreadDesk, _, _ := siProcGetThreadDesktop.Call(uintptr(tid))
	inputDesk, _, _ := siProcOpenInputDesktop.Call(0, 0, siDesktopSwitchDesktop)
	if oldThreadDesk == 0 || inputDesk == 0 {
		return nil, ErrSecureInputUnavailable
	}
	defer siProcCloseDesktop.Call(inputDesk)
	name, _ := windows.UTF16PtrFromString(siSecureDeskName)
	desk, _, err := siProcCreateDesktopW.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, siDesktopAccess, 0)
	if desk == 0 {
		return nil, fmt.Errorf("%w: %v", ErrSecureInputUnavailable, err)
	}
	defer siProcCloseDesktop.Call(desk)
	if r, _, err := siProcSetThreadDesktop.Call(desk); r == 0 {
		return nil, fmt.Errorf("%w: %v", ErrSecureInputUnavailable, err)
	}
	defer siProcSetThreadDesktop.Call(oldThreadDesk)
	if r, _, err := siProcSwitchDesktop.Call(desk); r == 0 {
		return nil, fmt.Errorf("%w: %v", ErrSecureInputUnavailable, err)
	}
	// Back to the user's desktop whatever happens below.
	defer siProcSwitchDesktop.Call(inputDesk)
	return promptWindow(prompt)
}

func promptWindow(prompt string) (*secmem.Buffer, error) {
	inst, _, _ := siProcGetModuleHandleW.Call(0)
	if !promptState.registerd {
		cls, _ := windows.UTF16PtrFromString("OpenScaleSecureInput")
		wc := siWndClassEx{wndProc: promptState.proc, instance: windows.Handle(inst), className: cls, background: windows.Handle(16)} // COLOR_BTNFACE+1
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, err := siProcRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			return nil, fmt.Errorf("%w: %v", ErrSecureInputUnavailable, err)
		}
		promptState.class, promptState.registerd = cls, true
	}
	promptState.ok, promptState.edit = false, 0
	const w, h = 460, 190
	sw, _, _ := siProcGetSystemMetrics.Call(siSmCxScreen)
	sh, _, _ := siProcGetSystemMetrics.Call(siSmCyScreen)
	title, _ := windows.UTF16PtrFromString(DisplayName() + " - güvenli parola girişi")
	hwnd, _, err := siProcCreateWindowExW.Call(0, uintptr(unsafe.Pointer(promptState.class)), uintptr(unsafe.Pointer(title)),
		siWsOverlapped|siWsCaption|siWsSysMenu|siWsVisible, (sw-w)/2, (sh-h)/2, w, h, 0, 0, inst, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("%w: %v", ErrSecureInputUnavailable, err)
	}
	child := func(class, text string, style, x, y, cw, ch, id uintptr) uintptr {
		c, _ := windows.UTF16PtrFromString(class)
		t, _ := windows.UTF16PtrFromString(text)
		r, _, _ := siProcCreateWindowExW.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(t)),
			siWsChild|siWsVisible|style, x, y, cw, ch, hwnd, id, inst, 0)
		return r
	}
	child("STATIC", prompt+":", 0, 16, 16, 420, 36, 0)
	edit := child("EDIT", "", siWsTabStop|siWsBorder|siEsPassword|siEsAutoHScroll, 16, 56, 420, 26, siIdEdit)
	child("BUTTON", "Tamam", siWsTabStop|siBsDefPush, 236, 104, 96, 30, siIdOK)
	child("BUTTON", "İptal", siWsTabStop, 340, 104, 96, 30, siIdCancel)
	if edit == 0 {
		siProcDestroyWindow.Call(hwnd)
		return nil, ErrSecureInputUnavailable
	}
	siProcSendMessageW.Call(edit, siEmLimitText, maxSecretRunes, 0)
	promptState.edit = edit
	siProcShowWindow.Call(hwnd, siSwShow)
	siProcSetFocus.Call(edit)

	var secret *secmem.Buffer
	var readErr error
	var m siWinMsg
	for {
		r, _, _ := siProcGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		// Read the field before the OK button destroys the window.
		if m.message == siWmCommand && m.wParam&0xffff == siIdOK || isEnterOnEdit(&m) {
			secret, readErr = readEditSecret(edit)
		}
		if d, _, _ := siProcIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		siProcTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		siProcDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	if !promptState.ok {
		secret.Destroy()
		return nil, ErrSecureInputCancelled
	}
	if secret == nil && readErr == nil {
		readErr = errors.New("parola okunamadı")
	}
	return secret, readErr
}

const (
	siWmKeyDown = 0x0100
	siVkReturn  = 0x0D
)

func isEnterOnEdit(m *siWinMsg) bool {
	return m.message == siWmKeyDown && m.wParam == siVkReturn && m.hwnd == promptState.edit
}

// readEditSecret copies the field into locked memory and overwrites the
// control's text.
func readEditSecret(edit uintptr) (*secmem.Buffer, error) {
	n, _, _ := siProcGetWindowTextLength.Call(edit)
	if n == 0 || n > maxSecretRunes {
		return nil, errors.New("parola boş veya çok uzun")
	}
	raw, err := secmem.New(int(n+1) * 2)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&raw.Bytes()[0])), n+1)
	got, _, _ := siProcGetWindowTextW.Call(edit, uintptr(unsafe.Pointer(&u[0])), n+1)
	// Overwrite the control's buffer with filler of the same length, then
	// empty it.
	filler := make([]uint16, n+1)
	for i := range filler[:n] {
		filler[i] = '*'
	}
	siProcSetWindowTextW.Call(edit, uintptr(unsafe.Pointer(&filler[0])))
	empty := []uint16{0}
	siProcSendMessageW.Call(edit, siWmSetText, 0, uintptr(unsafe.Pointer(&empty[0])))
	if got == 0 {
		return nil, errors.New("parola okunamadı")
	}
	// UTF-16 to UTF-8 without a Go string.
	out, err := secmem.New(int(got) * 3)
	if err != nil {
		return nil, err
	}
	dst := out.Bytes()
	w := 0
	runes := utf16.Decode(u[:got])
	for _, r := range runes {
		w += encodeRune(dst[w:], r)
	}
	clear(runes)
	res, err := secmem.New(w)
	if err != nil {
		out.Destroy()
		return nil, err
	}
	copy(res.Bytes(), dst[:w])
	out.Destroy()
	return res, nil
}

// encodeRune writes r as UTF-8 into p (which has room) and returns the
// length; it avoids utf8.AppendRune's growth on a heap slice.
func encodeRune(p []byte, r rune) int {
	switch {
	case r < 0x80:
		p[0] = byte(r)
		return 1
	case r < 0x800:
		p[0], p[1] = 0xC0|byte(r>>6), 0x80|byte(r)&0x3F
		return 2
	case r < 0x10000:
		p[0], p[1], p[2] = 0xE0|byte(r>>12), 0x80|byte(r>>6)&0x3F, 0x80|byte(r)&0x3F
		return 3
	default:
		p[0], p[1], p[2], p[3] = 0xF0|byte(r>>18), 0x80|byte(r>>12)&0x3F, 0x80|byte(r>>6)&0x3F, 0x80|byte(r)&0x3F
		return 4
	}
}
