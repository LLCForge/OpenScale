//go:build windows

package winapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// GDI-painted tray windows (f3_ui.go). Each window runs its own message
// loop on a locked OS thread; ShowUI blocks until it closes. Text comes
// only from UIModel and is drawn with DT_NOPREFIX, so no "&" turns into a
// keyboard accelerator and nothing is interpreted.

var (
	f3User32 = windows.NewLazySystemDLL("user32.dll")
	f3Gdi32  = windows.NewLazySystemDLL("gdi32.dll")
	f3Kernel = windows.NewLazySystemDLL("kernel32.dll")

	f3BeginPaint          = f3User32.NewProc("BeginPaint")
	f3EndPaint            = f3User32.NewProc("EndPaint")
	f3InvalidateRect      = f3User32.NewProc("InvalidateRect")
	f3GetClientRect       = f3User32.NewProc("GetClientRect")
	f3FillRect            = f3User32.NewProc("FillRect")
	f3DrawTextW           = f3User32.NewProc("DrawTextW")
	f3SetWindowPos        = f3User32.NewProc("SetWindowPos")
	f3ShowWindow          = f3User32.NewProc("ShowWindow")
	f3SetTimer            = f3User32.NewProc("SetTimer")
	f3KillTimer           = f3User32.NewProc("KillTimer")
	f3GetForegroundWindow = f3User32.NewProc("GetForegroundWindow")
	f3MonitorFromPoint    = f3User32.NewProc("MonitorFromPoint")
	f3GetMonitorInfoW     = f3User32.NewProc("GetMonitorInfoW")
	f3GetDpiForSystem     = f3User32.NewProc("GetDpiForSystem")
	f3LoadCursorW         = f3User32.NewProc("LoadCursorW")
	f3SetFocus            = f3User32.NewProc("SetFocus")
	f3BringWindowToTop    = f3User32.NewProc("BringWindowToTop")
	f3SetWindowTextW      = f3User32.NewProc("SetWindowTextW")

	f3CreateFontW          = f3Gdi32.NewProc("CreateFontW")
	f3CreateSolidBrush     = f3Gdi32.NewProc("CreateSolidBrush")
	f3SelectObject         = f3Gdi32.NewProc("SelectObject")
	f3DeleteObject         = f3Gdi32.NewProc("DeleteObject")
	f3SetTextColor         = f3Gdi32.NewProc("SetTextColor")
	f3SetBkMode            = f3Gdi32.NewProc("SetBkMode")
	f3CreateCompatibleDC   = f3Gdi32.NewProc("CreateCompatibleDC")
	f3CreateCompatibleBmp  = f3Gdi32.NewProc("CreateCompatibleBitmap")
	f3BitBlt               = f3Gdi32.NewProc("BitBlt")
	f3DeleteDC             = f3Gdi32.NewProc("DeleteDC")
	f3GetUserDefaultUILang = f3Kernel.NewProc("GetUserDefaultUILanguage")
)

const (
	f3WsPopup        = 0x80000000
	f3WsCaption      = 0x00C00000
	f3WsSysMenu      = 0x00080000
	f3WsBorder       = 0x00800000
	f3WsExTopmost    = 0x00000008
	f3WsExToolWindow = 0x00000080
	f3WsExDlgFrame   = 0x00000001

	f3WmPaint       = 0x000F
	f3WmEraseBkgnd  = 0x0014
	f3WmActivate    = 0x0006
	f3WmKeyDown     = 0x0100
	f3WmLButtonUp   = 0x0202
	f3WmMouseMove   = 0x0200
	f3WmTimer       = 0x0113
	f3WmSetCursor   = 0x0020
	f3WmModel       = wmApp + 40
	f3WmGetMinMax   = 0x0024
	f3WaInactive    = 0
	f3SwShow        = 5
	f3SwpNoZOrder   = 0x0004
	f3SwpNoActivate = 0x0010
	f3SwpShowWindow = 0x0040
	f3HwndTopmost   = ^uintptr(0) // (HWND)-1

	f3DtLeft       = 0x0000
	f3DtCenter     = 0x0001
	f3DtRight      = 0x0002
	f3DtVCenter    = 0x0004
	f3DtSingleLine = 0x0020
	f3DtNoPrefix   = 0x0800
	f3DtEndEllip   = 0x8000
	f3Transparent  = 1
	f3Srccopy      = 0x00CC0020

	f3VkReturn = 0x0D
	f3VkEscape = 0x1B
	f3VkTab    = 0x09
	f3VkUp     = 0x26
	f3VkDown   = 0x28
	f3VkSpace  = 0x20

	f3TimerFocus    = 1
	f3MonitorNear   = 2
	f3IdcArrow      = 32512
	f3IdcHand       = 32649
	dwmwaDarkMode   = 20
	dwmwaCornerPref = 33
	dwmwcpRound     = 2
	f3ClassName     = "OpenScaleTrayWindowF3"
)

type f3Rect struct{ Left, Top, Right, Bottom int32 }

type f3PaintStruct struct {
	HDC         uintptr
	FErase      int32
	RcPaint     f3Rect
	FRestore    int32
	FIncUpdate  int32
	RGBReserved [32]byte
}

type f3MonitorInfo struct {
	CbSize    uint32
	RcMonitor f3Rect
	RcWork    f3Rect
	DwFlags   uint32
}

// uiTheme holds COLORREF values (0x00BBGGRR).
type uiTheme struct {
	bg, fg, muted, warn, border, btn, btnFg, accent, accentFg, sel uintptr
	dark                                                           bool
}

func rgb(r, g, b uint8) uintptr { return uintptr(r) | uintptr(g)<<8 | uintptr(b)<<16 }

// systemDark reads the "apps" or "system" light theme setting of the
// signed-in user.
func systemDark(system bool) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	name := "AppsUseLightTheme"
	if system {
		name = "SystemUsesLightTheme"
	}
	v, _, err := k.GetIntegerValue(name)
	return err == nil && v == 0
}

func themeFor(kind UIKind) uiTheme {
	if systemDark(kind == UIFlyout) {
		return uiTheme{bg: rgb(0x20, 0x20, 0x20), fg: rgb(0xFF, 0xFF, 0xFF), muted: rgb(0xA8, 0xA8, 0xA8), warn: rgb(0xFC, 0xC0, 0x4E),
			border: rgb(0x3A, 0x3A, 0x3A), btn: rgb(0x2D, 0x2D, 0x2D), btnFg: rgb(0xFF, 0xFF, 0xFF), accent: rgb(0x4C, 0xC2, 0xFF),
			accentFg: rgb(0x00, 0x00, 0x00), sel: rgb(0x3A, 0x3A, 0x3A), dark: true}
	}
	return uiTheme{bg: rgb(0xF9, 0xF9, 0xF9), fg: rgb(0x1A, 0x1A, 0x1A), muted: rgb(0x5F, 0x5F, 0x5F), warn: rgb(0x9D, 0x5D, 0x00),
		border: rgb(0xE0, 0xE0, 0xE0), btn: rgb(0xFF, 0xFF, 0xFF), btnFg: rgb(0x1A, 0x1A, 0x1A), accent: rgb(0x00, 0x5F, 0xB8),
		accentFg: rgb(0xFF, 0xFF, 0xFF), sel: rgb(0xE5, 0xF1, 0xFB)}
}

// UITurkish reports whether the Windows display language is Turkish. The
// panel keeps its language in the browser only, so the tray follows the
// system. OPENSCALE_LANG=tr|en overrides it.
func UITurkish() bool {
	if v := envLang(); v != "" {
		return v == "tr"
	}
	if f3GetUserDefaultUILang.Find() != nil {
		return true
	}
	r, _, _ := f3GetUserDefaultUILang.Call()
	return r&0x3ff == 0x1f // LANG_TURKISH
}

func envLang() string {
	v := os.Getenv("OPENSCALE_LANG")
	if v == "tr" || v == "en" {
		return v
	}
	return ""
}

type uiWindow struct {
	kind  UIKind
	hwnd  uintptr
	theme uiTheme
	scale float64

	mu    sync.Mutex
	model UIModel

	// Loop thread only.
	font, bold, small uintptr
	focus             int // index into model.Buttons; -1 none
	hover             int
	buttons           []f3Rect
	rows              []f3Rect
	result            UIResult
	initialFG         uintptr
	activated         bool
	closed            bool
}

var (
	f3ClassOnce sync.Once
	f3ClassErr  error
	f3Class     *uint16
	f3Windows   sync.Map // hwnd -> *uiWindow
)

func registerF3Class(hinst windows.Handle) error {
	f3ClassOnce.Do(func() {
		name, err := windows.UTF16PtrFromString(f3ClassName)
		if err != nil {
			f3ClassErr = err
			return
		}
		cur, _, _ := f3LoadCursorW.Call(0, f3IdcArrow)
		wc := wndClassEx{WndProc: windows.NewCallback(f3WndProc), Instance: hinst, ClassName: name, Cursor: windows.Handle(cur)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 && !errors.Is(callErr, windows.ERROR_CLASS_ALREADY_EXISTS) {
			f3ClassErr = fmt.Errorf("pencere sınıfı kaydedilemedi: %w", callErr)
			return
		}
		f3Class = name
	})
	return f3ClassErr
}

func (w *uiWindow) px(v int) int32 { return int32(float64(v)*w.scale + 0.5) }

// Layout constants in 96-dpi pixels.
const (
	uiWidthFlyout = 360
	uiWidthDialog = 440
	uiPad         = 16
	uiLineH       = 22
	uiTitleH      = 30
	uiRowH        = 30
	uiBtnH        = 32
	uiBtnW        = 120
	uiBtnGap      = 8
	uiProgressH   = 8
	uiMaxRows     = 8
)

// size computes the client size for the model.
func (w *uiWindow) size(m UIModel) (int32, int32) {
	width := uiWidthDialog
	if w.kind == UIFlyout {
		width = uiWidthFlyout
	}
	h := uiPad
	for _, l := range m.Lines {
		if l.Style == LineTitle {
			h += uiTitleH
		} else {
			h += uiLineH
		}
	}
	if len(m.List) > 0 {
		h += 6 + min(len(m.List), uiMaxRows)*uiRowH
	}
	if m.Progress >= 0 {
		h += 12 + uiProgressH
	}
	if len(m.Buttons) > 0 {
		h += 14 + uiBtnH
	}
	h += uiPad
	return w.px(width), w.px(h)
}

func (w *uiWindow) createFonts() {
	mk := func(pt int, weight int) uintptr {
		face, _ := windows.UTF16PtrFromString("Segoe UI")
		height := -int32(float64(pt) * w.scale * 96 / 72)
		f, _, _ := f3CreateFontW.Call(uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1 /*DEFAULT_CHARSET*/, 0, 0, 5 /*CLEARTYPE_QUALITY*/, 0, uintptr(unsafe.Pointer(face)))
		return f
	}
	w.font, w.bold, w.small = mk(10, 400), mk(12, 600), mk(9, 400)
}

func (w *uiWindow) deleteFonts() {
	for _, f := range []uintptr{w.font, w.bold, w.small} {
		if f != 0 {
			f3DeleteObject.Call(f)
		}
	}
}

func fill(hdc uintptr, r f3Rect, color uintptr) {
	br, _, _ := f3CreateSolidBrush.Call(color)
	if br == 0 {
		return
	}
	f3FillRect.Call(hdc, uintptr(unsafe.Pointer(&r)), br)
	f3DeleteObject.Call(br)
}

func drawText(hdc uintptr, s string, r f3Rect, font, color uintptr, flags uintptr) {
	if s == "" {
		return
	}
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	f3SelectObject.Call(hdc, font)
	f3SetTextColor.Call(hdc, color)
	f3SetBkMode.Call(hdc, f3Transparent)
	f3DrawTextW.Call(hdc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&r)), flags|f3DtNoPrefix|f3DtSingleLine|f3DtVCenter|f3DtEndEllip)
}

func outline(hdc uintptr, r f3Rect, t int32, color uintptr) {
	fill(hdc, f3Rect{r.Left, r.Top, r.Right, r.Top + t}, color)
	fill(hdc, f3Rect{r.Left, r.Bottom - t, r.Right, r.Bottom}, color)
	fill(hdc, f3Rect{r.Left, r.Top, r.Left + t, r.Bottom}, color)
	fill(hdc, f3Rect{r.Right - t, r.Top, r.Right, r.Bottom}, color)
}

func (w *uiWindow) paint(hdc uintptr, rc f3Rect) {
	w.mu.Lock()
	m := w.model
	w.mu.Unlock()
	th := w.theme
	fill(hdc, rc, th.bg)
	if w.kind == UIFlyout {
		outline(hdc, rc, 1, th.border)
	}
	pad := w.px(uiPad)
	y := pad
	left, right := rc.Left+pad, rc.Right-pad
	for _, l := range m.Lines {
		h := w.px(uiLineH)
		font, color := w.font, th.fg
		switch l.Style {
		case LineTitle:
			h, font = w.px(uiTitleH), w.bold
		case LineMuted:
			font, color = w.small, th.muted
		case LineWarn:
			color = th.warn
		case LineHeading:
			font, color = w.small, th.muted
		}
		r := f3Rect{left, y, right, y + h}
		if l.Value != "" {
			drawText(hdc, l.Value, r, font, th.fg, f3DtRight)
			r.Right = right - (right-left)*45/100
		}
		drawText(hdc, l.Text, r, font, color, f3DtLeft)
		y += h
	}
	w.rows = w.rows[:0]
	if len(m.List) > 0 {
		y += w.px(6)
		start := 0
		if m.Selected >= uiMaxRows {
			start = m.Selected - uiMaxRows + 1
		}
		for i := start; i < len(m.List) && i < start+uiMaxRows; i++ {
			r := f3Rect{left, y, right, y + w.px(uiRowH)}
			if i == m.Selected {
				fill(hdc, r, th.sel)
				fill(hdc, f3Rect{r.Left, r.Top + w.px(6), r.Left + w.px(3), r.Bottom - w.px(6)}, th.accent)
			}
			tr := r
			tr.Left += w.px(12)
			drawText(hdc, m.List[i], tr, w.font, th.fg, f3DtLeft)
			w.rows = append(w.rows, r)
			y += w.px(uiRowH)
		}
	}
	if m.Progress >= 0 {
		y += w.px(12)
		track := f3Rect{left, y, right, y + w.px(uiProgressH)}
		fill(hdc, track, th.border)
		p := min(max(m.Progress, 0), 1)
		fill(hdc, f3Rect{left, y, left + int32(float64(right-left)*p), y + w.px(uiProgressH)}, th.accent)
		y += w.px(uiProgressH)
	}
	w.buttons = w.buttons[:0]
	if len(m.Buttons) > 0 {
		y = rc.Bottom - pad - w.px(uiBtnH)
		x := right
		rects := make([]f3Rect, len(m.Buttons))
		for i := len(m.Buttons) - 1; i >= 0; i-- {
			r := f3Rect{x - w.px(uiBtnW), y, x, y + w.px(uiBtnH)}
			rects[i] = r
			x = r.Left - w.px(uiBtnGap)
		}
		for i, b := range m.Buttons {
			r := rects[i]
			bg, fg := th.btn, th.btnFg
			if b.Primary {
				bg, fg = th.accent, th.accentFg
			}
			fill(hdc, r, bg)
			if !b.Primary {
				outline(hdc, r, 1, th.border)
			}
			if i == w.hover && !b.Primary {
				outline(hdc, r, 1, th.muted)
			}
			if i == w.focus {
				in := f3Rect{r.Left - w.px(3), r.Top - w.px(3), r.Right + w.px(3), r.Bottom + w.px(3)}
				outline(hdc, in, w.px(2), th.fg)
			}
			drawText(hdc, b.Label, r, w.font, fg, f3DtCenter)
		}
		w.buttons = rects
	}
}

func hit(rs []f3Rect, x, y int32) int {
	for i, r := range rs {
		if x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom {
			return i
		}
	}
	return -1
}

// finish closes the window once with button as its result; the
// deactivation that destroying causes does not overwrite it.
func (w *uiWindow) finish(button int) {
	if w.closed {
		return
	}
	w.closed = true
	w.mu.Lock()
	w.result = UIResult{Button: button, Selected: w.model.Selected}
	w.mu.Unlock()
	procDestroyWindow.Call(w.hwnd)
}

func (w *uiWindow) defaultButton() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range w.model.Buttons {
		if b.Primary {
			return b.ID
		}
	}
	return 0
}

func (w *uiWindow) moveSelection(d int) {
	w.mu.Lock()
	n := len(w.model.List)
	if n > 0 {
		w.model.Selected = min(max(w.model.Selected+d, 0), n-1)
	}
	w.mu.Unlock()
	f3InvalidateRect.Call(w.hwnd, 0, 0)
}

func f3WndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	v, ok := f3Windows.Load(hwnd)
	if !ok {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return r
	}
	w := v.(*uiWindow)
	switch uint32(msg) {
	case f3WmEraseBkgnd:
		return 1
	case f3WmPaint:
		var ps f3PaintStruct
		hdc, _, _ := f3BeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			var rc f3Rect
			f3GetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			// Painted off screen first, so redraws do not flicker.
			mem, _, _ := f3CreateCompatibleDC.Call(hdc)
			bmp, _, _ := f3CreateCompatibleBmp.Call(hdc, uintptr(rc.Right), uintptr(rc.Bottom))
			if mem != 0 && bmp != 0 {
				old, _, _ := f3SelectObject.Call(mem, bmp)
				w.paint(mem, rc)
				f3BitBlt.Call(hdc, 0, 0, uintptr(rc.Right), uintptr(rc.Bottom), mem, 0, 0, f3Srccopy)
				f3SelectObject.Call(mem, old)
			} else {
				w.paint(hdc, rc)
			}
			if bmp != 0 {
				f3DeleteObject.Call(bmp)
			}
			if mem != 0 {
				f3DeleteDC.Call(mem)
			}
			f3EndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		}
		return 0
	case f3WmActivate:
		if wParam&0xFFFF == f3WaInactive {
			if w.kind == UIFlyout && w.activated {
				w.finish(0)
			}
		} else {
			w.activated = true
		}
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return r
	case f3WmTimer:
		if w.kind == UIFlyout {
			// Activation is not guaranteed for an elevated window; a
			// change of the foreground window to someone else closes it.
			fg, _, _ := f3GetForegroundWindow.Call()
			if fg != hwnd && fg != w.initialFG && fg != 0 {
				w.finish(0)
			}
		}
		return 0
	case f3WmMouseMove:
		x, y := int32(int16(lParam&0xFFFF)), int32(int16(lParam>>16&0xFFFF))
		if h := hit(w.buttons, x, y); h != w.hover {
			w.hover = h
			f3InvalidateRect.Call(hwnd, 0, 0)
		}
		return 0
	case f3WmLButtonUp:
		x, y := int32(int16(lParam&0xFFFF)), int32(int16(lParam>>16&0xFFFF))
		if i := hit(w.buttons, x, y); i >= 0 {
			w.mu.Lock()
			id := w.model.Buttons[i].ID
			w.mu.Unlock()
			w.finish(id)
			return 0
		}
		if i := hit(w.rows, x, y); i >= 0 {
			w.mu.Lock()
			start := 0
			if w.model.Selected >= uiMaxRows {
				start = w.model.Selected - uiMaxRows + 1
			}
			w.model.Selected = start + i
			w.mu.Unlock()
			f3InvalidateRect.Call(hwnd, 0, 0)
		}
		return 0
	case f3WmKeyDown:
		switch wParam {
		case f3VkEscape:
			w.finish(0)
		case f3VkReturn, f3VkSpace:
			w.mu.Lock()
			id := 0
			if w.focus >= 0 && w.focus < len(w.model.Buttons) {
				id = w.model.Buttons[w.focus].ID
			}
			w.mu.Unlock()
			if id == 0 {
				id = w.defaultButton()
			}
			w.finish(id)
		case f3VkTab:
			w.mu.Lock()
			n := len(w.model.Buttons)
			w.mu.Unlock()
			if n > 0 {
				w.focus = (w.focus + 1) % n
				f3InvalidateRect.Call(hwnd, 0, 0)
			}
		case f3VkUp:
			w.moveSelection(-1)
		case f3VkDown:
			w.moveSelection(1)
		}
		return 0
	case f3WmModel:
		w.mu.Lock()
		m := w.model
		w.mu.Unlock()
		cw, ch := w.size(m)
		var rc f3Rect
		f3GetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		if rc.Bottom != ch {
			// Only the flyout grows; it keeps its bottom edge.
			w.place(cw, ch)
		}
		setTitle(hwnd, m.Title)
		f3InvalidateRect.Call(hwnd, 0, 0)
		return 0
	case wmClose:
		w.finish(0)
		return 0
	case wmDestroy:
		f3KillTimer.Call(hwnd, f3TimerFocus)
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func setTitle(hwnd uintptr, s string) {
	if p, err := windows.UTF16PtrFromString(s); err == nil {
		f3SetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(p)))
	}
}

// workArea returns the work area of the monitor under the cursor.
func workArea() (f3Rect, point) {
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	mon, _, _ := f3MonitorFromPoint.Call(uintptr(uint32(pt.X))|uintptr(uint32(pt.Y))<<32, f3MonitorNear)
	mi := f3MonitorInfo{}
	mi.CbSize = uint32(unsafe.Sizeof(mi))
	if mon == 0 {
		return f3Rect{0, 0, 1024, 768}, pt
	}
	if r, _, _ := f3GetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return f3Rect{0, 0, 1024, 768}, pt
	}
	return mi.RcWork, pt
}

// place sizes and moves the window for a client area of cw x ch.
func (w *uiWindow) place(cw, ch int32) {
	work, pt := workArea()
	ww, wh := cw, ch
	if w.kind == UIDialog {
		// Caption and frame.
		ww += w.px(16)
		wh += w.px(39)
	}
	var x, y int32
	if w.kind == UIFlyout {
		// Next to the notification area: the corner of the work area
		// nearest to the cursor.
		margin := w.px(12)
		x = min(max(pt.X-ww/2, work.Left+margin), work.Right-ww-margin)
		y = work.Bottom - wh - margin
		if pt.Y < (work.Top+work.Bottom)/2 {
			y = work.Top + margin // taskbar at the top
		}
	} else {
		x = work.Left + (work.Right-work.Left-ww)/2
		y = work.Top + (work.Bottom-work.Top-wh)/2
	}
	f3SetWindowPos.Call(w.hwnd, f3HwndTopmost, uintptr(x), uintptr(y), uintptr(ww), uintptr(wh), f3SwpShowWindow)
}

func (w *uiWindow) setModel(m UIModel) {
	w.mu.Lock()
	if m.Selected >= len(m.List) {
		m.Selected = len(m.List) - 1
	}
	w.model = m
	w.mu.Unlock()
	procPostMessageW.Call(w.hwnd, f3WmModel, 0, 0)
}

// ShowUI opens a window for m and blocks until it closes or ctx ends.
// update, when set, is called every two seconds and returns a new model
// (ok false keeps the shown one).
func ShowUI(ctx context.Context, kind UIKind, m UIModel, update func() (UIModel, bool)) (UIResult, error) {
	if IsServerCore() {
		return UIResult{}, ErrNoDesktopShell
	}
	type out struct {
		res UIResult
		err error
	}
	done := make(chan out, 1)
	var hwndReady atomic.Uintptr
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		res, err := runUI(kind, m, &hwndReady)
		done <- out{res, err}
	}()
	stop := make(chan struct{})
	defer close(stop)
	if update != nil {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					if h := hwndReady.Load(); h != 0 {
						if nm, ok := update(); ok {
							if v, ok := f3Windows.Load(h); ok {
								v.(*uiWindow).setModel(nm)
							}
						}
					}
				}
			}
		}()
	}
	select {
	case r := <-done:
		return r.res, r.err
	case <-ctx.Done():
		if h := hwndReady.Load(); h != 0 {
			procPostMessageW.Call(h, wmClose, 0, 0)
		}
		r := <-done
		return r.res, r.err
	}
}

func runUI(kind UIKind, m UIModel, ready *atomic.Uintptr) (UIResult, error) {
	var hinst windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &hinst); err != nil {
		return UIResult{}, err
	}
	if err := registerF3Class(hinst); err != nil {
		return UIResult{}, err
	}
	w := &uiWindow{kind: kind, theme: themeFor(kind), scale: 1, model: m, focus: -1, hover: -1}
	if w.model.Selected >= len(w.model.List) {
		w.model.Selected = len(w.model.List) - 1
	}
	for i, b := range m.Buttons {
		if b.Primary {
			w.focus = i
		}
	}
	if f3GetDpiForSystem.Find() == nil {
		if dpi, _, _ := f3GetDpiForSystem.Call(); dpi >= 96 {
			w.scale = float64(dpi) / 96
		}
	}
	w.createFonts()
	defer w.deleteFonts()
	style := uintptr(f3WsPopup | f3WsBorder)
	ex := uintptr(f3WsExTopmost | f3WsExToolWindow)
	if kind == UIDialog {
		style = f3WsPopup | f3WsCaption | f3WsSysMenu
		ex = f3WsExTopmost | f3WsExDlgFrame
	}
	title, _ := windows.UTF16PtrFromString(m.Title)
	w.initialFG, _, _ = f3GetForegroundWindow.Call()
	hwnd, _, callErr := procCreateWindowExW.Call(ex, uintptr(unsafe.Pointer(f3Class)), uintptr(unsafe.Pointer(title)), style,
		0, 0, 100, 100, 0, 0, uintptr(hinst), 0)
	if hwnd == 0 {
		return UIResult{}, fmt.Errorf("pencere oluşturulamadı: %w", callErr)
	}
	w.hwnd = hwnd
	f3Windows.Store(hwnd, w)
	defer f3Windows.Delete(hwnd)
	dark := int32(0)
	if w.theme.dark {
		dark = 1
	}
	_ = windows.DwmSetWindowAttribute(windows.HWND(hwnd), dwmwaDarkMode, unsafe.Pointer(&dark), 4)
	if kind == UIFlyout {
		corner := int32(dwmwcpRound)
		_ = windows.DwmSetWindowAttribute(windows.HWND(hwnd), dwmwaCornerPref, unsafe.Pointer(&corner), 4)
	}
	cw, ch := w.size(w.model)
	w.place(cw, ch)
	f3ShowWindow.Call(hwnd, f3SwShow)
	f3BringWindowToTop.Call(hwnd)
	procSetForegroundWindow.Call(hwnd)
	f3SetFocus.Call(hwnd)
	if kind == UIFlyout {
		f3SetTimer.Call(hwnd, f3TimerFocus, 300, 0)
	}
	ready.Store(hwnd)
	defer ready.Store(0)
	var msg winMsg
	for {
		r, _, callErr := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		switch int32(r) {
		case -1:
			return UIResult{}, fmt.Errorf("mesaj döngüsü hatası: %w", callErr)
		case 0:
			w.mu.Lock()
			res := w.result
			w.mu.Unlock()
			return res, nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}
