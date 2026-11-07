//go:build windows

package webview

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Title bar theming (Windows 10 20H1+ dark mode; Windows 11 caption and
// text colours). Unsupported attributes fail silently on older systems.

var (
	dwmapi                    = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")

	// ICoreWebView2WebMessageReceivedEventHandler
	iidWebMessageReceived = mustGUID("{57213F19-00E6-49FA-8E07-898EA01ECBD2}")
)

const (
	dwmwaUseImmersiveDarkMode = 20
	dwmwaCaptionColor         = 35
	dwmwaTextColor            = 36

	// ICoreWebView2::add_WebMessageReceived
	idxWVAddWebMessageReceived = 34
	// ICoreWebView2WebMessageReceivedEventArgs
	idxMsgArgsGetSource      = 3
	idxMsgArgsTryGetAsString = 5
)

func colorRef(r, g, b uint8) uint32 { return uint32(r) | uint32(g)<<8 | uint32(b)<<16 }

func dwmSet(hwnd uintptr, attr uint32, v uint32) {
	if procDwmSetWindowAttribute.Find() != nil {
		return
	}
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, uintptr(attr), uintptr(unsafe.Pointer(&v)), 4)
}

// applyTitleBar paints the caption to match the panel.
func (w *win) applyTitleBar(m themeMessage) {
	if w.hwnd == 0 {
		return
	}
	dark := uint32(0)
	if m.dark {
		dark = 1
	}
	dwmSet(w.hwnd, dwmwaUseImmersiveDarkMode, dark)
	dwmSet(w.hwnd, dwmwaCaptionColor, colorRef(m.r, m.g, m.b))
	tr, tg, tb := m.textOn()
	dwmSet(w.hwnd, dwmwaTextColor, colorRef(tr, tg, tb))
}

// initialTitleBar starts dark: the panel's default theme is dark
// (next-themes defaultTheme), and the panel reports its real theme as soon
// as it loads.
func (w *win) initialTitleBar() {
	w.applyTitleBar(themeMessage{dark: true, r: 0x18, g: 0x18, b: 0x1b})
}

// onWebMessage accepts only a theme message from a top-level document in
// the allowed origin; everything else is dropped.
func (w *win) onWebMessage(_, args uintptr) uintptr {
	a := comPtr(args)
	src, err := a.getString(idxMsgArgsGetSource)
	if err != nil || w.cfg.origin.check(src) != actionAllow || src == "about:blank" {
		return sOK
	}
	s, err := a.getString(idxMsgArgsTryGetAsString)
	if err != nil {
		return sOK
	}
	if m, ok := parseThemeMessage(s); ok {
		w.applyTitleBar(m)
	}
	return sOK
}
