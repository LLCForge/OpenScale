//go:build windows

package rdesk

import "golang.org/x/sys/windows"

var procGetUserDefaultUILanguage = modKernel32.NewProc("GetUserDefaultUILanguage")

// uiTurkish reports whether the Windows display language is Turkish; the
// frame of a session shown on this screen follows it.
func uiTurkish() bool {
	if procGetUserDefaultUILanguage.Find() != nil {
		return true
	}
	r, _, _ := procGetUserDefaultUILanguage.Call()
	return r&0x3ff == 0x1f // LANG_TURKISH
}

// SetText changes the label of a shown frame (#853). Frames leave the
// server's list before they close, so the window still exists here.
func (f *winFrame) SetText(text string) {
	if f.hwnd == 0 {
		return
	}
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return
	}
	frameTexts.Store(f.hwnd, u)
	procInvalidateRect.Call(f.hwnd, 0, 1)
}
