//go:build windows

package cli

import "golang.org/x/sys/windows"

// enableANSI turns on escape sequence processing of the Windows console
// and returns the function that restores the previous mode.
func enableANSI(fd int) func() {
	h := windows.Handle(fd)
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		return func() {}
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }
}
