//go:build windows

package service

import "golang.org/x/sys/windows"

// canDrawFrame reports whether this process runs in an interactive
// session. The Windows service runs in session 0, whose windows the user
// never sees; there the support notice is the notification and the panel
// bar instead of the #671 frame (ADR-0232).
func canDrawFrame() bool {
	var id uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id); err != nil {
		return false
	}
	return id != 0
}
