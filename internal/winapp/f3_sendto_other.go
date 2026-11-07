//go:build !windows

package winapp

import "errors"

// errSendToWindowsOnly: Finder and file managers use their own entries
// (deploy/sendto/), which run "openscale send" instead.
var errSendToWindowsOnly = errors.New("\"send-to\" yalnızca Windows'ta; macOS ve Linux için deploy/sendto altındaki örneklere bakın")

// SendToTray exists only on Windows.
func SendToTray([]string) error { return errSendToWindowsOnly }

// DetachOwnConsole does nothing outside Windows.
func DetachOwnConsole() bool { return false }

// ShowMessage does nothing outside Windows; callers print instead.
func ShowMessage(string, bool) {}
