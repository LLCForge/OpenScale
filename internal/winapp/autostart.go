package winapp

import (
	"errors"
	"path/filepath"
	"strings"
)

// Start at sign-in (ADR-0194): the tray starts when a user signs in, from
// a value under ...\CurrentVersion\Run. The installer writes the value for
// every user (HKLM); "openscale autostart on|off" changes the user's own
// value (HKCU). The value runs "openscale.exe autostart run", which reads
// the user's "start at sign-in" setting before it starts anything.

// RunValueName is the value name under the Run keys.
const RunValueName = "OpenScale"

// RunKeyPath is the Run key below HKLM or HKCU.
const RunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// ErrBadRunCommand: the program path cannot be written as a Run command.
var ErrBadRunCommand = errors.New("başlangıç komutu için program yolu geçersiz")

// RunCommand quotes the program and appends the arguments. Arguments must
// be plain words (no quotes, spaces or control characters).
func RunCommand(exe string, args ...string) (string, error) {
	if !filepath.IsAbs(exe) || strings.ContainsAny(exe, "\"\x00\r\n%") || len(exe) > 1024 {
		return "", ErrBadRunCommand
	}
	parts := []string{`"` + exe + `"`}
	for _, a := range args {
		if a == "" || strings.ContainsFunc(a, func(r rune) bool { return r <= ' ' || r == '"' || r == 0x7f }) {
			return "", ErrBadRunCommand
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " "), nil
}

// RunCommandProgram returns the quoted program of a Run command, or "".
func RunCommandProgram(cmd string) string {
	if !strings.HasPrefix(cmd, `"`) {
		return ""
	}
	end := strings.IndexByte(cmd[1:], '"')
	if end < 0 {
		return ""
	}
	return cmd[1 : end+1]
}
