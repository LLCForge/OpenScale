//go:build windows

package service

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/dohcheck"
)

// consoleUserDirs returns the folders of the user at the console; the
// service's own profile (LocalSystem) has no browsers. Only DNS settings
// are read, and nothing leaves this computer.
func consoleUserDirs() dohcheck.Dirs {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == noConsoleSession {
		return dohcheck.DefaultDirs()
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return dohcheck.DefaultDirs()
	}
	defer tok.Close()
	home, err := tok.GetUserProfileDirectory()
	if err != nil || home == "" {
		return dohcheck.DefaultDirs()
	}
	return dohcheck.Dirs{Home: home, AppData: filepath.Join(home, "AppData", "Roaming"), LocalAppData: filepath.Join(home, "AppData", "Local"), GOOS: "windows"}
}
