//go:build windows

package osnet

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DetectWSL reports whether WSL is installed and, when home is a user's
// profile directory, that user's .wslconfig networking mode. The service
// runs as LocalSystem and passes "": then only the installation is known.
func DetectWSL(home string) WSLInfo {
	var w WSLInfo
	if sys, err := windows.GetSystemDirectory(); err == nil {
		if st, err := os.Stat(filepath.Join(sys, "wsl.exe")); err == nil && st.Mode().IsRegular() {
			w.Installed = true
		}
	}
	if w.Installed && home != "" {
		if f, err := os.Open(filepath.Join(home, ".wslconfig")); err == nil {
			data, _ := io.ReadAll(io.LimitReader(f, maxWSLConfigSize))
			f.Close()
			w.ConfigRead = true
			w.Mode, w.DNSTunneling = ParseWSLConfig(data)
		} else {
			w.Mode = WSLModeNAT
		}
	}
	w.Notes = WSLNotes(w)
	return w
}
