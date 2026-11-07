//go:build windows

package osnet

import (
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// toolDirs is System32 (and its PowerShell folder) from the system, not
// from %PATH% or %SystemRoot%.
func toolDirs() []string {
	sys, err := windows.GetSystemDirectory()
	if err != nil || sys == "" {
		return nil
	}
	return []string{sys, filepath.Join(sys, "WindowsPowerShell", "v1.0")}
}

func toolFileNames(name string) []string {
	if filepath.Ext(name) != "" {
		return []string{name}
	}
	return []string{name + ".exe"}
}

func executableMode(fs.FileMode) bool { return true }

// toolEnv keeps the environment on Windows: the service's environment
// comes from the Service Control Manager, and netsh needs SystemRoot and
// the profile folders. Only the program path is fixed.
func toolEnv() []string { return os.Environ() }
