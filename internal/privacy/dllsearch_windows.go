//go:build windows

package privacy

import (
	"golang.org/x/sys/windows"
)

// HardenDLLSearch limits where Windows looks for a DLL loaded by name to
// System32 for the rest of the process (#518): a DLL planted next to
// openscale.exe, in the working directory or on PATH is never loaded in
// place of a system DLL, so a writable program folder cannot be turned
// into code running as SYSTEM. wintun.dll, the only DLL that is not a
// system DLL, is verified and loaded by its full path
// (internal/wintunembed), which this setting does not affect. It changes
// only this process, never a system setting, and must run before anything
// loads a DLL by name.
func HardenDLLSearch() (measures, warnings []string) {
	if err := windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		warnings = append(warnings, "SetDefaultDllDirectories uygulanamadı: "+err.Error())
	} else {
		measures = append(measures, "SetDefaultDllDirectories(SYSTEM32): DLL'ler adla yalnızca System32'den yüklenir")
	}
	// The working directory leaves the legacy search order too.
	if err := windows.SetDllDirectory(""); err != nil {
		warnings = append(warnings, "SetDllDirectory(\"\") uygulanamadı: "+err.Error())
	} else {
		measures = append(measures, "SetDllDirectory(\"\"): çalışma klasörü DLL aramasından çıkarıldı")
	}
	return measures, warnings
}
