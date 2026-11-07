//go:build windows

package privacy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A file named like a DLL in the working directory must not be found by a
// load by name once the search is limited to System32: the error is "not
// found" (126), not "bad image" (193) which would mean Windows opened it.
func TestHardenDLLSearchSkipsWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	const name = "openscale-planted-p11.dll"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not a dll"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	measures, warnings := HardenDLLSearch()
	if len(warnings) != 0 || len(measures) != 2 {
		t.Fatalf("measures %v warnings %v", measures, warnings)
	}
	h, err := windows.LoadLibrary(name)
	if err == nil {
		_ = windows.FreeLibrary(h)
		t.Fatal("planted DLL was loaded")
	}
	if !errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		t.Fatalf("load error %v, want ERROR_MOD_NOT_FOUND", err)
	}
	// System DLLs still load by name.
	k, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		t.Fatalf("kernel32.dll: %v", err)
	}
	_ = windows.FreeLibrary(k)
}
