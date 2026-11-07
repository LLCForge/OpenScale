//go:build windows

package netdrive

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The attributes Explorer needs are set and removed again (in a temporary
// folder; the user's Network Shortcuts folder is never touched).
func TestPlacesWindowsAttributes(t *testing.T) {
	p, _ := testPlaces(t)
	p.SetAttrs, p.ClearAttrs, p.Changed = nil, nil, func(string) {}
	if res, err := p.Sync([]PlaceDevice{nas("Arsiv")}); err != nil || len(res.Added) != 1 {
		t.Fatal(res, err)
	}
	dir := filepath.Join(p.Dir, "Arsiv (nas)")
	attrs := func(path string) uint32 {
		u, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		a, err := windows.GetFileAttributes(u)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if attrs(dir)&windows.FILE_ATTRIBUTE_READONLY == 0 {
		t.Fatal("folder is not read-only")
	}
	if a := attrs(filepath.Join(dir, "desktop.ini")); a&windows.FILE_ATTRIBUTE_HIDDEN == 0 || a&windows.FILE_ATTRIBUTE_SYSTEM == 0 {
		t.Fatalf("desktop.ini attributes = %#x", a)
	}
	res, err := p.RemoveAll()
	if err != nil || len(res.Removed) != 1 || len(res.Errors) != 0 {
		t.Fatal(res, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("folder left: %v", err)
	}
}
