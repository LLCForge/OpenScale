//go:build windows

package winapp

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readShortcut loads a saved shortcut back through the shell, so the test
// proves Windows understands the file rather than that bytes were written.
func readShortcut(t *testing.T, path string) (target, args string) {
	t.Helper()
	err := withShellLink(func(link, file *comObject) error {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		if err := file.call(idxPFLoad, uintptr(unsafe.Pointer(p)), 0); err != nil {
			return err
		}
		tb := make([]uint16, 1024)
		if err := link.call(idxSLGetPath, uintptr(unsafe.Pointer(&tb[0])), uintptr(len(tb)), 0, 0); err != nil {
			return err
		}
		ab := make([]uint16, 1024)
		if err := link.call(idxSLGetArguments, uintptr(unsafe.Pointer(&ab[0])), uintptr(len(ab))); err != nil {
			return err
		}
		target, args = windows.UTF16ToString(tb), windows.UTF16ToString(ab)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return target, args
}

func TestWriteShortcutRoundTrip(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, shortcutFileName)
	if err := writeShortcut(path, exe); err != nil {
		t.Fatal(err)
	}
	// A second install replaces the file rather than failing.
	if err := writeShortcut(path, exe); err != nil {
		t.Fatal(err)
	}
	target, args := readShortcut(t, path)
	if !filepath.IsAbs(target) || filepath.Base(target) != filepath.Base(exe) {
		t.Fatalf("target = %q, want %q", target, exe)
	}
	if args != shortcutArg {
		t.Fatalf("args = %q, want %q", args, shortcutArg)
	}
}

func TestShortcutsGoToFoldersForAllUsers(t *testing.T) {
	sm, err := startMenuShortcutPath()
	if err != nil {
		t.Fatal(err)
	}
	dt, err := desktopShortcutPath()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.KnownFolderPath(windows.FOLDERID_Profile, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sm, dt} {
		if rel, err := filepath.Rel(user, p); err == nil && filepath.IsLocal(rel) {
			t.Fatalf("%s is in the user's profile, which the user can change", p)
		}
	}
}
