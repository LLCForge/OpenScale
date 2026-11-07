//go:build windows

package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// lockFile opens path the way a virus scanner does: it shares reading
// only, so the file can be neither renamed nor removed until it is closed.
func lockFile(t *testing.T, path string) (release func()) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	release = func() {
		if !closed {
			closed = true
			_ = windows.CloseHandle(h)
		}
	}
	t.Cleanup(release)
	return release
}

func swapFixture(t *testing.T) (exe, staged string) {
	t.Helper()
	dir := t.TempDir()
	exe, staged = filepath.Join(dir, "openscale.exe"), filepath.Join(dir, "yeni.new.exe")
	if err := os.WriteFile(exe, []byte("eski"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("yeni"), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe, staged
}

func TestSwapWaitsForShortLivedLock(t *testing.T) {
	exe, staged := swapFixture(t)
	release := lockFile(t, staged)
	timer := time.AfterFunc(300*time.Millisecond, release)
	defer timer.Stop()
	if err := swap(exe, staged); err != nil {
		t.Fatalf("swap gave up on a lock that clears in moments: %v", err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "yeni" {
		t.Fatalf("program = %q, want the new one", got)
	}
}

func TestSwapKeepsOldProgramWhenLockStays(t *testing.T) {
	exe, staged := swapFixture(t)
	lockFile(t, staged)
	start := time.Now()
	if err := swap(exe, staged); err == nil {
		t.Fatal("swap succeeded over a held lock")
	}
	if took := time.Since(start); took > busyWait+5*time.Second {
		t.Fatalf("swap waited %v, the limit is %v", took, busyWait)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "eski" {
		t.Fatalf("program = %q, the old one must stay in place", got)
	}
}

func TestRemoveStagedWaitsForShortLivedLock(t *testing.T) {
	_, staged := swapFixture(t)
	release := lockFile(t, staged)
	timer := time.AfterFunc(300*time.Millisecond, release)
	defer timer.Stop()
	if err := removeBusy(staged); err != nil {
		t.Fatalf("removeBusy gave up: %v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged file still there: %v", err)
	}
}
