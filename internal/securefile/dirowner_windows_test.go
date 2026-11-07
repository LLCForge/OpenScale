//go:build windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A key is never written into a directory another account owns, whichever
// way it is written.
func TestPrivateWritesRefuseForeignDirectory(t *testing.T) {
	old := dirOwnerPolicy
	t.Cleanup(func() { dirOwnerPolicy = old })
	dirOwnerPolicy = func() func(*windows.SID) bool {
		return func(*windows.SID) bool { return false }
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "device.key")
	if err := WriteNew(key, []byte("gizli")); !errors.Is(err, ErrForeignDirectory) {
		t.Fatalf("WriteNew: %v", err)
	}
	if err := Replace(key, []byte("gizli")); !errors.Is(err, ErrForeignDirectory) {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dosya yazıldı: %v", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("geçici dosya kaldı: %v", left)
	}
}

func TestPrivateWritesAcceptTrustedOwner(t *testing.T) {
	old := dirOwnerPolicy
	t.Cleanup(func() { dirOwnerPolicy = old })
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dirOwnerPolicy = func() func(*windows.SID) bool {
		return func(s *windows.SID) bool {
			return s.Equals(u.User.Sid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid)
		}
	}
	if err := WriteNew(filepath.Join(t.TempDir(), "device.key"), []byte("gizli")); err != nil {
		t.Fatal(err)
	}
}

// A standard process has no check: it gains nothing from one.
func TestPolicyOnlyForPrivilegedProcess(t *testing.T) {
	tok := windows.GetCurrentProcessToken()
	if tok.IsElevated() {
		t.Skip("yükseltilmiş süreçte denetim açıktır")
	}
	if privilegedOwnerPolicy() != nil {
		t.Fatal("standart süreçte denetim açık")
	}
}
