//go:build windows

package webview

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckDirOwner only reads owners: the package folder belongs to the
// user running the tests, the Windows folder to TrustedInstaller.
func TestCheckDirOwner(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDirOwner(wd); err != nil {
		t.Errorf("checkDirOwner(%q) = %v, kabul bekleniyordu", wd, err)
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		t.Skip("SystemRoot yok")
	}
	if err := checkDirOwner(filepath.Clean(sysRoot)); err == nil {
		t.Errorf("checkDirOwner(%q) kabul etti; sahibi TrustedInstaller olan klasör reddedilmeliydi", sysRoot)
	}
	if err := checkDirOwner(filepath.Join(wd, "yok-boyle-bir-klasor")); err == nil {
		t.Error("olmayan klasör kabul edildi")
	}
}
