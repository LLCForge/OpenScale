//go:build windows

package service

import (
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The audit finding: on Windows the start-up check never looked at the
// data folder, so an open ACL stayed unnoticed.
func TestSelfCheckReportsOpenWindowsDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "OpenScale")
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreateDirectory(p, &sa); err != nil {
		t.Fatal(err)
	}
	old := serviceDataDir
	serviceDataDir = func() string { return dir }
	t.Cleanup(func() { serviceDataDir = old })

	c := &checker{now: time.Now()}
	c.checkDataDirPermissions(dir)
	if !hasDataDirWarning(c.out) {
		t.Fatalf("herkese açık veri klasörü bildirilmedi: %+v", c.out)
	}

	// Another folder (a foreground state directory) is not judged.
	serviceDataDir = func() string { return filepath.Join(dir, "baska") }
	c = &checker{now: time.Now()}
	c.checkDataDirPermissions(dir)
	if hasDataDirWarning(c.out) {
		t.Fatalf("servis klasörü olmayan yer bildirildi: %+v", c.out)
	}
}

func hasDataDirWarning(out []Finding) bool {
	for _, f := range out {
		if f.Level == FindingWarn && f.Area == "veri klasörü" {
			return true
		}
	}
	return false
}
