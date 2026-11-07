//go:build windows

package winapp

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func setRawDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// The raw call is what a holder of WRITE_DAC can use; unlike
	// SetNamedSecurityInfo it keeps the "inherited" flag as written.
	setFileSecurity := windows.NewLazySystemDLL("advapi32.dll").NewProc("SetFileSecurityW")
	if r, _, callErr := setFileSecurity.Call(uintptr(unsafe.Pointer(p)), uintptr(windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd))); r == 0 {
		t.Fatalf("SetFileSecurity: %v", callErr)
	}
}

func hasGrantTo(t *testing.T, path string, who *windows.SID) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		return true
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if aceSID(ace).Equals(who) {
			return true
		}
	}
	return false
}

// A grant carrying the "inherited" flag on a DACL that does not inherit
// survives the root's propagation, so the flag proves nothing.
func TestAuditDataTreeRemovesForgedInheritedGrant(t *testing.T) {
	root := filepath.Join(t.TempDir(), "OpenScale")
	sub := filepath.Join(root, "device")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	me := selfSID(t)
	setRawDACL(t, sub, "D:P(A;OICIID;FA;;;WD)(A;OICI;FA;;;"+me.String()+")")
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if !hasGrantTo(t, sub, everyone) {
		t.Fatal("hazırlık: izin yazılamadı")
	}
	if err := auditDataTree(root, func(s *windows.SID) bool { return s != nil && s.Equals(me) }); err != nil {
		t.Fatalf("denetim: %v", err)
	}
	if hasGrantTo(t, sub, everyone) {
		t.Fatal("devralınmış gibi işaretlenen izin kaldırılmadı")
	}
}

func TestDataDirProblem(t *testing.T) {
	root := filepath.Join(t.TempDir(), "OpenScale")
	sub := filepath.Join(root, "device")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	me := selfSID(t).String()
	locked := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + ")"
	setRawDACL(t, root, locked)
	setRawDACL(t, sub, locked)
	if err := DataDirProblem(root); err != nil {
		t.Fatalf("kilitli klasör bildirildi: %v", err)
	}

	setRawDACL(t, sub, "D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;"+me+")")
	if err := DataDirProblem(root); err == nil {
		t.Fatal("herkese açık alt klasör bildirilmedi")
	}
	if !hasGrantTo(t, sub, mustWorld(t)) {
		t.Fatal("yalnızca okuyan denetim izni değiştirdi")
	}

	setRawDACL(t, sub, locked)
	setRawDACL(t, root, "D:(A;OICI;FA;;;AU)(A;OICI;FA;;;"+me+")")
	if err := DataDirProblem(root); err == nil {
		t.Fatal("herkese açık kök bildirilmedi")
	}
}

func mustWorld(t *testing.T) *windows.SID {
	t.Helper()
	s, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
