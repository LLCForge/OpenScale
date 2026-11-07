//go:build windows

package winapp

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	installHelperEnv = "OPENSCALE_F4_INSTALL_HELPER"
	installDstEnv    = "OPENSCALE_F4_INSTALL_DST"
	swapBytes        = "saldirganin programi"
)

// TestHelperInstallAfterSwap plays the elevated copy. In the "swap" mode a
// lower-trust process has renamed the program it was started from and put
// another file at the same path between the UAC consent and the copy.
func TestHelperInstallAfterSwap(t *testing.T) {
	mode := os.Getenv(installHelperEnv)
	if mode == "" {
		t.Skip("yardımcı süreç")
	}
	dst := os.Getenv(installDstEnv)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "swap" {
		if err := os.Rename(self, self+".orig"); err != nil {
			t.Fatalf("çalışan program yeniden adlandırılamadı: %v", err)
		}
		if err := os.WriteFile(self, []byte(swapBytes), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := installBinary(self, dst); err != nil {
		if mode == "plain" {
			t.Fatalf("installBinary: %v", err)
		}
		t.Logf("reddedildi: %v", err)
	}
}

func runInstallHelper(t *testing.T, mode string) (dst string, exe string) {
	t.Helper()
	dir := t.TempDir()
	exe = filepath.Join(dir, "kaynak.exe")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	dst = filepath.Join(dir, "kurulu", installedExeName)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHelperInstallAfterSwap$", "-test.v")
	cmd.Env = append(os.Environ(), installHelperEnv+"="+mode, installDstEnv+"="+dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("yardımcı süreç: %v\n%s", err, out)
	}
	return dst, exe
}

// The audit finding: what lands in Program Files must be the running
// image, never the file a lower-trust process put at the path afterwards.
func TestInstallBinaryRefusesSwappedSource(t *testing.T) {
	dst, _ := runInstallHelper(t, "swap")
	data, err := os.ReadFile(dst)
	if err == nil && bytes.Contains(data, []byte(swapBytes)) {
		t.Fatal("yerine konan dosya kuruldu: LocalSystem servisi bu dosyadan çalışırdı")
	}
	if err == nil {
		t.Fatalf("beklenmeyen kurulum: %d bayt", len(data))
	}
}

func TestInstallBinaryCopiesRunningImage(t *testing.T) {
	dst, exe := runInstallHelper(t, "plain")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(want) {
		t.Fatal("kopya kaynak programla aynı değil")
	}
	left, err := filepath.Glob(filepath.Join(filepath.Dir(dst), ".openscale-*.tmp"))
	if err != nil || len(left) != 0 {
		t.Fatalf("geçici dosya kaldı: %v %v", left, err)
	}
}

// While the source is held open nothing can rename, delete or rewrite it.
func TestLockedSourceBlocksRenameAndWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kaynak.bin")
	if err := os.WriteFile(p, []byte("program"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openLockedSource(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(p, p+".baska"); err == nil {
		t.Fatal("kilitli kaynak yeniden adlandırıldı")
	}
	if err := os.WriteFile(p, []byte("baska"), 0o644); err == nil {
		t.Fatal("kilitli kaynak değiştirildi")
	}
	if err := os.Remove(p); err == nil {
		t.Fatal("kilitli kaynak silindi")
	}
}

func TestSourceMustBeRunningImage(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	own, err := openLockedSource(self)
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if err := checkIsRunningImage(own); err != nil {
		t.Fatalf("kendi görüntüsü: %v", err)
	}
	other := filepath.Join(t.TempDir(), "baska.exe")
	if err := os.WriteFile(other, []byte("baska"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openLockedSource(other)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkIsRunningImage(f); err == nil {
		t.Fatal("başka bir dosya çalışan görüntü sayıldı")
	}
}

// --- data folder ---

func selfSID(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

// daclOf reports whether the DACL is protected and whether any ACE was
// inherited from the parent.
func daclOf(t *testing.T, dir string) (protected, inherited bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl != nil {
		for i := uint16(0); i < dacl.AceCount; i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
				inherited = true
			}
		}
	}
	return ctl&windows.SE_DACL_PROTECTED != 0, inherited
}

// The audit finding: the folder must never exist with the ACL inherited
// from its parent, not even for a moment and not after a failed install.
func TestPrepareDataDirNeverLeavesInheritedACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "OpenScale")
	err := prepareDataDir(dir)
	if _, statErr := os.Stat(dir); statErr != nil {
		if err == nil {
			t.Fatal("hata yok ama klasör de yok")
		}
		return // not elevated: the owner cannot be set, nothing was created
	}
	if protected, inherited := daclOf(t, dir); !protected || inherited {
		t.Fatalf("klasör devralınan izinlerle kaldı (korumalı=%v devralınan=%v, hata=%v)", protected, inherited, err)
	}
}

func TestCreateProtectedDirIsProtectedFromBirth(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "OpenScale")
	sddl := "D:P(A;OICI;FA;;;" + selfSID(t).String() + ")(A;OICI;FA;;;SY)"
	created, err := createProtectedDir(dir, sddl)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("yeni klasör oluşturulmuş sayılmadı")
	}
	if protected, inherited := daclOf(t, dir); !protected || inherited {
		t.Fatalf("korumalı=%v devralınan=%v", protected, inherited)
	}
	created, err = createProtectedDir(dir, sddl)
	if err != nil || created {
		t.Fatalf("var olan klasör: created=%v err=%v", created, err)
	}
}

func TestAuditDataTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "OpenScale")
	sub := filepath.Join(root, "device")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(sub, "device.key")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	me := selfSID(t)
	trusted := func(s *windows.SID) bool { return s != nil && s.Equals(me) }

	if err := auditDataTree(root, trusted); err != nil {
		t.Fatalf("güvenilir ağaç reddedildi: %v", err)
	}

	// A sub-object of another owner: its owner could open it up again.
	err := auditDataTree(root, func(*windows.SID) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "device") {
		t.Fatalf("yabancı sahipli alt nesne kabul edildi: %v", err)
	}

	// A sub-folder a user opened with an explicit ACE loses it.
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;" + me.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(sub, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if !hasExplicitGrantTo(t, sub, everyone) {
		t.Fatal("hazırlık: açık izin yazılamadı")
	}
	if err := auditDataTree(root, trusted); err != nil {
		t.Fatalf("onarım: %v", err)
	}
	if hasExplicitGrantTo(t, sub, everyone) {
		t.Fatal("alt klasördeki açık izin kaldırılmadı")
	}
	if protected, _ := daclOf(t, sub); protected {
		t.Fatal("alt klasör üst klasörün izinlerini devralmıyor")
	}

	// A junction is never walked through.
	outside := t.TempDir()
	junction := filepath.Join(root, "baglanti")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Clean(junction), filepath.Clean(outside)).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	err = auditDataTree(root, trusted)
	if err == nil || !strings.Contains(err.Error(), "baglanti") {
		t.Fatalf("bağlantı noktası kabul edildi: %v", err)
	}
}

func hasExplicitGrantTo(t *testing.T, path string, who *windows.SID) bool {
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
		return false
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 && aceSID(ace).Equals(who) {
			return true
		}
	}
	return false
}
