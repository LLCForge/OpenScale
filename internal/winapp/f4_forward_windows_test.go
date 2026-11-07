//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The fake window of the regression test: a different program (a copy of
// the test binary with extra bytes, so neither its path nor its hash is
// this program's) registers the panel window's class name and writes down
// whatever it receives. This is what a same-user attacker would run.

const (
	fakeWindowOutEnv   = "OPENSCALE_F4_FAKE_WINDOW_OUT"
	fakeWindowClass    = "OpenScaleWebViewWindow"
	fakeWindowCopyData = 0x004A
	fakeWindowTag      = 0x4F534657
)

type fakeCopyData struct {
	data  uintptr
	size  uint32
	bytes uintptr
}

var (
	fakeProcRegisterClass = modUser32.NewProc("RegisterClassExW")
	fakeProcCreateWindow  = modUser32.NewProc("CreateWindowExW")
	fakeProcDefWindowProc = modUser32.NewProc("DefWindowProcW")
	fakeProcGetMessage    = modUser32.NewProc("GetMessageW")
	fakeProcDispatch      = modUser32.NewProc("DispatchMessageW")
)

type fakeWndClass struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSm     uintptr
}

type fakeMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	x, y    int32
}

// TestHelperFakePanelWindow is the attacker process; it does nothing in a
// normal test run.
func TestHelperFakePanelWindow(t *testing.T) {
	out := os.Getenv(fakeWindowOutEnv)
	if out == "" {
		t.Skip("yardımcı süreç")
	}
	runtime.LockOSThread()
	class, _ := windows.UTF16PtrFromString(fakeWindowClass)
	proc := windows.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
		if msg == fakeWindowCopyData && lParam != 0 {
			cds := *(**fakeCopyData)(unsafe.Pointer(&lParam))
			if cds.data == fakeWindowTag && cds.bytes != 0 && cds.size > 0 {
				units := unsafe.Slice(*(**uint16)(unsafe.Pointer(&cds.bytes)), cds.size/2)
				_ = os.WriteFile(out, []byte(string(utf16.Decode(units))), 0o600)
				return 1
			}
		}
		r, _, _ := fakeProcDefWindowProc.Call(hwnd, msg, wParam, lParam)
		return r
	})
	wc := fakeWndClass{wndProc: proc, className: class}
	wc.size = uint32(unsafe.Sizeof(wc))
	if r, _, err := fakeProcRegisterClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		t.Fatalf("RegisterClassExW: %v", err)
	}
	hwnd, _, err := fakeProcCreateWindow.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(class)), 0, 0, 0, 1, 1, 0, 0, 0, 0)
	if hwnd == 0 {
		t.Fatalf("CreateWindowExW: %v", err)
	}
	if err := os.WriteFile(out+".ready", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	var m fakeMsg
	for {
		r, _, _ := fakeProcGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 || int32(r) == -1 {
			return
		}
		_, _, _ = fakeProcDispatch.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// foreignCopyOfTestBinary copies the test binary with trailing bytes: it
// still runs, but has another path and another hash.
func foreignCopyOfTestBinary(t *testing.T, dir, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, append(data, []byte("baska program")...), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A window with the panel's class name in another program must not get the
// sign-in ticket: the audit finding, end to end, with real window messages.
func TestForwardRefusesWindowOfAnotherProgram(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "alinan.txt")
	fake := foreignCopyOfTestBinary(t, dir, "sahte-pencere.exe")
	cmd := exec.Command(fake, "-test.run=^TestHelperFakePanelWindow$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), fakeWindowOutEnv+"="+out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(out + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sahte pencere açılmadı")
		}
		time.Sleep(50 * time.Millisecond)
	}

	const secret = "gizli-bilet"
	err := ForwardToPanelWindow(fmt.Sprintf("http://127.0.0.1:1%s?t=%s", TicketPath, secret))
	if data, readErr := os.ReadFile(out); readErr == nil {
		t.Fatalf("giriş bileti başka bir programın penceresine gitti: %q", data)
	}
	if err == nil {
		t.Fatal("yönlendirme başarılı sayıldı: gerçek pencere hiç açılmazdı")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("hata metninde bilet var: %v", err)
	}
}

func TestPanelWindowFactsRefuseEachMismatch(t *testing.T) {
	allow := func(string) error { return nil }
	deny := func(string) error { return errors.New("yabancı program") }
	good := panelWindowFacts{session: 1, integrity: integrityMedium, image: `C:\Program Files\OpenScale\openscale.exe`}
	cases := []struct {
		name  string
		facts panelWindowFacts
		allow func(string) error
		ok    bool
	}{
		{"doğrulanmış pencere", good, allow, true},
		{"yükseltilmiş pencere de aynı program", panelWindowFacts{session: 1, integrity: 0x3000, image: good.image}, allow, true},
		{"başka program", good, deny, false},
		{"başka oturum", panelWindowFacts{session: 2, integrity: integrityMedium, image: good.image}, allow, false},
		{"düşük bütünlük düzeyi", panelWindowFacts{session: 1, integrity: 0x1000, image: good.image}, allow, false},
		{"görüntü adı yok", panelWindowFacts{session: 1, integrity: integrityMedium}, allow, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkPanelWindowFacts(c.facts, 1, c.allow)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok = %v", err, c.ok)
			}
		})
	}
}

// The real check on real processes: this program passes, another fails.
func TestVerifyPanelWindowProcess(t *testing.T) {
	if err := verifyPanelWindowProcess(uint32(os.Getpid())); err != nil {
		t.Fatalf("kendi süreci: %v", err)
	}
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "ping.exe"), "-n", "20", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err := verifyPanelWindowProcess(uint32(cmd.Process.Pid)); err == nil {
		t.Fatal("başka bir program doğrulandı")
	}
	if err := verifyPanelWindowProcess(0); err == nil {
		t.Fatal("geçersiz süreç doğrulandı")
	}
}
