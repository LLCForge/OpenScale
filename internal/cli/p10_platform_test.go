package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/wintunembed"
)

func portableTestHost(t *testing.T, exeDir string) portableHost {
	t.Helper()
	return portableHost{
		goos:                "windows",
		exe:                 func() (string, error) { return filepath.Join(exeDir, "openscale.exe"), nil },
		elevated:            func() bool { return true },
		serviceInstalled:    func() (bool, error) { return false, nil },
		killSwitchInstalled: func() (bool, error) { return false, nil },
		firewallPresent:     func() (bool, error) { return true, nil },
		driverVersion:       func() (string, error) { return "", wintunembed.ErrDriverNotLoaded },
	}
}

func TestPlanPortable(t *testing.T) {
	usb := t.TempDir()
	if err := os.WriteFile(filepath.Join(usb, "openscale.exe"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := portableTestHost(t, usb)
	// No membership on the stick yet: the error names the join command.
	if _, err := planPortable(h, ""); err == nil || !strings.Contains(err.Error(), "openscale join --state-dir") {
		t.Fatalf("no membership: %v", err)
	}
	dir := filepath.Join(usb, portableDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := planPortable(h, "")
	if err != nil {
		t.Fatal(err)
	}
	// The firewall rules were already there: they stay. The kill switch
	// and the driver were not: the run removes them at the end.
	want, _ := filepath.EvalSymlinks(dir)
	if got, _ := filepath.EvalSymlinks(p.StateDir); got != want || !p.RemoveKillSwitch || p.RemoveFirewall || !p.DeleteDriver {
		t.Fatalf("plan %+v", p)
	}

	for name, mutate := range map[string]func(*portableHost){
		"linux":     func(h *portableHost) { h.goos = "linux" },
		"no admin":  func(h *portableHost) { h.elevated = func() bool { return false } },
		"service":   func(h *portableHost) { h.serviceInstalled = func() (bool, error) { return true, nil } },
		"svc error": func(h *portableHost) { h.serviceInstalled = func() (bool, error) { return false, errors.New("x") } },
	} {
		hh := h
		mutate(&hh)
		if _, err := planPortable(hh, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := planPortable(h, "goreli/klasor"); err == nil {
		t.Fatal("relative state directory accepted")
	}
}

func TestSplitPortableArgs(t *testing.T) {
	dir, confirm := "", ""
	rest, err := splitPortableArgs([]string{"--exit-node", "ev", "--state-dir", `E:\os`, "--confirm=GUVENIYORUM", "-debug"}, &dir, &confirm)
	if err != nil || dir != `E:\os` || confirm != portableTrustWord || strings.Join(rest, " ") != "--exit-node ev -debug" {
		t.Fatalf("rest=%v dir=%q confirm=%q err=%v", rest, dir, confirm, err)
	}
	if _, err := splitPortableArgs([]string{"--state-dir"}, &dir, &confirm); err == nil {
		t.Fatal("missing value accepted")
	}
}

func TestPortableCleanupOnlyUndoesItsOwn(t *testing.T) {
	var calls []string
	u := portableUndo{
		removeKillSwitch: func() error { calls = append(calls, "ks"); return nil },
		removeFirewall:   func() error { calls = append(calls, "fw"); return nil },
		deleteDriver:     func() error { calls = append(calls, "drv"); return errors.New("adaptör kullanımda") },
	}
	notes := portableCleanup(portablePlan{RemoveKillSwitch: true, DeleteDriver: true}, u)
	if strings.Join(calls, ",") != "ks,drv" {
		t.Fatalf("calls %v", calls)
	}
	text := strings.Join(notes, "\n")
	if !strings.Contains(text, "Kill switch kaldırıldı") || !strings.Contains(text, "Wintun sürücüsü kaldırılamadı") || !strings.Contains(text, "Prefetch") {
		t.Fatalf("notes: %s", text)
	}
}

func TestPortableRefusesOutsideWindows(t *testing.T) {
	h := portableTestHost(t, t.TempDir())
	h.goos = "linux"
	_, err := planPortable(h, "")
	if err == nil || !strings.Contains(err.Error(), "up --state-dir") {
		t.Fatalf("err %v", err)
	}
}

func TestPlatformCommandsWithoutService(t *testing.T) {
	h := newHarness(t)
	out := h.run(0, "platform", "--state-dir", filepath.Join(t.TempDir(), "yok"))
	if !strings.Contains(out, "İşletim sistemi:") || !strings.Contains(out, "Bellek profili:") || !strings.Contains(out, "Servise ulaşılamadı") {
		t.Fatalf("platform: %s", out)
	}
	h.run(0, "platform", "wsl")
	// Two profiles that do not exist yet: a clear error, nothing created.
	h.run(1, "network", "concurrent", "default", "aile")
	h.run(2, "network", "concurrent", "default")
}
