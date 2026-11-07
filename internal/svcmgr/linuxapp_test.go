package svcmgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxAppInstall(t *testing.T) {
	f, s := newFakeSystem(t)
	res, err := installLinuxApp(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Started || res.Binary != localBinary {
		t.Fatalf("result = %+v", res)
	}
	unit := f.read(t, "/etc/systemd/system/openscale-app.service")
	for _, want := range []string{
		linuxAppMarker + "\n",
		"ExecStart=/usr/local/bin/openscale service run\n",
		"RuntimeDirectory=openscale\nRuntimeDirectoryMode=0755\n",
		"LimitCORE=0\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if info, err := os.Stat(filepath.Join(f.root, "var", "lib", "openscale", "app")); err != nil || !info.IsDir() {
		t.Fatalf("state dir: %v", err)
	}
	if !strings.Contains(f.read(t, "/etc/xdg/autostart/"+AutostartDesktopFile), "autostart run") {
		t.Fatal("all-users sign-in entry missing")
	}
	if got := strings.Join(f.cmds, "|"); got != "systemctl daemon-reload|systemctl enable openscale-app.service|systemctl restart openscale-app.service" {
		t.Fatalf("commands = %s", got)
	}
	if !linuxAppInstalled(s) {
		t.Fatal("not installed")
	}
	f.cmds = nil
	if err := restartLinuxApp(context.Background(), s); err != nil || strings.Join(f.cmds, "|") != "systemctl restart openscale-app.service" {
		t.Fatalf("restart: %v %v", err, f.cmds)
	}
	notes, err := uninstallLinuxApp(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if linuxAppInstalled(s) || len(notes) < 2 {
		t.Fatalf("after uninstall: %v", notes)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc", "xdg", "autostart", AutostartDesktopFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sign-in entry left: %v", err)
	}
}

func TestLinuxAppRefusals(t *testing.T) {
	f, s := newFakeSystem(t)
	f.euid = 1000
	if _, err := installLinuxApp(context.Background(), s); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("non-root: %v", err)
	}
	f.euid = 0
	dev := filepath.Join(f.root, "usr", "lib", "systemd", "system")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dev, "openscale-device.service"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installLinuxApp(context.Background(), s); !errors.Is(err, ErrLinuxDeviceUnit) {
		t.Fatalf("device unit: %v", err)
	}
	if err := os.Remove(filepath.Join(dev, "openscale-device.service")); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(f.root, "etc", "systemd", "system")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, LinuxAppUnit), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installLinuxApp(context.Background(), s); err == nil {
		t.Fatal("hand-written unit overwritten")
	}
	if _, err := uninstallLinuxApp(context.Background(), s); err == nil {
		t.Fatal("hand-written unit removed")
	}
	for _, bad := range []string{"rel/openscale", "/a b/openscale", "/a;rm/x", "/a%h/x"} {
		if _, err := LinuxAppUnitFile(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLegacyAutostartEntryReplaced(t *testing.T) {
	f, s := newFakeSystem(t)
	dir := filepath.Join(f.root, "etc", "xdg", "autostart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old, err := DesktopEntry("/usr/bin/openscale")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, LegacyAutostartDesktopFile), old, 0o644); err != nil {
		t.Fatal(err)
	}
	installSystemAutostart(s, "linux", "/usr/bin/openscale")
	if _, err := os.Stat(filepath.Join(dir, LegacyAutostartDesktopFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy entry left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, AutostartDesktopFile)); err != nil {
		t.Fatal(err)
	}
	// Someone else's old file stays.
	if err := os.WriteFile(filepath.Join(dir, LegacyAutostartDesktopFile), []byte("[Desktop Entry]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installSystemAutostart(s, "linux", "/usr/bin/openscale")
	if _, err := os.Stat(filepath.Join(dir, LegacyAutostartDesktopFile)); err != nil {
		t.Fatal("foreign legacy file removed")
	}
	e := legacyAutostartState(AutostartEntry{Scope: ScopeAllUsers, Path: filepath.Join(dir, "missing", AutostartDesktopFile)})
	if e.Installed {
		t.Fatal("missing legacy reported")
	}
}

func TestLinuxAppGroupAndProgram(t *testing.T) {
	f, s := newFakeSystem(t)
	if _, err := installLinuxApp(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if bin, err := linuxAppProgram(s); err != nil || bin != localBinary {
		t.Fatalf("program %q %v", bin, err)
	}
	f.cmds = nil
	notes, err := addToLinuxAppGroup(context.Background(), s, "ayse", false, false)
	if err != nil || len(notes) != 2 {
		t.Fatalf("%v %v", notes, err)
	}
	if got := strings.Join(f.cmds, "|"); got != "groupadd --system openscale|gpasswd -a ayse openscale" {
		t.Fatalf("commands %s", got)
	}
	f.cmds = nil
	if _, err := addToLinuxAppGroup(context.Background(), s, "ayse", true, true); err != nil || len(f.cmds) != 0 {
		t.Fatalf("member: %v %v", err, f.cmds)
	}
	for _, bad := range []string{"-r", "", "a b", "a:b"} {
		if _, err := addToLinuxAppGroup(context.Background(), s, bad, true, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
