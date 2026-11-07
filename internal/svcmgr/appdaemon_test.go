package svcmgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/launchd"
)

func TestDarwinAppInstall(t *testing.T) {
	f, s := newFakeSystem(t)
	res, err := installDarwinApp(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Started || res.Binary != DarwinAppBinary {
		t.Fatalf("result = %+v", res)
	}
	if got := f.read(t, DarwinAppBinary); got != "program" {
		t.Fatalf("binary = %q", got)
	}
	plist := f.read(t, launchd.Path(DarwinAppLabel))
	for _, want := range []string{
		"<string>com.openscale.service</string>",
		"<string>/Library/Application Support/OpenScale/bin/openscale</string>\n\t\t<string>service</string>\n\t\t<string>run</string>",
		"<string>/var/db/openscale/service</string>",
		"<key>SuccessfulExit</key>",
		"<string>root</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	if !launchd.HasMarker([]byte(plist), darwinAppMarker) {
		t.Fatal("marker missing")
	}
	info, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(DarwinAppStateDir)))
	if err != nil || !info.IsDir() {
		t.Fatalf("state dir: %v", err)
	}
	if !strings.HasPrefix(f.read(t, darwinAppSyslog), installMarker+"\n") {
		t.Fatal("newsyslog file without marker")
	}
	want := "launchctl enable system/com.openscale.service|launchctl print system/com.openscale.service|launchctl bootout system/com.openscale.service|launchctl bootstrap system /Library/LaunchDaemons/com.openscale.service.plist"
	if got := strings.Join(f.cmds, "|"); got != want {
		t.Fatalf("commands = %s", got)
	}
	if !darwinAppInstalled(s) {
		t.Fatal("not reported as installed")
	}

	f.cmds = nil
	if err := restartDarwinApp(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.cmds, "|"); got != "launchctl print system/com.openscale.service|launchctl kickstart -k system/com.openscale.service" {
		t.Fatalf("restart commands = %s", got)
	}

	notes, err := uninstallDarwinApp(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if darwinAppInstalled(s) || len(notes) < 3 {
		t.Fatalf("after uninstall: installed=%v notes=%v", darwinAppInstalled(s), notes)
	}
	if _, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(DarwinAppBinary))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("binary left: %v", err)
	}
}

func TestDarwinAppInstallRefusals(t *testing.T) {
	f, s := newFakeSystem(t)
	f.euid = 501
	if _, err := installDarwinApp(context.Background(), s); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("non-root: %v", err)
	}
	if _, err := uninstallDarwinApp(context.Background(), s); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("non-root uninstall: %v", err)
	}
	if err := restartDarwinApp(context.Background(), s); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("non-root restart: %v", err)
	}
	f.euid = 0
	dev := filepath.Join(f.root, filepath.FromSlash(launchd.Path(darwinDeviceLabel)))
	if err := os.MkdirAll(filepath.Dir(dev), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dev, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installDarwinApp(context.Background(), s); !errors.Is(err, ErrDarwinDeviceDaemon) {
		t.Fatalf("beside the device daemon: %v", err)
	}
	if err := os.Remove(dev); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(f.root, filepath.FromSlash(launchd.Path(DarwinAppLabel)))
	if err := os.WriteFile(own, []byte("<plist>by hand</plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installDarwinApp(context.Background(), s); err == nil || !strings.Contains(err.Error(), "elle yazılmış") {
		t.Fatalf("hand-written plist: %v", err)
	}
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	f.cmds = nil
	s.trusted = func(string) error { return errors.New("user-owned") }
	if _, err := installDarwinApp(context.Background(), s); err == nil || !strings.Contains(err.Error(), "F-124") {
		t.Fatalf("untrusted binary: %v", err)
	}
	if len(f.cmds) != 0 {
		t.Fatalf("commands ran: %v", f.cmds)
	}
}

func TestDarwinAppPlistMatchesDeploy(t *testing.T) {
	want, err := launchd.Plist(DarwinAppJob(DarwinAppBinary))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", "deploy", "macos", DarwinAppLabel+".plist"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != string(want) {
		t.Fatalf("deploy/macos/%s.plist is out of date; want:\n%s", DarwinAppLabel, want)
	}
}
