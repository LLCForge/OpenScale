package svcmgr

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/launchd"
)

func TestDarwinInstallNotJoined(t *testing.T) {
	f, s := newFakeSystem(t)
	res, err := installDarwin(context.Background(), s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Started || res.Binary != localBinary {
		t.Fatalf("result = %+v", res)
	}
	plist := f.read(t, launchd.Path(darwinDeviceLabel))
	for _, want := range []string{
		"<string>com.openscale.device</string>",
		"<string>/usr/local/bin/openscale</string>\n\t\t<string>up</string>\n\t\t<string>--config</string>\n\t\t<string>/etc/openscale/device.json</string>",
		"<string>/var/db/openscale/device</string>",
		"<key>SuccessfulExit</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
	if !launchd.HasMarker([]byte(plist), darwinPlistMarker) {
		t.Fatal("marker missing")
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(f.read(t, "/etc/openscale/device.json")), &params); err != nil {
		t.Fatal(err)
	}
	if params["interface"] != "utun" || params["state-dir"] != DarwinDeviceStateDir {
		t.Fatalf("params = %v", params)
	}
	if !strings.HasPrefix(f.read(t, darwinNewsyslogConf), installMarker+"\n") {
		t.Fatal("newsyslog file without marker")
	}
	if strings.Join(f.cmds, "|") != "launchctl enable system/com.openscale.device" {
		t.Fatalf("commands = %v (must not start before joining)", f.cmds)
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, " "), "ağa katılmamış") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestDarwinInstallRefusals(t *testing.T) {
	f, s := newFakeSystem(t)
	if _, err := installDarwin(context.Background(), s, Options{Role: RoleCoordinator}); !errors.Is(err, ErrDarwinCoordinator) {
		t.Fatalf("coordinator: %v", err)
	}
	f.euid = 501
	if _, err := installDarwin(context.Background(), s, Options{}); !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("non-root: %v", err)
	}
	f.euid = 0
	// A hand-written daemon file is never overwritten.
	p := filepath.Join(f.root, filepath.FromSlash(launchd.Path(darwinDeviceLabel)))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("<plist>mine</plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installDarwin(context.Background(), s, Options{}); err == nil {
		t.Fatal("foreign plist overwritten")
	}
	if _, err := uninstallDarwin(context.Background(), s, RoleDevice); err == nil {
		t.Fatal("foreign plist removed")
	}
	if got, _ := os.ReadFile(p); string(got) != "<plist>mine</plist>" {
		t.Fatal("foreign plist changed")
	}
	if _, err := installDarwin(context.Background(), s, Options{Interface: "bad name"}); err == nil {
		t.Fatal("bad interface accepted")
	}
}

func TestDarwinControlStatusUninstall(t *testing.T) {
	f, s := newFakeSystem(t)
	ctx := context.Background()
	if err := controlDarwin(ctx, s, "start", RoleDevice); err == nil {
		t.Fatal("start without install")
	}
	if _, err := installDarwin(ctx, s, Options{NoStart: true}); err != nil {
		t.Fatal(err)
	}
	f.cmds = nil
	// The fake runner succeeds for "print": the daemon counts as loaded.
	if err := controlDarwin(ctx, s, "restart", RoleDevice); err != nil {
		t.Fatal(err)
	}
	if err := controlDarwin(ctx, s, "stop", RoleDevice); err != nil {
		t.Fatal(err)
	}
	want := "launchctl print system/com.openscale.device|launchctl kickstart -k system/com.openscale.device|launchctl print system/com.openscale.device|launchctl bootout system/com.openscale.device"
	if got := strings.Join(f.cmds, "|"); got != want {
		t.Fatalf("commands:\n%s\nwant:\n%s", got, want)
	}
	if err := controlDarwin(ctx, s, "start", RoleCoordinator); !errors.Is(err, ErrDarwinCoordinator) {
		t.Fatalf("coordinator: %v", err)
	}
	st, err := statusDarwin(ctx, s, RoleDevice)
	if err != nil || !st.Installed || !st.Enabled {
		t.Fatalf("status = %+v %v", st, err)
	}
	f.cmds = nil
	notes, err := uninstallDarwin(ctx, s, RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(launchd.Path(darwinDeviceLabel)))); !os.IsNotExist(err) {
		t.Fatal("plist kept")
	}
	if _, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(darwinNewsyslogConf))); !os.IsNotExist(err) {
		t.Fatal("newsyslog file kept")
	}
	if !strings.Contains(strings.Join(notes, " "), "yerinde bırakıldı") || !strings.Contains(strings.Join(f.cmds, "|"), "bootout") {
		t.Fatalf("notes = %v cmds = %v", notes, f.cmds)
	}
	st, _ = statusDarwin(ctx, s, RoleDevice)
	if st.Installed || st.State != "kurulu değil" {
		t.Fatalf("status after uninstall = %+v", st)
	}
}

func TestDeployMacOSPlistMatchesInstall(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "macos", "com.openscale.device.plist"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := launchd.Plist(darwinDeviceJob(localBinary, paramsDir+"/device.json", DarwinDeviceStateDir))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.ReplaceAll(string(data), "\r\n", "\n")
	if got != string(want) {
		t.Fatalf("deploy/macos/com.openscale.device.plist differs from what service install writes:\n%s", want)
	}
}
