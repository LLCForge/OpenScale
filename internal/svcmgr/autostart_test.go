package svcmgr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopEntry(t *testing.T) {
	data, err := DesktopEntry("/usr/local/bin/openscale")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		autostartMarker + "\n[Desktop Entry]\n",
		"Type=Application\n",
		"Exec=/usr/local/bin/openscale autostart run\n",
		"Terminal=false\n",
		"X-GNOME-Autostart-enabled=true\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("entry lacks %q:\n%s", want, s)
		}
	}
	// Spaces and special characters are quoted and escaped twice
	// (Exec quoting, then the desktop file's own escape).
	data, err = DesktopEntry("/opt/Open Scale/bin$/openscale")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `Exec="/opt/Open Scale/bin\\$/openscale" autostart run`) {
		t.Fatalf("quoting:\n%s", data)
	}
	for _, bad := range []string{"openscale", "/a%f/openscale", "/a\nExec=/bin/sh", ""} {
		if _, err := DesktopEntry(bad); err == nil {
			t.Errorf("DesktopEntry(%q) accepted", bad)
		}
	}
	if !hasAutostartMarker(data) {
		t.Fatal("marker not recognized")
	}
}

func TestLaunchAgentPlist(t *testing.T) {
	data, err := LaunchAgentPlist("/usr/local/bin/openscale")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"<string>com.openscale.tray</string>",
		"<string>/usr/local/bin/openscale</string>\n\t\t<string>autostart</string>\n\t\t<string>run</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>",
		"<key>ProcessType</key>\n\t<string>Interactive</string>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "UserName") {
		t.Fatal("a launch agent must run as the signed-in user")
	}
	if !hasAutostartMarker(data) {
		t.Fatal("marker not recognized")
	}
}

func TestAutostartPaths(t *testing.T) {
	home := filepath.FromSlash("/home/ali")
	if !filepath.IsAbs(home) {
		home = `C:\Users\ali` // Windows test host
	}
	cases := []struct{ goos, cfg, want string }{
		{"linux", "", filepath.Join(home, ".config", "autostart", "openscale-tray.desktop")},
		{"linux", "relative", filepath.Join(home, ".config", "autostart", "openscale-tray.desktop")},
		{"darwin", "", filepath.Join(home, "Library", "LaunchAgents", "com.openscale.tray.plist")},
	}
	for _, c := range cases {
		got, err := UserAutostartPath(c.goos, home, c.cfg)
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", c.goos, got, err, c.want)
		}
	}
	xdg := filepath.Join(home, "xdg")
	if got, _ := UserAutostartPath("linux", home, xdg); got != filepath.Join(xdg, "autostart", "openscale-tray.desktop") {
		t.Fatal(got)
	}
	if _, err := UserAutostartPath("linux", "", ""); err == nil {
		t.Fatal("empty home accepted")
	}
	if _, err := UserAutostartPath("windows", home, ""); err == nil {
		t.Fatal("windows has no file entry")
	}
	if p, _ := SystemAutostartPath("linux"); p != "/etc/xdg/autostart/openscale-tray.desktop" {
		t.Fatal(p)
	}
	if p, _ := SystemAutostartPath("darwin"); p != "/Library/LaunchAgents/com.openscale.tray.plist" {
		t.Fatal(p)
	}
}

func TestAutostartFileWriteAndRemove(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "autostart", "openscale-tray.desktop")
	data, _ := DesktopEntry("/usr/bin/openscale")
	if err := writeAutostartFile(p, data, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := autostartFileState(ScopeUser, p)
	if err != nil || !st.Installed || !st.Ours {
		t.Fatalf("state = %+v, %v", st, err)
	}
	// Rewriting our own entry is fine.
	if err := writeAutostartFile(p, data, 0o700); err != nil {
		t.Fatal(err)
	}
	removed, err := removeAutostartFile(p)
	if err != nil || !removed {
		t.Fatalf("remove = %v, %v", removed, err)
	}
	if removed, err := removeAutostartFile(p); err != nil || removed {
		t.Fatalf("second remove = %v, %v", removed, err)
	}
	// Someone else's file is never overwritten or deleted.
	if err := os.WriteFile(p, []byte("[Desktop Entry]\nExec=other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeAutostartFile(p, data, 0o700); err == nil {
		t.Fatal("foreign file overwritten")
	}
	if _, err := removeAutostartFile(p); err == nil {
		t.Fatal("foreign file removed")
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "Exec=other") {
		t.Fatal("foreign file changed")
	}
}

func TestAutostartSetting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "OpenScale")
	if on, err := LoadAutostartSetting(dir); err != nil || !on {
		t.Fatalf("default = %v, %v (owner wants on by default)", on, err)
	}
	if err := SaveAutostartSetting(dir, false); err != nil {
		t.Fatal(err)
	}
	if on, err := LoadAutostartSetting(dir); err != nil || on {
		t.Fatalf("after off = %v, %v", on, err)
	}
	if err := os.WriteFile(filepath.Join(dir, AutostartSettingFile), []byte(`{"enabled":false,"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if on, err := LoadAutostartSetting(dir); err == nil || !on {
		t.Fatalf("damaged = %v, %v", on, err)
	}
	for _, s := range []string{"", "user", "all", "herkes"} {
		if _, err := ParseScope(s); err != nil {
			t.Fatal(s, err)
		}
	}
	if _, err := ParseScope("root"); err == nil {
		t.Fatal("bad scope accepted")
	}
}

// The background service starts at boot on Linux: the unit is wanted by
// multi-user.target and "service install" enables it.
func TestLinuxServiceStartsAtBoot(t *testing.T) {
	data, err := unitFiles.ReadFile("units/" + RoleDevice.Unit())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(data), "\r\n", "\n"), "[Install]\nWantedBy=multi-user.target") {
		t.Fatal("device unit is not wanted by multi-user.target")
	}
	// "service install" on a joined device runs "systemctl enable" (see
	// installLinux); an unjoined one only writes the files, which still
	// include the all-users sign-in entry.
	f, s := newFakeSystem(t)
	f.euid = 0
	if _, err := installLinux(context.Background(), s, Options{Role: RoleDevice}); err != nil {
		t.Fatal(err)
	}
	entry := f.read(t, "/etc/xdg/autostart/openscale-tray.desktop")
	if !strings.Contains(entry, "autostart run") || !hasAutostartMarker([]byte(entry)) {
		t.Fatalf("all-users entry:\n%s", entry)
	}
	notes, err := uninstallLinux(context.Background(), s, RoleDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc", "xdg", "autostart", "openscale-tray.desktop")); !os.IsNotExist(err) {
		t.Fatalf("entry left after uninstall: %v (notes %v)", err, notes)
	}
}

// The background service starts at boot on macOS: RunAtLoad in the
// daemon, and the sign-in agent is written and removed with it.
func TestDarwinServiceStartsAtBoot(t *testing.T) {
	f, s := newFakeSystem(t)
	if _, err := installDarwin(context.Background(), s, Options{}); err != nil {
		t.Fatal(err)
	}
	plist := f.read(t, "/Library/LaunchDaemons/com.openscale.device.plist")
	if !strings.Contains(plist, "<key>RunAtLoad</key>\n\t<true/>") {
		t.Fatal("daemon does not run at load")
	}
	agent := f.read(t, "/Library/LaunchAgents/com.openscale.tray.plist")
	if !strings.Contains(agent, "<key>RunAtLoad</key>\n\t<true/>") || !hasAutostartMarker([]byte(agent)) {
		t.Fatalf("agent:\n%s", agent)
	}
	if _, err := uninstallDarwin(context.Background(), s, RoleDevice); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "Library", "LaunchAgents", "com.openscale.tray.plist")); !os.IsNotExist(err) {
		t.Fatalf("agent left after uninstall: %v", err)
	}
}
