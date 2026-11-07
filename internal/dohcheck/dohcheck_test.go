package dohcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanLinux(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	write(t, filepath.Join(home, ".mozilla", "firefox", "abc.default", "prefs.js"),
		`user_pref("browser.x", true);`+"\n"+`user_pref("network.trr.mode", 3);`+"\n"+`user_pref("network.trr.uri", "https://doh.example/dns-query/ACCOUNT");`+"\n")
	write(t, filepath.Join(home, ".mozilla", "firefox", "off.default", "prefs.js"), `user_pref("network.trr.mode", 5);`)
	write(t, filepath.Join(home, ".mozilla", "firefox", "first.default", "prefs.js"), `user_pref("network.trr.mode", 2);`)
	write(t, filepath.Join(cfg, "google-chrome", "Local State"), `{"dns_over_https":{"mode":"secure","templates":"https://dns.example/dns-query{?dns}"}}`)
	write(t, filepath.Join(cfg, "chromium", "Local State"), `{"dns_over_https":{"mode":"automatic","templates":""}}`)
	write(t, filepath.Join(cfg, "microsoft-edge", "Local State"), `not json`)

	got, err := ScanDirs(Dirs{Home: home, Config: cfg, GOOS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[0].Browser != "Chrome" || got[0].Resolver != "dns.example" || !got[0].Bypass {
		t.Errorf("chrome %+v", got[0])
	}
	if got[1].Browser != "Firefox" || got[1].Profile != "abc.default" || got[1].Resolver != "doh.example" || !got[1].Bypass {
		t.Errorf("firefox %+v", got[1])
	}
	if got[2].Profile != "first.default" || got[2].Bypass || got[2].Mode != "2" {
		t.Errorf("firefox fallback %+v", got[2])
	}
}

func TestScanWindowsEmpty(t *testing.T) {
	got, err := ScanDirs(Dirs{AppData: t.TempDir(), LocalAppData: t.TempDir(), GOOS: "windows"})
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %+v", err, got)
	}
}
