package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The OpenWrt (#446) and AppImage (#502) files that build-ipk.sh and
// build-appimage.sh pack must stay consistent with each other.
func TestOpenWrtFiles(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "openwrt")
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "\r") {
			t.Fatalf("%s has CRLF line endings; busybox sh would fail", name)
		}
		return string(data)
	}
	initd := read("openscale.init")
	for _, want := range []string{"#!/bin/sh /etc/rc.common", "USE_PROCD=1", "config_load openscale", "OPENSCALE_MEMORY_PROFILE", "anchor.json"} {
		if !strings.Contains(initd, want) {
			t.Errorf("init script lacks %q", want)
		}
	}
	conf := read("openscale.config")
	for _, opt := range []string{"enabled", "state_dir", "listen_port", "interface", "memory_profile"} {
		if !strings.Contains(conf, "option "+opt+" ") {
			t.Errorf("config lacks option %s", opt)
		}
		if !strings.Contains(initd, "main "+opt+" ") {
			t.Errorf("init script does not read option %s", opt)
		}
	}
	if strings.TrimSpace(read("conffiles")) != "/etc/config/openscale" {
		t.Error("conffiles must list /etc/config/openscale")
	}
	build := read("build-ipk.sh")
	for _, want := range []string{"etc/config/openscale", "etc/init.d/openscale", "etc/uci-defaults/90-openscale", "usr/bin/openscale", "kmod-tun"} {
		if !strings.Contains(build, want) {
			t.Errorf("build-ipk.sh lacks %q", want)
		}
	}
	if !strings.Contains(read("openscale.uci-defaults"), "41821") || !strings.Contains(conf, "'41821'") {
		t.Error("the firewall rule and the default listen port differ")
	}
	read("postinst")
	read("prerm")
}

func TestAppImageFiles(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "appimage")
	desktop, err := os.ReadFile(filepath.Join(root, "openscale.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Desktop Entry]", "\nType=Application", "\nName=OpenScale", "\nExec=", "\nIcon=openscale", "\nCategories="} {
		if !strings.Contains(string(desktop), want) {
			t.Errorf("desktop file lacks %q", strings.TrimSpace(want))
		}
	}
	apprun, err := os.ReadFile(filepath.Join(root, "AppRun"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(apprun), "#!/bin/sh\n") || !strings.Contains(string(apprun), `exec "$HERE/usr/bin/openscale"`) {
		t.Error("AppRun must exec the bundled program")
	}
	if _, err := os.Stat(filepath.Join("..", "..", "logos", "android-chrome-512x512.png")); err != nil {
		t.Errorf("AppImage icon: %v", err)
	}
}
