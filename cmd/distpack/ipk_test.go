package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	mode int64
	typ  byte
	data []byte
}

func readTarGz(t *testing.T, data []byte) ([]string, map[string]tarEntry) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var order []string
	out := map[string]tarEntry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		order = append(order, h.Name)
		out[h.Name] = tarEntry{mode: h.Mode, typ: h.Typeflag, data: b}
		if h.ModTime.Unix() != 1793361600 || h.Uid != 0 || h.Gid != 0 {
			t.Fatalf("%s: mtime %v uid %d", h.Name, h.ModTime, h.Uid)
		}
	}
	return order, out
}

func TestIPK(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bin := write("openscale-linux-arm64", "ELF")
	initd := write("openscale.init", "#!/bin/sh /etc/rc.common\n")
	conf := write("openscale.config", "config openscale 'main'\n")
	control := write("control", "Package: openscale\nVersion: 0.9.1-1\nArchitecture: aarch64_generic\nMaintainer: OpenScale <root@localhost>\nDescription: OpenScale\n kişisel mesh VPN\n")
	conffiles := write("conffiles", "/etc/config/openscale\n")
	out1 := filepath.Join(dir, "a.ipk")
	args := func(out string, inputs ...string) []string {
		return append([]string{"-out", out, "-source-date-epoch", "1793361600", "-control", control, "-conffiles", conffiles,
			"-x", "usr/bin/openscale", "-x", "etc/init.d/openscale"}, inputs...)
	}
	in := []string{bin + "=usr/bin/openscale", initd + "=etc/init.d/openscale", conf + "=etc/config/openscale"}
	if err := run(args(out1, in...)); err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(dir, "b.ipk")
	if err := run(args(out2, in[2], in[0], in[1])); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(out1)
	b, _ := os.ReadFile(out2)
	if !bytes.Equal(a, b) {
		t.Fatal("ipk is not reproducible")
	}
	order, outer := readTarGz(t, a)
	if strings.Join(order, ",") != "./debian-binary,./control.tar.gz,./data.tar.gz" || string(outer["./debian-binary"].data) != "2.0\n" {
		t.Fatalf("outer %v", order)
	}
	_, ctrl := readTarGz(t, outer["./control.tar.gz"].data)
	if !strings.Contains(string(ctrl["./control"].data), "Package: openscale") || string(ctrl["./conffiles"].data) != "/etc/config/openscale\n" {
		t.Fatalf("control %v", ctrl)
	}
	_, data := readTarGz(t, outer["./data.tar.gz"].data)
	if data["./usr/bin/openscale"].mode != 0o755 || data["./etc/init.d/openscale"].mode != 0o755 || data["./etc/config/openscale"].mode != 0o644 {
		t.Fatalf("modes %v", data)
	}
	if data["./usr/bin/"].typ != tar.TypeDir || data["./"].typ != tar.TypeDir {
		t.Fatal("directory entries missing")
	}

	// Refusals: missing field, conffile not in the package, a prefix.
	bad := write("control-bad", "Package: openscale\nVersion: 1\n")
	if err := run([]string{"-out", filepath.Join(dir, "c.ipk"), "-source-date-epoch", "0", "-control", bad, in[0]}); err == nil {
		t.Fatal("incomplete control accepted")
	}
	wrong := write("conffiles-bad", "/etc/config/baska\n")
	if err := run([]string{"-out", filepath.Join(dir, "d.ipk"), "-source-date-epoch", "0", "-control", control, "-conffiles", wrong, in[0]}); err == nil {
		t.Fatal("foreign conffile accepted")
	}
	if err := run([]string{"-out", filepath.Join(dir, "e.ipk"), "-prefix", "x", "-source-date-epoch", "0", "-control", control, in[0]}); err == nil {
		t.Fatal("prefix accepted")
	}
}

func TestCheckControlName(t *testing.T) {
	if err := checkControl([]byte("Package: OpenScale\nVersion: 1\nArchitecture: all\nMaintainer: x\nDescription: y\n")); err == nil {
		t.Fatal("upper case package name accepted")
	}
}
