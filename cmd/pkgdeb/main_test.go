package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type arMember struct {
	name  string
	mtime int64
	data  []byte
}

func readAr(t *testing.T, data []byte) []arMember {
	t.Helper()
	if !bytes.HasPrefix(data, []byte("!<arch>\n")) {
		t.Fatal("missing ar magic")
	}
	data = data[8:]
	var out []arMember
	for len(data) > 0 {
		if len(data) < 60 || string(data[58:60]) != "`\n" {
			t.Fatal("bad ar header")
		}
		h := data[:60]
		size, err := strconv.Atoi(strings.TrimSpace(string(h[48:58])))
		if err != nil {
			t.Fatal(err)
		}
		mtime, _ := strconv.ParseInt(strings.TrimSpace(string(h[16:28])), 10, 64)
		out = append(out, arMember{strings.TrimSpace(string(h[:16])), mtime, data[60 : 60+size]})
		data = data[60+size+size%2:]
	}
	return out
}

func readTarGz(t *testing.T, data []byte) map[string]*tar.Header {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			h.PAXRecords = map[string]string{"content": string(b)}
		}
		out[h.Name] = h
	}
	return out
}

func setup(t *testing.T) options {
	t.Helper()
	dir := t.TempDir()
	deploy := filepath.Join("..", "..", "deploy", "linux")
	if _, err := os.Stat(filepath.Join(deploy, "deb", "postinst")); err != nil {
		t.Skip("deploy/linux not present")
	}
	bin := filepath.Join(dir, "openscale-linux-arm64")
	if err := os.WriteFile(bin, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "root.pub")
	if err := os.WriteFile(pub, []byte("osrelkey1:test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return options{version: "0.9.0", arch: "arm64", binary: bin, deploy: deploy, rootPub: pub,
		out: filepath.Join(dir, "x.deb"), maintainer: "OpenScale <root@localhost>", sde: 1793361600}
}

func TestBuildDeb(t *testing.T) {
	o := setup(t)
	a, err := build(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := build(o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("package is not reproducible")
	}
	members := readAr(t, a)
	if len(members) != 3 || members[0].name != "debian-binary" || string(members[0].data) != "2.0\n" ||
		members[1].name != "control.tar.gz" || members[2].name != "data.tar.gz" {
		t.Fatalf("unexpected members: %v", members)
	}
	for _, m := range members {
		if m.mtime != o.sde {
			t.Fatal("ar mtime is not SOURCE_DATE_EPOCH")
		}
	}
	ctrl := readTarGz(t, members[1].data)
	control := ctrl["./control"].PAXRecords["content"]
	for _, want := range []string{"Package: openscale\n", "Version: 0.9.0\n", "Architecture: arm64\n", "Maintainer: OpenScale <root@localhost>\n"} {
		if !strings.Contains(control, want) {
			t.Errorf("control lacks %q", want)
		}
	}
	if ctrl["./postinst"].Mode != 0o755 || strings.Contains(ctrl["./postinst"].PAXRecords["content"], "\r") {
		t.Error("postinst must be executable with LF line endings")
	}
	if got := ctrl["./conffiles"].PAXRecords["content"]; got != "/etc/openscale/release-root.pub\n" {
		t.Errorf("conffiles = %q", got)
	}
	data := readTarGz(t, members[2].data)
	if h := data["./usr/bin/openscale"]; h == nil || h.Mode != 0o755 || h.Uname != "root" || h.ModTime.Unix() != o.sde {
		t.Fatal("binary entry wrong")
	}
	unit := data["./usr/lib/systemd/system/openscale-coordinator.service"]
	if unit == nil || !strings.Contains(unit.PAXRecords["content"], "ExecStart=/usr/bin/openscale coordinator run") ||
		strings.Contains(unit.PAXRecords["content"], "/usr/local/bin") {
		t.Fatal("coordinator unit path not rewritten")
	}
	if data["./usr/lib/systemd/system/"] == nil || data["./"] == nil {
		t.Fatal("parent directories missing")
	}
	if !strings.Contains(ctrl["./md5sums"].PAXRecords["content"], "  usr/bin/openscale\n") {
		t.Fatal("md5sums missing binary")
	}
}

func TestBuildDebRejectsBadInput(t *testing.T) {
	o := setup(t)
	bad := o
	bad.arch = "mips"
	if _, err := build(bad); err == nil {
		t.Error("unknown arch accepted")
	}
	bad = o
	bad.version = "../1"
	if _, err := build(bad); err == nil {
		t.Error("bad version accepted")
	}
	bad = o
	bad.maintainer = "nobody"
	if _, err := build(bad); err == nil {
		t.Error("bad maintainer accepted")
	}
	o.arch = "armhf"
	if _, err := build(o); err != nil {
		t.Fatal(err)
	}
}
