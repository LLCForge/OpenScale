package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeInputs(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"openscale-linux-arm64": "bin", "install-device.sh": "#!/bin/sh\n", "unit.service": "[Unit]\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, []string{
		filepath.Join(dir, "unit.service"),
		filepath.Join(dir, "install-device.sh"),
		filepath.Join(dir, "openscale-linux-arm64"),
	}
}

func TestTarGzReproducible(t *testing.T) {
	dir, inputs := writeInputs(t)
	out1, out2 := filepath.Join(dir, "a.tar.gz"), filepath.Join(dir, "b.tar.gz")
	base := []string{"-prefix", "openscale-0.9.0-linux-arm64", "-source-date-epoch", "1793361600", "-x", "openscale-linux-arm64"}
	if err := run(append(append([]string{"-out", out1}, base...), inputs...)); err != nil {
		t.Fatal(err)
	}
	// Different argument order, same archive.
	rev := []string{inputs[2], inputs[0], inputs[1]}
	if err := run(append(append([]string{"-out", out2}, base...), rev...)); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(out1)
	b, _ := os.ReadFile(out2)
	if !bytes.Equal(a, b) {
		t.Fatal("archive is not reproducible")
	}
	gz, err := gzip.NewReader(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modes[h.Name] = h.Mode
		if h.ModTime.Unix() != 1793361600 {
			t.Fatalf("%s mtime %v", h.Name, h.ModTime)
		}
	}
	if modes["openscale-0.9.0-linux-arm64/openscale-linux-arm64"] != 0o755 ||
		modes["openscale-0.9.0-linux-arm64/install-device.sh"] != 0o755 ||
		modes["openscale-0.9.0-linux-arm64/unit.service"] != 0o644 {
		t.Fatalf("modes: %v", modes)
	}
}

func TestZip(t *testing.T) {
	dir, inputs := writeInputs(t)
	out := filepath.Join(dir, "a.zip")
	if err := run(append([]string{"-out", out, "-source-date-epoch", "1793361600"}, inputs...)); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 3 || zr.File[0].Name != "install-device.sh" {
		t.Fatalf("entries: %v", zr.File)
	}
}

func TestRejectsUnsafeNames(t *testing.T) {
	dir, inputs := writeInputs(t)
	for _, bad := range []string{"../x", "/abs", "a/../../b", `c:\x`} {
		if err := run([]string{"-out", filepath.Join(dir, "x.zip"), "-source-date-epoch", "0", inputs[0] + "=" + bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
