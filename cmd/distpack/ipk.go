package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OpenWrt package (#446, ADR-0162). An .ipk is a gzip-compressed tar
// holding "./debian-binary", "./control.tar.gz" and "./data.tar.gz", in
// that order. distpack writes it like the other archives: sorted entries,
// root owner, SOURCE_DATE_EPOCH everywhere, so the package is reproducible
// and can be listed in the signed release manifest (ADR-0022) like every
// other file. No OpenWrt SDK is needed for a prebuilt Go binary.

// ipkMeta holds the control archive's files.
type ipkMeta struct {
	control   []byte
	conffiles []byte
	postinst  []byte
	prerm     []byte
}

// maxControl bounds the control file.
const maxControl = 64 << 10

// requiredControlFields must appear in the control file.
var requiredControlFields = []string{"Package", "Version", "Architecture", "Maintainer", "Description"}

// checkControl validates an opkg control file: required fields, no empty
// lines inside, ASCII field names, and a package name opkg accepts.
func checkControl(data []byte) error {
	if len(data) == 0 || len(data) > maxControl {
		return errors.New("control dosyası boş veya çok büyük")
	}
	text := strings.TrimRight(string(data), "\n")
	seen := map[string]string{}
	for i, line := range strings.Split(text, "\n") {
		if line == "" {
			return fmt.Errorf("control: %d. satır boş", i+1)
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of Description
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return fmt.Errorf("control: %d. satır alan değil: %q", i+1, line)
		}
		seen[k] = strings.TrimSpace(v)
	}
	for _, f := range requiredControlFields {
		if seen[f] == "" {
			return fmt.Errorf("control: %s alanı eksik", f)
		}
	}
	for _, r := range seen["Package"] {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '+' || r == '.') {
			return fmt.Errorf("control: paket adı %q geçersiz", seen["Package"])
		}
	}
	return nil
}

// checkConffiles accepts absolute paths that are part of the package.
func checkConffiles(data []byte, files []file) error {
	names := map[string]bool{}
	for _, f := range files {
		names["/"+f.name] = true
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !names[line] {
			return fmt.Errorf("conffiles: %s pakette yok", line)
		}
	}
	return nil
}

func writeIPK(files []file, meta ipkMeta, mtime time.Time) ([]byte, error) {
	if err := checkControl(meta.control); err != nil {
		return nil, err
	}
	if len(meta.conffiles) > 0 {
		if err := checkConffiles(meta.conffiles, files); err != nil {
			return nil, err
		}
	}
	ctrl := []file{{name: "control", mode: 0o644, data: ensureNewline(meta.control)}}
	if len(meta.conffiles) > 0 {
		ctrl = append(ctrl, file{name: "conffiles", mode: 0o644, data: ensureNewline(meta.conffiles)})
	}
	if len(meta.postinst) > 0 {
		ctrl = append(ctrl, file{name: "postinst", mode: 0o755, data: meta.postinst})
	}
	if len(meta.prerm) > 0 {
		ctrl = append(ctrl, file{name: "prerm", mode: 0o755, data: meta.prerm})
	}
	controlTar, err := ipkTarGz(ctrl, mtime, true)
	if err != nil {
		return nil, err
	}
	dataTar, err := ipkTarGz(files, mtime, true)
	if err != nil {
		return nil, err
	}
	outer := []file{
		{name: "debian-binary", mode: 0o644, data: []byte("2.0\n")},
		{name: "control.tar.gz", mode: 0o644, data: controlTar},
		{name: "data.tar.gz", mode: 0o644, data: dataTar},
	}
	// The order is part of the format; ipkTarGz keeps the given order.
	return ipkTarGz(outer, mtime, false)
}

func ensureNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] != '\n' {
		return append(bytes.Clone(b), '\n')
	}
	return b
}

// ipkTarGz writes files as "./name" entries with "./dir/" entries for
// every directory, as OpenWrt's ipkg-build does; withDirs is false for
// the outer archive, which has no directories.
func ipkTarGz(files []file, mtime time.Time, withDirs bool) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	hdr := func(typ byte, name string, mode, size int64) *tar.Header {
		// GNU format with numeric root owner: busybox tar on OpenWrt reads it.
		return &tar.Header{Typeflag: typ, Name: name, Mode: mode, Size: size, ModTime: mtime,
			Uname: "root", Gname: "root", Format: tar.FormatGNU}
	}
	if withDirs {
		if err := tw.WriteHeader(hdr(tar.TypeDir, "./", 0o755, 0)); err != nil {
			return nil, err
		}
		for _, d := range dirsOf(files, "") {
			if err := tw.WriteHeader(hdr(tar.TypeDir, "./"+d+"/", 0o755, 0)); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range files {
		if err := tw.WriteHeader(hdr(tar.TypeReg, "./"+f.name, f.mode, int64(len(f.data)))); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
