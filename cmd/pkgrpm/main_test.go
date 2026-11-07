package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"  // #nosec G501 -- checks the legacy rpm digest
	"crypto/sha1" // #nosec G505 -- checks the legacy rpm digest
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// parsedHeader is a header read back with the checks rpm applies in
// hdrblobVerifyRegion and hdrblobVerifyInfo.
type parsedHeader struct {
	raw     []byte
	entries map[int32]parsedEntry
}

type parsedEntry struct {
	typ, count int32
	data       []byte // from offset to the end of the store
}

func parseHeader(t *testing.T, b []byte, regionTag int32) (parsedHeader, int) {
	t.Helper()
	if len(b) < 16 || !bytes.Equal(b[:8], headerMagic) {
		t.Fatal("bad header magic")
	}
	il := int(binary.BigEndian.Uint32(b[8:]))
	dl := int(binary.BigEndian.Uint32(b[12:]))
	end := 16 + il*16 + dl
	if len(b) < end {
		t.Fatal("header truncated")
	}
	index := b[16 : 16+il*16]
	store := b[16+il*16 : end]
	ent := func(i int) (int32, int32, int32, int32) {
		e := index[i*16:]
		return int32(binary.BigEndian.Uint32(e)), int32(binary.BigEndian.Uint32(e[4:])),
			int32(binary.BigEndian.Uint32(e[8:])), int32(binary.BigEndian.Uint32(e[12:]))
	}
	// Region: first entry, trailer at the end of the store.
	tag, typ, off, count := ent(0)
	if tag != regionTag || typ != typeBin || count != 16 || int(off)+16 != dl {
		t.Fatalf("region entry %d %d %d %d (dl %d)", tag, typ, off, count, dl)
	}
	tr := store[off:]
	if int32(binary.BigEndian.Uint32(tr)) != regionTag || binary.BigEndian.Uint32(tr[4:]) != typeBin ||
		-int32(binary.BigEndian.Uint32(tr[8:])) != int32(il*16) || binary.BigEndian.Uint32(tr[12:]) != 16 {
		t.Fatal("bad region trailer")
	}
	out := parsedHeader{raw: b[:end], entries: map[int32]parsedEntry{}}
	prevEnd, prevTag := int32(0), int32(-1)
	for i := 1; i < il; i++ {
		tag, typ, off, count := ent(i)
		if tag <= prevTag {
			t.Fatalf("tags not sorted: %d after %d", tag, prevTag)
		}
		prevTag = tag
		if off < prevEnd {
			t.Fatalf("tag %d overlaps previous data", tag)
		}
		switch typ {
		case typeInt16:
			if off%2 != 0 {
				t.Fatalf("tag %d misaligned", tag)
			}
		case typeInt32:
			if off%4 != 0 {
				t.Fatalf("tag %d misaligned", tag)
			}
		}
		var n int32
		switch typ {
		case typeInt16:
			n = 2 * count
		case typeInt32:
			n = 4 * count
		case typeBin:
			n = count
		case typeString, typeStringArray, typeI18NString:
			p := off
			for c := int32(0); c < count; c++ {
				z := bytes.IndexByte(store[p:], 0)
				if z < 0 {
					t.Fatalf("tag %d unterminated", tag)
				}
				p += int32(z) + 1
			}
			n = p - off
			if typ == typeString && count != 1 {
				t.Fatalf("string tag %d count %d", tag, count)
			}
		default:
			t.Fatalf("tag %d unexpected type %d", tag, typ)
		}
		if off+n > int32(dl)-16 {
			t.Fatalf("tag %d overlaps region trailer", tag)
		}
		prevEnd = off + n
		out.entries[tag] = parsedEntry{typ: typ, count: count, data: store[off:]}
	}
	return out, end
}

func (h parsedHeader) strings(t *testing.T, tag int32) []string {
	t.Helper()
	e, ok := h.entries[tag]
	if !ok {
		t.Fatalf("tag %d missing", tag)
	}
	parts := strings.SplitN(string(e.data), "\x00", int(e.count)+1)
	return parts[:e.count]
}

func (h parsedHeader) ints(t *testing.T, tag int32) []int64 {
	t.Helper()
	e, ok := h.entries[tag]
	if !ok {
		t.Fatalf("tag %d missing", tag)
	}
	var out []int64
	for i := int32(0); i < e.count; i++ {
		switch e.typ {
		case typeInt32:
			out = append(out, int64(int32(binary.BigEndian.Uint32(e.data[4*i:]))))
		case typeInt16:
			out = append(out, int64(binary.BigEndian.Uint16(e.data[2*i:])))
		default:
			t.Fatalf("tag %d is not an integer", tag)
		}
	}
	return out
}

type cpioFile struct {
	ino, mode, mtime int64
	data             []byte
}

func readCpio(t *testing.T, b []byte) ([]string, map[string]cpioFile) {
	t.Helper()
	var names []string
	files := map[string]cpioFile{}
	p := 0
	hexField := func(i int) int64 {
		v, err := strconv.ParseInt(string(b[p+6+8*i:p+14+8*i]), 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for {
		if string(b[p:p+6]) != "070701" {
			t.Fatalf("bad cpio magic at %d", p)
		}
		ino, mode, mtime, size, nameSize := hexField(0), hexField(1), hexField(5), hexField(6), hexField(11)
		name := string(b[p+110 : p+110+int(nameSize)-1])
		p += 110 + int(nameSize)
		p = (p + 3) &^ 3
		if name == "TRAILER!!!" {
			return names, files
		}
		names = append(names, name)
		files[name] = cpioFile{ino: ino, mode: mode, mtime: mtime, data: b[p : p+int(size)]}
		p += int(size)
		p = (p + 3) &^ 3
	}
}

func setup(t *testing.T) options {
	t.Helper()
	dir := t.TempDir()
	deploy := filepath.Join("..", "..", "deploy", "linux")
	if _, err := os.Stat(filepath.Join(deploy, "rpm", "post")); err != nil {
		t.Skip("deploy/linux not present")
	}
	bin := filepath.Join(dir, "openscale-linux-amd64")
	if err := os.WriteFile(bin, []byte("binary!"), 0o644); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "root.pub")
	if err := os.WriteFile(pub, []byte("osrelkey1:test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return options{version: "0.9.0", release: "1", arch: "amd64", binary: bin, deploy: deploy, rootPub: pub,
		out: filepath.Join(dir, "x.rpm"), packager: "OpenScale <root@localhost>", sde: 1793361600}
}

func TestBuildRPM(t *testing.T) {
	o := setup(t)
	pkg, err := build(o)
	if err != nil {
		t.Fatal(err)
	}
	again, err := build(o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkg, again) {
		t.Fatal("package is not reproducible")
	}

	// Lead.
	if !bytes.Equal(pkg[:4], []byte{0xed, 0xab, 0xee, 0xdb}) || pkg[4] != 3 ||
		!bytes.HasPrefix(pkg[10:], []byte("openscale-0.9.0-1\x00")) || binary.BigEndian.Uint16(pkg[78:]) != 5 {
		t.Fatal("bad lead")
	}
	sig, n := parseHeader(t, pkg[96:], tagHeaderSignatures)
	rest := pkg[96+n:]
	pad := (8 - n%8) % 8
	if !bytes.Equal(rest[:pad], make([]byte, pad)) {
		t.Fatal("signature padding not zero")
	}
	rest = rest[pad:]
	hdr, hn := parseHeader(t, rest, tagHeaderImmutable)
	payload := rest[hn:]

	// Signature digests.
	s256 := sha256.Sum256(hdr.raw)
	s1 := sha1.Sum(hdr.raw) // #nosec G401
	if got := sig.strings(t, sigSHA256)[0]; got != hex.EncodeToString(s256[:]) {
		t.Fatal("header SHA-256 mismatch")
	}
	if got := sig.strings(t, sigSHA1)[0]; got != hex.EncodeToString(s1[:]) {
		t.Fatal("header SHA-1 mismatch")
	}
	md := md5.Sum(append(append([]byte{}, hdr.raw...), payload...)) // #nosec G401
	if e := sig.entries[sigMD5]; e.count != 16 || !bytes.Equal(e.data[:16], md[:]) {
		t.Fatal("MD5 mismatch")
	}
	if got := sig.ints(t, sigSize)[0]; got != int64(len(hdr.raw)+len(payload)) {
		t.Fatalf("size %d", got)
	}
	ps := sha256.Sum256(payload)
	if got := hdr.strings(t, tagPayloadDigest)[0]; got != hex.EncodeToString(ps[:]) {
		t.Fatal("payload digest mismatch")
	}

	// Package identity.
	for tag, want := range map[int32]string{tagName: "openscale", tagVersion: "0.9.0", tagRelease: "1",
		tagArch: "x86_64", tagOS: "linux", tagSourceRPM: "openscale-0.9.0-1.src.rpm",
		tagPayloadFormat: "cpio", tagPayloadCompressor: "gzip"} {
		if got := hdr.strings(t, tag)[0]; got != want {
			t.Errorf("tag %d = %q, want %q", tag, got, want)
		}
	}
	if !strings.Contains(hdr.strings(t, tagPostIn)[0], "systemctl daemon-reload") ||
		strings.Contains(hdr.strings(t, tagPostIn)[0], "\r") {
		t.Error("post script missing or has CR")
	}
	if strings.Contains(hdr.strings(t, tagPostIn)[0], "enable --now openscale") &&
		!strings.Contains(hdr.strings(t, tagPostIn)[0], "Sonra: systemctl enable --now") {
		t.Error("post script must never enable a unit")
	}

	// File list against the payload.
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if got := sig.ints(t, sigPayloadSize)[0]; got != int64(len(raw)) {
		t.Fatalf("payload size %d != %d", got, len(raw))
	}
	names, files := readCpio(t, raw)
	dirs := hdr.strings(t, tagDirNames)
	bases := hdr.strings(t, tagBaseNames)
	idx := hdr.ints(t, tagDirIndexes)
	digests := hdr.strings(t, tagFileDigests)
	modes := hdr.ints(t, tagFileModes)
	sizes := hdr.ints(t, tagFileSizes)
	flags := hdr.ints(t, tagFileFlags)
	if len(bases) != len(names) || len(digests) != len(names) || len(modes) != len(names) || len(flags) != len(names) {
		t.Fatalf("file list lengths differ: %d names", len(names))
	}
	paths := map[string]int{}
	for i := range bases {
		full := dirs[idx[i]] + bases[i]
		paths[full] = i
		if names[i] != "."+full {
			t.Fatalf("payload order %q != header %q", names[i], full)
		}
		f := files[names[i]]
		if f.mode != modes[i] || f.mtime != o.sde || int64(len(f.data)) != sizes[i] {
			t.Fatalf("%s: metadata mismatch", full)
		}
		if modes[i]&0o170000 == 0o100000 {
			s := sha256.Sum256(f.data)
			if digests[i] != hex.EncodeToString(s[:]) {
				t.Fatalf("%s: digest mismatch", full)
			}
		}
	}
	for _, p := range []string{"/usr/bin/openscale", "/usr/lib/systemd/system/openscale-device.service",
		"/etc/openscale/release-root.pub", "/usr/share/doc/openscale/examples/nftables.conf", "/etc/openscale"} {
		if _, ok := paths[p]; !ok {
			t.Errorf("%s missing", p)
		}
	}
	for _, p := range []string{"/usr/bin", "/usr/lib/systemd/system", "/etc"} {
		if _, ok := paths[p]; ok {
			t.Errorf("shared directory %s must not be owned", p)
		}
	}
	if modes[paths["/usr/bin/openscale"]] != 0o100755 {
		t.Error("binary not executable")
	}
	if flags[paths["/etc/openscale/release-root.pub"]] != fileConfig|fileNoReplace {
		t.Error("root key is not config(noreplace)")
	}
	if flags[paths["/usr/share/doc/openscale/examples/nftables.conf"]] != fileDoc {
		t.Error("example is not doc")
	}
	unit := string(files["./usr/lib/systemd/system/openscale-coordinator.service"].data)
	if !strings.Contains(unit, "ExecStart=/usr/bin/openscale coordinator run") || strings.Contains(unit, "/usr/local/bin") {
		t.Fatal("coordinator unit path not rewritten")
	}
}

func TestBuildRPMRejects(t *testing.T) {
	o := setup(t)
	for name, mutate := range map[string]func(*options){
		"dash in version": func(o *options) { o.version = "0.9.0-rc1" },
		"bad release":     func(o *options) { o.release = "a" },
		"arch":            func(o *options) { o.arch = "riscv64" },
		"packager":        func(o *options) { o.packager = "x" },
		"y2038":           func(o *options) { o.sde = 1 << 31 },
	} {
		c := o
		mutate(&c)
		if _, err := build(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := o
	c.arch = "armhf"
	pkg, err := build(c)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(pkg[8:]) != 12 {
		t.Error("armhf lead arch")
	}
}
