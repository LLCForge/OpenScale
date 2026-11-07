// Command pkgdeb builds the OpenScale Debian package in pure Go (F-163):
// an ar archive holding debian-binary, control.tar.gz and data.tar.gz.
// Output is reproducible: every timestamp is SOURCE_DATE_EPOCH, owners are
// root and entries are sorted.
//
//	go run ./cmd/pkgdeb -version 0.9.0 -arch arm64 -binary bin/openscale-linux-arm64 \
//	    -deploy deploy/linux -source-date-epoch N -out dist/openscale_0.9.0_arm64.deb \
//	    [-verifier bin/openscale-release-verify-linux-arm64] [-root-pub build/release/root.pub]
//
// The package installs the program and both systemd units but never enables
// or starts them: a coordinator or device must join the network first.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5" // #nosec G501 -- dpkg's md5sums format; integrity is provided by the signed release manifest
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	packageName      = "openscale"
	installedBinary  = "/usr/bin/openscale"
	legacyBinary     = "/usr/local/bin/openscale"
	unitDir          = "usr/lib/systemd/system"
	docDir           = "usr/share/doc/openscale"
	rootPubConffile  = "etc/openscale/release-root.pub"
	maxInputFileSize = 512 << 20
)

// debArch maps GOARCH (and GOARM) to Debian architecture names.
var debArch = map[string]string{"amd64": "amd64", "arm64": "arm64", "armhf": "armhf", "arm": "armhf", "armv7": "armhf"}

var (
	debVersionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~-]{0,63}$`)
	maintainerRe = regexp.MustCompile(`^[^<>\n]{1,80} <[^<>@\s]{1,64}@[^<>@\s]{1,128}>$`)
)

type entry struct {
	name string // without leading "./"
	mode int64
	data []byte
	dir  bool
}

type options struct {
	version, arch, binary, verifier, deploy, rootPub, out, maintainer string
	sde                                                               int64
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pkgdeb:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	o := options{}
	fs := flag.NewFlagSet("pkgdeb", flag.ContinueOnError)
	fs.StringVar(&o.version, "version", "", "paket sürümü, ör. 0.9.0")
	fs.StringVar(&o.arch, "arch", "", "amd64, arm64 veya armhf")
	fs.StringVar(&o.binary, "binary", "", "linux openscale ikilisi")
	fs.StringVar(&o.verifier, "verifier", "", "openscale-release-verify ikilisi (isteğe bağlı)")
	fs.StringVar(&o.deploy, "deploy", "deploy/linux", "deploy/linux klasörü (birimler ve deb/ betikleri)")
	fs.StringVar(&o.rootPub, "root-pub", "", "sürüm kök açık anahtarı; /etc/openscale/release-root.pub olarak kurulur (isteğe bağlı)")
	fs.StringVar(&o.out, "out", "", "çıktı .deb dosyası")
	fs.StringVar(&o.maintainer, "maintainer", "OpenScale <root@localhost>", "Maintainer alanı: \"Ad <adres>\"")
	fs.Int64Var(&o.sde, "source-date-epoch", -1, "SOURCE_DATE_EPOCH")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.version == "" || o.arch == "" || o.binary == "" || o.out == "" || o.sde < 0 || fs.NArg() != 0 {
		return errors.New("-version, -arch, -binary, -source-date-epoch ve -out gerekli")
	}
	data, err := build(o)
	if err != nil {
		return err
	}
	return os.WriteFile(o.out, data, 0o644)
}

func build(o options) ([]byte, error) {
	arch, ok := debArch[o.arch]
	if !ok {
		return nil, fmt.Errorf("desteklenmeyen mimari %q", o.arch)
	}
	if !debVersionRe.MatchString(o.version) {
		return nil, fmt.Errorf("geçersiz paket sürümü %q", o.version)
	}
	if !maintainerRe.MatchString(o.maintainer) {
		return nil, fmt.Errorf("Maintainer \"Ad <adres>\" biçiminde olmalı: %q", o.maintainer)
	}
	mtime := time.Unix(o.sde, 0).UTC()

	var files []entry
	add := func(name string, mode int64, data []byte) {
		files = append(files, entry{name: name, mode: mode, data: data})
	}
	bin, err := readFile(o.binary)
	if err != nil {
		return nil, err
	}
	add(strings.TrimPrefix(installedBinary, "/"), 0o755, bin)
	if o.verifier != "" {
		v, err := readFile(o.verifier)
		if err != nil {
			return nil, err
		}
		add("usr/bin/openscale-release-verify", 0o755, v)
	}
	for _, u := range []string{"openscale-coordinator.service", "openscale-device.service", "openscale-wait-online.service",
		// ADR-0225: automatic update installer and release source sync.
		"openscale-autoupdate.service", "openscale-autoupdate.path", "openscale-release-sync.service", "openscale-release-sync.timer"} {
		d, err := readFile(filepath.Join(o.deploy, u))
		if err != nil {
			return nil, err
		}
		// The units in deploy/linux serve the manual install under
		// /usr/local; a package installs to /usr/bin (Debian policy).
		d = bytes.ReplaceAll(toLF(d), []byte(legacyBinary+" "), []byte(installedBinary+" "))
		if bytes.Contains(d, []byte(legacyBinary)) {
			return nil, fmt.Errorf("%s: %s yolu değiştirilemedi", u, legacyBinary)
		}
		add(unitDir+"/"+u, 0o644, d)
	}
	// Hardening examples only: they change the firewall, SSH and automatic
	// reboots, so the administrator copies them deliberately.
	// The network manager files (F-150) are written by "openscale service
	// install" when those managers are present; here they are examples.
	for _, ex := range []string{"nftables.conf", "sshd-openscale.conf", "50-openscale-upgrades.conf",
		"50-openscale-networkd.conf", "50-openscale.network", "50-openscale-networkmanager.conf"} {
		d, err := readFile(filepath.Join(o.deploy, ex))
		if err != nil {
			return nil, err
		}
		add(docDir+"/examples/"+ex, 0o644, d)
	}
	var conffiles []string
	if o.rootPub != "" {
		d, err := readFile(o.rootPub)
		if err != nil {
			return nil, err
		}
		add(rootPubConffile, 0o644, d)
		conffiles = append(conffiles, "/"+rootPubConffile)
	}
	data := withDirs(files)

	installedKiB := int64(0)
	for _, e := range data {
		installedKiB += (int64(len(e.data)) + 1023) / 1024
		if e.dir {
			installedKiB++
		}
	}
	control := fmt.Sprintf(`Package: %s
Version: %s
Architecture: %s
Maintainer: %s
Installed-Size: %d
Recommends: nftables
Section: net
Priority: optional
Description: OpenScale personal WireGuard mesh VPN
 Coordinator and device for a single-owner, cloud-free WireGuard mesh.
 The package installs the program and the systemd units but does not
 enable or start them; join the network first (docs/sunucu-kurulumu.md).
`, packageName, o.version, arch, o.maintainer, installedKiB)

	var md5sums strings.Builder
	for _, e := range data {
		if e.dir {
			continue
		}
		sum := md5.Sum(e.data) // #nosec G401 -- dpkg md5sums, not a security control
		fmt.Fprintf(&md5sums, "%s  %s\n", hex.EncodeToString(sum[:]), e.name)
	}
	ctrl := []entry{
		{name: "control", mode: 0o644, data: []byte(control)},
		{name: "md5sums", mode: 0o644, data: []byte(md5sums.String())},
	}
	if len(conffiles) > 0 {
		ctrl = append(ctrl, entry{name: "conffiles", mode: 0o644, data: []byte(strings.Join(conffiles, "\n") + "\n")})
	}
	for _, s := range []string{"postinst", "prerm", "postrm"} {
		d, err := readFile(filepath.Join(o.deploy, "deb", s))
		if err != nil {
			return nil, err
		}
		// A Windows checkout may have CRLF line endings; /bin/sh would then
		// fail on "set -e\r".
		ctrl = append(ctrl, entry{name: s, mode: 0o755, data: toLF(d)})
	}

	controlTar, err := tarGz(ctrl, mtime, true)
	if err != nil {
		return nil, err
	}
	dataTar, err := tarGz(data, mtime, true)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	for _, m := range []struct {
		name string
		data []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", controlTar},
		{"data.tar.gz", dataTar},
	} {
		if err := writeArMember(&out, m.name, m.data, o.sde); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

// withDirs adds every parent directory and sorts the entries.
func withDirs(files []entry) []entry {
	dirs := map[string]bool{}
	for _, f := range files {
		for d := path.Dir(f.name); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	out := slices.Clone(files)
	for d := range dirs {
		out = append(out, entry{name: d, mode: 0o755, dir: true})
	}
	slices.SortFunc(out, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	return out
}

// tarGz writes a reproducible gzip-compressed tar with "./" prefixed names.
func tarGz(entries []entry, mtime time.Time, rootDir bool) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	hdr := func(name string, mode int64, size int64, typ byte) *tar.Header {
		return &tar.Header{
			Typeflag: typ, Name: name, Mode: mode, Size: size, ModTime: mtime,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root", Format: tar.FormatGNU,
		}
	}
	if rootDir {
		if err := tw.WriteHeader(hdr("./", 0o755, 0, tar.TypeDir)); err != nil {
			return nil, err
		}
	}
	for _, e := range entries {
		if e.dir {
			if err := tw.WriteHeader(hdr("./"+e.name+"/", e.mode, 0, tar.TypeDir)); err != nil {
				return nil, err
			}
			continue
		}
		if err := tw.WriteHeader(hdr("./"+e.name, e.mode, int64(len(e.data)), tar.TypeReg)); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
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

// writeArMember writes one member of a common-format ar archive.
func writeArMember(w io.Writer, name string, data []byte, mtime int64) error {
	if len(name) > 16 {
		return fmt.Errorf("ar member name %q is too long", name)
	}
	h := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", name, strconv.FormatInt(mtime, 10), "0", "0", "100644", strconv.Itoa(len(data)))
	if len(h) != 60 {
		return errors.New("ar header overflow")
	}
	if _, err := io.WriteString(w, h); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if len(data)%2 == 1 {
		_, err := w.Write([]byte{'\n'})
		return err
	}
	return nil
}

func toLF(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

func readFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInputFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputFileSize {
		return nil, fmt.Errorf("%s çok büyük", p)
	}
	return data, nil
}
