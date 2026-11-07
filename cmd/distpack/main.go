// Command distpack writes reproducible release archives (.tar.gz, .zip or
// an OpenWrt .ipk package)
// without depending on the host's tar or zip: entries are sorted, owners are
// root, and every timestamp is SOURCE_DATE_EPOCH.
//
//	go run ./cmd/distpack -out dist/openscale-0.9.0-linux-arm64.tar.gz \
//	    -prefix openscale-0.9.0-linux-arm64 -source-date-epoch N \
//	    -x openscale-linux-arm64 bin/openscale-linux-arm64 deploy/linux/install-device.sh=install-device.sh ...
//
// Each argument is SOURCE or SOURCE=NAME (NAME is the path inside the
// archive, under -prefix). Names ending in .sh or .exe and names given with
// -x are stored as executable (0755); everything else is 0644.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const maxFileSize = 512 << 20

type file struct {
	name string
	mode int64
	data []byte
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "distpack:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("distpack", flag.ContinueOnError)
	out := fs.String("out", "", "çıktı arşivi (.tar.gz, .zip veya .ipk)")
	prefix := fs.String("prefix", "", "arşivdeki üst klasör (isteğe bağlı)")
	sde := fs.Int64("source-date-epoch", -1, "SOURCE_DATE_EPOCH")
	var execs multiFlag
	fs.Var(&execs, "x", "çalıştırılabilir olarak saklanacak ad (tekrarlanabilir)")
	// OpenWrt package (.ipk, #446): control archive files.
	controlFile := fs.String("control", "", ".ipk: opkg control dosyası")
	conffilesFile := fs.String("conffiles", "", ".ipk: yükseltmede korunacak yapılandırma dosyalarının listesi")
	postinstFile := fs.String("postinst", "", ".ipk: kurulum sonrası betik")
	prermFile := fs.String("prerm", "", ".ipk: kaldırma öncesi betik")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *sde < 0 || fs.NArg() == 0 {
		return errors.New("-out, -source-date-epoch ve en az bir dosya gerekli")
	}
	if *prefix != "" && !validName(*prefix) {
		return fmt.Errorf("geçersiz önek %q", *prefix)
	}
	var files []file
	seen := map[string]bool{}
	for _, a := range fs.Args() {
		src, name, ok := strings.Cut(a, "=")
		if !ok {
			name = filepath.Base(src)
		}
		name = path.Clean(filepath.ToSlash(name))
		if !validName(name) {
			return fmt.Errorf("geçersiz arşiv adı %q", name)
		}
		if seen[name] {
			return fmt.Errorf("%s iki kez verildi", name)
		}
		seen[name] = true
		data, err := readFile(src)
		if err != nil {
			return err
		}
		mode := int64(0o644)
		if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".exe") || slices.Contains(execs, name) {
			mode = 0o755
		}
		files = append(files, file{name: name, mode: mode, data: data})
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.name, b.name) })
	mtime := time.Unix(*sde, 0).UTC()

	var data []byte
	var err error
	switch {
	case strings.HasSuffix(*out, ".tar.gz"):
		data, err = writeTarGz(files, *prefix, mtime)
	case strings.HasSuffix(*out, ".zip"):
		data, err = writeZip(files, *prefix, mtime)
	case strings.HasSuffix(*out, ".ipk"):
		if *prefix != "" {
			return errors.New(".ipk ile -prefix kullanılmaz; adlar kurulum yoludur (usr/bin/openscale)")
		}
		var meta ipkMeta
		for _, m := range []struct {
			path string
			dst  *[]byte
		}{{*controlFile, &meta.control}, {*conffilesFile, &meta.conffiles}, {*postinstFile, &meta.postinst}, {*prermFile, &meta.prerm}} {
			if m.path == "" {
				continue
			}
			if *m.dst, err = readFile(m.path); err != nil {
				return err
			}
		}
		data, err = writeIPK(files, meta, mtime)
	default:
		return errors.New("-out .tar.gz, .zip veya .ipk ile bitmeli")
	}
	if err != nil {
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

// validName accepts relative slash-separated names without "..".
func validName(n string) bool {
	if n == "" || n == "." || strings.HasPrefix(n, "/") || strings.Contains(n, `\`) || strings.Contains(n, ":") {
		return false
	}
	for _, part := range strings.Split(n, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func dirsOf(files []file, prefix string) []string {
	set := map[string]bool{}
	if prefix != "" {
		set[prefix] = true
	}
	for _, f := range files {
		for d := path.Dir(join(prefix, f.name)); d != "."; d = path.Dir(d) {
			set[d] = true
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

func writeTarGz(files []file, prefix string, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, d := range dirsOf(files, prefix) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755, ModTime: mtime,
			Uname: "root", Gname: "root", Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: join(prefix, f.name), Mode: f.mode,
			Size: int64(len(f.data)), ModTime: mtime, Uname: "root", Gname: "root", Format: tar.FormatPAX}); err != nil {
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

func writeZip(files []file, prefix string, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, d := range dirsOf(files, prefix) {
		h := &zip.FileHeader{Name: d + "/", Method: zip.Store, Modified: mtime}
		h.SetMode(os.ModeDir | 0o755)
		if _, err := zw.CreateHeader(h); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		h := &zip.FileHeader{Name: join(prefix, f.name), Method: zip.Deflate, Modified: mtime}
		h.SetMode(os.FileMode(f.mode))
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s normal bir dosya değil", p)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s çok büyük", p)
	}
	return data, nil
}
