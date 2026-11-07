// Command pkgrpm builds the OpenScale RPM package in pure Go (F-163, #316,
// ADR-0091): lead, signature header, main header and a gzip-compressed cpio
// (newc) payload, the RPM v4 format that rpm 4.x reads. Like cmd/pkgdeb
// the output is reproducible: every timestamp is SOURCE_DATE_EPOCH, owners
// are root and files are sorted.
//
//	go run ./cmd/pkgrpm -version 0.9.0 -arch arm64 -binary bin/openscale-linux-arm64 \
//	    -deploy deploy/linux -source-date-epoch N -out dist/openscale-0.9.0-1.aarch64.rpm \
//	    [-verifier bin/openscale-release-verify-linux-arm64] [-root-pub build/release/root.pub]
//
// The package installs the same files as the .deb and never enables or
// starts a unit. It carries no OpenPGP signature (that would need an
// OpenPGP implementation outside ADR-0002); authenticity comes from the
// signed release manifest (ADR-0022), which lists the .rpm. The header
// holds SHA-256 digests of every file, of the header and of the payload,
// so `rpm -K` checks integrity.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"  // #nosec G501 -- RPMSIGTAG_MD5 for rpm < 4.14; integrity comes from the SHA-256 tags and the signed manifest
	"crypto/sha1" // #nosec G505 -- RPMSIGTAG_SHA1 for rpm < 4.14; see above
	"crypto/sha256"
	"encoding/binary"
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
	"strings"
)

const (
	packageName      = "openscale"
	installedBinary  = "/usr/bin/openscale"
	legacyBinary     = "/usr/local/bin/openscale"
	unitDir          = "/usr/lib/systemd/system"
	docDir           = "/usr/share/doc/openscale"
	rootPubConffile  = "/etc/openscale/release-root.pub"
	maxInputFileSize = 512 << 20
)

// rpmArch maps the release architecture names (GOARCH, Debian names) to
// RPM architectures and the legacy lead arch number.
var rpmArch = map[string]struct {
	name string
	num  uint16
}{
	"amd64": {"x86_64", 1}, "x86_64": {"x86_64", 1},
	"arm64": {"aarch64", 19}, "aarch64": {"aarch64", 19},
	"arm": {"armv7hl", 12}, "armv7": {"armv7hl", 12}, "armhf": {"armv7hl", 12}, "armv7hl": {"armv7hl", 12},
}

var (
	// RPM forbids '-' in version and release (it separates N-V-R).
	rpmVersionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~^_]{0,63}$`)
	rpmReleaseRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~^_]{0,31}$`)
	packagerRe   = regexp.MustCompile(`^[^<>\n]{1,80} <[^<>@\s]{1,64}@[^<>@\s]{1,128}>$`)
)

// Header tags (rpmtag.h).
const (
	tagHeaderSignatures = 62
	tagHeaderImmutable  = 63
	tagI18NTable        = 100

	sigSHA1        = 269
	sigSHA256      = 273
	sigSize        = 1000
	sigMD5         = 1004
	sigPayloadSize = 1007

	tagName              = 1000
	tagVersion           = 1001
	tagRelease           = 1002
	tagSummary           = 1004
	tagDescription       = 1005
	tagBuildTime         = 1006
	tagBuildHost         = 1007
	tagSize              = 1009
	tagLicense           = 1014
	tagPackager          = 1015
	tagGroup             = 1016
	tagOS                = 1021
	tagArch              = 1022
	tagPreIn             = 1023
	tagPostIn            = 1024
	tagPreUn             = 1025
	tagPostUn            = 1026
	tagFileSizes         = 1028
	tagFileModes         = 1030
	tagFileRdevs         = 1033
	tagFileMtimes        = 1034
	tagFileDigests       = 1035
	tagFileLinkTos       = 1036
	tagFileFlags         = 1037
	tagFileUserName      = 1039
	tagFileGroupName     = 1040
	tagSourceRPM         = 1044
	tagFileVerifyFlags   = 1045
	tagProvideName       = 1047
	tagRequireFlags      = 1048
	tagRequireName       = 1049
	tagRequireVersion    = 1050
	tagPreInProg         = 1085
	tagPostInProg        = 1086
	tagPreUnProg         = 1087
	tagPostUnProg        = 1088
	tagFileDevices       = 1095
	tagFileInodes        = 1096
	tagFileLangs         = 1097
	tagProvideFlags      = 1112
	tagProvideVersion    = 1113
	tagDirIndexes        = 1116
	tagBaseNames         = 1117
	tagDirNames          = 1118
	tagPayloadFormat     = 1124
	tagPayloadCompressor = 1125
	tagPayloadFlags      = 1126
	tagFileDigestAlgo    = 5011
	tagRecommendName     = 5046
	tagRecommendVersion  = 5047
	tagRecommendFlags    = 5048
	tagEncoding          = 5062
	tagPayloadDigest     = 5092
	tagPayloadDigestAlgo = 5093
)

// Header data types.
const (
	typeInt16       = 3
	typeInt32       = 4
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

const (
	fileConfig    = 1 << 0
	fileDoc       = 1 << 1
	fileNoReplace = 1 << 4

	senseLess   = 1 << 1
	senseEqual  = 1 << 3
	senseRPMLib = 1 << 24

	digestSHA256 = 8
)

var headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}

type file struct {
	name  string // absolute path
	mode  uint32 // permission bits
	data  []byte
	flags int32
	dir   bool
}

type options struct {
	version, release, arch, binary, verifier, deploy, rootPub, out, packager string
	sde                                                                      int64
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pkgrpm:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	o := options{}
	fs := flag.NewFlagSet("pkgrpm", flag.ContinueOnError)
	fs.StringVar(&o.version, "version", "", "paket sürümü, ör. 0.9.0 ('-' içeremez)")
	fs.StringVar(&o.release, "release", "1", "RPM Release alanı")
	fs.StringVar(&o.arch, "arch", "", "amd64, arm64 veya armhf (x86_64, aarch64, armv7hl de olur)")
	fs.StringVar(&o.binary, "binary", "", "linux openscale ikilisi")
	fs.StringVar(&o.verifier, "verifier", "", "openscale-release-verify ikilisi (isteğe bağlı)")
	fs.StringVar(&o.deploy, "deploy", "deploy/linux", "deploy/linux klasörü (birimler ve rpm/ betikleri)")
	fs.StringVar(&o.rootPub, "root-pub", "", "sürüm kök açık anahtarı; /etc/openscale/release-root.pub olarak kurulur (isteğe bağlı)")
	fs.StringVar(&o.out, "out", "", "çıktı .rpm dosyası")
	fs.StringVar(&o.packager, "packager", "OpenScale <root@localhost>", "Packager alanı: \"Ad <adres>\"")
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
	arch, ok := rpmArch[o.arch]
	if !ok {
		return nil, fmt.Errorf("desteklenmeyen mimari %q", o.arch)
	}
	if !rpmVersionRe.MatchString(o.version) {
		return nil, fmt.Errorf("geçersiz paket sürümü %q", o.version)
	}
	if !rpmReleaseRe.MatchString(o.release) {
		return nil, fmt.Errorf("geçersiz Release %q", o.release)
	}
	if !packagerRe.MatchString(o.packager) {
		return nil, fmt.Errorf("Packager \"Ad <adres>\" biçiminde olmalı: %q", o.packager)
	}
	// RPM stores times as 32-bit integers.
	if o.sde > 1<<31-1 {
		return nil, errors.New("SOURCE_DATE_EPOCH 2038 sonrası; RPM 32 bit zaman tutar")
	}

	files, err := collect(o)
	if err != nil {
		return nil, err
	}
	scripts := map[string]string{}
	for _, s := range []string{"pre", "post", "preun", "postun"} {
		d, err := readFile(filepath.Join(o.deploy, "rpm", s))
		if err != nil {
			return nil, err
		}
		scripts[s] = string(toLF(d))
	}

	payload, payloadSize, err := cpioGz(files, o.sde)
	if err != nil {
		return nil, err
	}
	nvr := packageName + "-" + o.version + "-" + o.release
	mh := mainHeader(o, arch.name, nvr, files, scripts, payload)
	hdr := mh.bytes(tagHeaderImmutable)

	sha1sum := sha1.Sum(hdr) // #nosec G401 -- legacy rpm header digest
	sha256sum := sha256.Sum256(hdr)
	md := md5.New() // #nosec G401 -- legacy rpm digest
	md.Write(hdr)
	md.Write(payload)
	if int64(len(hdr))+int64(len(payload)) > 1<<31-1 || payloadSize > 1<<31-1 {
		return nil, errors.New("paket 2 GiB sınırını aşıyor")
	}
	var sig header
	sig.addString(sigSHA1, hex.EncodeToString(sha1sum[:]))
	sig.addString(sigSHA256, hex.EncodeToString(sha256sum[:]))
	sig.addInt32(sigSize, int32(len(hdr)+len(payload)))
	sig.addBin(sigMD5, md.Sum(nil))
	sig.addInt32(sigPayloadSize, int32(payloadSize))
	sigBytes := sig.bytes(tagHeaderSignatures)

	var out bytes.Buffer
	out.Write(lead(nvr, arch.num))
	out.Write(sigBytes)
	// The signature header is padded to an 8-byte boundary.
	out.Write(make([]byte, (8-len(sigBytes)%8)%8))
	out.Write(hdr)
	out.Write(payload)
	return out.Bytes(), nil
}

// collect lists the package files, sorted by path, with the directories the
// package owns. Shared system directories (/usr/bin, the systemd unit
// directory) are not owned: their owners (filesystem, systemd) set them.
func collect(o options) ([]file, error) {
	var files []file
	add := func(name string, mode uint32, flags int32, data []byte) {
		files = append(files, file{name: name, mode: mode, flags: flags, data: data})
	}
	bin, err := readFile(o.binary)
	if err != nil {
		return nil, err
	}
	add(installedBinary, 0o755, 0, bin)
	if o.verifier != "" {
		v, err := readFile(o.verifier)
		if err != nil {
			return nil, err
		}
		add("/usr/bin/openscale-release-verify", 0o755, 0, v)
	}
	for _, u := range []string{"openscale-coordinator.service", "openscale-device.service"} {
		d, err := readFile(filepath.Join(o.deploy, u))
		if err != nil {
			return nil, err
		}
		// Same rewrite as the .deb: packages install to /usr/bin.
		d = bytes.ReplaceAll(toLF(d), []byte(legacyBinary+" "), []byte(installedBinary+" "))
		if bytes.Contains(d, []byte(legacyBinary)) {
			return nil, fmt.Errorf("%s: %s yolu değiştirilemedi", u, legacyBinary)
		}
		add(unitDir+"/"+u, 0o644, 0, d)
	}
	for _, ex := range []string{"nftables.conf", "sshd-openscale.conf", "50-openscale-upgrades.conf"} {
		d, err := readFile(filepath.Join(o.deploy, ex))
		if err != nil {
			return nil, err
		}
		add(docDir+"/examples/"+ex, 0o644, fileDoc, d)
	}
	owned := []string{docDir, docDir + "/examples"}
	if o.rootPub != "" {
		d, err := readFile(o.rootPub)
		if err != nil {
			return nil, err
		}
		add(rootPubConffile, 0o644, fileConfig|fileNoReplace, d)
		owned = append(owned, path.Dir(rootPubConffile))
	}
	for _, d := range owned {
		files = append(files, file{name: d, mode: 0o755, dir: true})
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.name, b.name) })
	return files, nil
}

func mainHeader(o options, arch, nvr string, files []file, scripts map[string]string, payload []byte) *header {
	h := &header{}
	h.addStringArray(tagI18NTable, []string{"C"})
	h.addString(tagName, packageName)
	h.addString(tagVersion, o.version)
	h.addString(tagRelease, o.release)
	h.addI18N(tagSummary, "OpenScale personal WireGuard mesh VPN")
	h.addI18N(tagDescription, "Coordinator and device for a single-owner, cloud-free WireGuard mesh.\n"+
		"The package installs the program and the systemd units but does not\n"+
		"enable or start them; join the network first (docs/sunucu-kurulumu.md).")
	h.addInt32(tagBuildTime, int32(o.sde))
	h.addString(tagBuildHost, "localhost") // reproducible: never the real host name
	var total int64
	for _, f := range files {
		total += int64(len(f.data))
	}
	h.addInt32(tagSize, int32(total))
	// ADR-0010 has not chosen a license yet; rpm requires the field.
	h.addString(tagLicense, "LicenseRef-OpenScale-Unlicensed")
	h.addString(tagPackager, o.packager)
	h.addI18N(tagGroup, "Applications/Internet")
	h.addString(tagOS, "linux")
	h.addString(tagArch, arch)
	h.addString(tagPreIn, scripts["pre"])
	h.addString(tagPostIn, scripts["post"])
	h.addString(tagPreUn, scripts["preun"])
	h.addString(tagPostUn, scripts["postun"])

	n := len(files)
	sizes := make([]int32, n)
	modes := make([]uint16, n)
	rdevs := make([]uint16, n)
	mtimes := make([]int32, n)
	digests := make([]string, n)
	linktos := make([]string, n)
	flags := make([]int32, n)
	users := make([]string, n)
	groups := make([]string, n)
	verify := make([]int32, n)
	devices := make([]int32, n)
	inodes := make([]int32, n)
	langs := make([]string, n)
	var dirNames []string
	dirIndex := map[string]int32{}
	dirIndexes := make([]int32, n)
	baseNames := make([]string, n)
	for i, f := range files {
		sizes[i] = int32(len(f.data))
		modes[i] = uint16(fileMode(f))
		mtimes[i] = int32(o.sde)
		if !f.dir {
			s := sha256.Sum256(f.data)
			digests[i] = hex.EncodeToString(s[:])
		}
		flags[i] = f.flags
		users[i], groups[i] = "root", "root"
		verify[i] = -1
		devices[i] = 1
		inodes[i] = int32(i + 1)
		dir, base := path.Split(f.name)
		idx, ok := dirIndex[dir]
		if !ok {
			idx = int32(len(dirNames))
			dirIndex[dir] = idx
			dirNames = append(dirNames, dir)
		}
		dirIndexes[i], baseNames[i] = idx, base
	}
	h.addInt32(tagFileSizes, sizes...)
	h.addInt16(tagFileModes, modes...)
	h.addInt16(tagFileRdevs, rdevs...)
	h.addInt32(tagFileMtimes, mtimes...)
	h.addStringArray(tagFileDigests, digests)
	h.addStringArray(tagFileLinkTos, linktos)
	h.addInt32(tagFileFlags, flags...)
	h.addStringArray(tagFileUserName, users)
	h.addStringArray(tagFileGroupName, groups)
	h.addString(tagSourceRPM, nvr+".src.rpm") // its presence marks a binary package
	h.addInt32(tagFileVerifyFlags, verify...)
	h.addStringArray(tagProvideName, []string{packageName})
	h.addInt32(tagRequireFlags, 0,
		senseRPMLib|senseLess|senseEqual, senseRPMLib|senseLess|senseEqual, senseRPMLib|senseLess|senseEqual)
	h.addStringArray(tagRequireName, []string{"/bin/sh",
		"rpmlib(CompressedFileNames)", "rpmlib(FileDigests)", "rpmlib(PayloadFilesHavePrefix)"})
	h.addStringArray(tagRequireVersion, []string{"", "3.0.4-1", "4.6.0-1", "4.0-1"})
	for _, t := range []int32{tagPreInProg, tagPostInProg, tagPreUnProg, tagPostUnProg} {
		h.addString(t, "/bin/sh")
	}
	h.addInt32(tagFileDevices, devices...)
	h.addInt32(tagFileInodes, inodes...)
	h.addStringArray(tagFileLangs, langs)
	h.addInt32(tagProvideFlags, senseEqual)
	h.addStringArray(tagProvideVersion, []string{o.version + "-" + o.release})
	h.addInt32(tagDirIndexes, dirIndexes...)
	h.addStringArray(tagBaseNames, baseNames)
	h.addStringArray(tagDirNames, dirNames)
	h.addString(tagPayloadFormat, "cpio")
	h.addString(tagPayloadCompressor, "gzip")
	h.addString(tagPayloadFlags, "9")
	h.addInt32(tagFileDigestAlgo, digestSHA256)
	// The exit node needs nftables (or iptables); a weak dependency like
	// the .deb's Recommends.
	h.addStringArray(tagRecommendName, []string{"nftables"})
	h.addStringArray(tagRecommendVersion, []string{""})
	h.addInt32(tagRecommendFlags, 0)
	h.addString(tagEncoding, "utf-8")
	ps := sha256.Sum256(payload)
	h.addStringArray(tagPayloadDigest, []string{hex.EncodeToString(ps[:])})
	h.addInt32(tagPayloadDigestAlgo, digestSHA256)
	return h
}

func fileMode(f file) uint32 {
	if f.dir {
		return 0o040000 | f.mode
	}
	return 0o100000 | f.mode
}

// lead is the 96-byte legacy RPM lead.
func lead(nvr string, archNum uint16) []byte {
	b := make([]byte, 96)
	copy(b, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(b[6:], 0) // binary package
	binary.BigEndian.PutUint16(b[8:], archNum)
	name := nvr
	if len(name) > 65 {
		name = name[:65]
	}
	copy(b[10:76], name)
	binary.BigEndian.PutUint16(b[76:], 1) // Linux
	binary.BigEndian.PutUint16(b[78:], 5) // RPMSIGTYPE_HEADERSIG
	return b
}

// header is an RPM header structure being built.
type header struct {
	entries []entry
}

type entry struct {
	tag, typ, count int32
	data            []byte
}

func (h *header) add(tag, typ, count int32, data []byte) {
	h.entries = append(h.entries, entry{tag: tag, typ: typ, count: count, data: data})
}

func (h *header) addString(tag int32, s string) {
	h.add(tag, typeString, 1, append([]byte(s), 0))
}

func (h *header) addI18N(tag int32, s string) {
	h.add(tag, typeI18NString, 1, append([]byte(s), 0))
}

func (h *header) addStringArray(tag int32, ss []string) {
	var b []byte
	for _, s := range ss {
		b = append(append(b, s...), 0)
	}
	h.add(tag, typeStringArray, int32(len(ss)), b)
}

func (h *header) addInt32(tag int32, vs ...int32) {
	b := make([]byte, 4*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint32(b[4*i:], uint32(v))
	}
	h.add(tag, typeInt32, int32(len(vs)), b)
}

func (h *header) addInt16(tag int32, vs ...uint16) {
	b := make([]byte, 2*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint16(b[2*i:], v)
	}
	h.add(tag, typeInt16, int32(len(vs)), b)
}

func (h *header) addBin(tag int32, b []byte) {
	h.add(tag, typeBin, int32(len(b)), slices.Clone(b))
}

// bytes serializes the header with an immutable region: the region tag is
// the first index entry and its 16-byte trailer is the last item of the
// data store, as rpm's hdrblobVerifyRegion expects. Data items follow the
// index order without overlap and are aligned for their type.
func (h *header) bytes(regionTag int32) []byte {
	entries := slices.Clone(h.entries)
	slices.SortStableFunc(entries, func(a, b entry) int { return int(a.tag - b.tag) })
	il := len(entries) + 1
	var store []byte
	offsets := make([]int32, len(entries))
	for i, e := range entries {
		align := 1
		switch e.typ {
		case typeInt16:
			align = 2
		case typeInt32:
			align = 4
		}
		for len(store)%align != 0 {
			store = append(store, 0)
		}
		offsets[i] = int32(len(store))
		store = append(store, e.data...)
	}
	trailerOff := int32(len(store))
	trailer := make([]byte, 16)
	binary.BigEndian.PutUint32(trailer[0:], uint32(regionTag))
	binary.BigEndian.PutUint32(trailer[4:], typeBin)
	binary.BigEndian.PutUint32(trailer[8:], uint32(-int32(il*16)))
	binary.BigEndian.PutUint32(trailer[12:], 16)
	store = append(store, trailer...)

	var b bytes.Buffer
	b.Write(headerMagic)
	_ = binary.Write(&b, binary.BigEndian, uint32(il))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(store)))
	writeIndex := func(tag, typ, off, count int32) {
		_ = binary.Write(&b, binary.BigEndian, [4]int32{tag, typ, off, count})
	}
	writeIndex(regionTag, typeBin, trailerOff, 16)
	for i, e := range entries {
		writeIndex(e.tag, e.typ, offsets[i], e.count)
	}
	b.Write(store)
	return b.Bytes()
}

// cpioGz writes the payload: a cpio "newc" archive with "./"-prefixed
// names in header order, gzip-compressed. It returns the compressed bytes
// and the uncompressed size.
func cpioGz(files []file, mtime int64) ([]byte, int64, error) {
	var raw bytes.Buffer
	for i, f := range files {
		nlink := 1
		if f.dir {
			nlink = 2
		}
		if err := cpioEntry(&raw, uint32(i+1), fileMode(f), uint32(nlink), uint32(mtime), "."+f.name, f.data); err != nil {
			return nil, 0, err
		}
	}
	if err := cpioEntry(&raw, 0, 0, 1, 0, "TRAILER!!!", nil); err != nil {
		return nil, 0, err
	}
	var out bytes.Buffer
	gz, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, 0, err
	}
	// The gzip header keeps a zero time and no name: reproducible.
	if _, err := gz.Write(raw.Bytes()); err != nil {
		return nil, 0, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, err
	}
	return out.Bytes(), int64(raw.Len()), nil
}

func cpioEntry(w *bytes.Buffer, ino, mode, nlink, mtime uint32, name string, data []byte) error {
	if uint64(len(data)) > 0xffffffff {
		return fmt.Errorf("%s: cpio için çok büyük", name)
	}
	fmt.Fprintf(w, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, nlink, mtime, len(data), 0, 0, 0, 0, len(name)+1, 0)
	w.WriteString(name)
	w.WriteByte(0)
	pad4(w)
	w.Write(data)
	pad4(w)
	return nil
}

func pad4(w *bytes.Buffer) {
	for w.Len()%4 != 0 {
		w.WriteByte(0)
	}
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
