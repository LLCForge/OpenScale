package rdesk

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"image"
	"strings"
	"time"
	"unicode/utf8"
)

// Protocol version 3 (ADR-0146): version 2 (end-to-end layer) plus
// latency echo for the quality overlay (#436), annotations on the remote
// screen (#425) and browsing and fetching files from the device's chosen
// folders (#435). The hello layout is the same as version 2. A version 3
// client that is answered with a plain "bad request" welcome (an older
// server) dials again with version 2, so it never asks the person at the
// device twice: the version check comes before consent.

// ProtocolVersionExt is the hello version with the version 3 extensions.
const ProtocolVersionExt = 3

// Client to server (version 3).
const (
	msgEcho       msgType = 0x10
	msgAnnotate   msgType = 0x11
	msgFileList   msgType = 0x12
	msgFileGet    msgType = 0x13
	msgFileCancel msgType = 0x14
)

// Server to client (version 3).
const (
	msgEchoReply   msgType = 0x8b
	msgFileListing msgType = 0x8c
	msgFileChunk   msgType = 0x8d
	msgFileDone    msgType = 0x8e
)

// ErrFeatureUnsupported is returned when the device speaks an older
// protocol version without the requested feature.
var ErrFeatureUnsupported = errors.New("rdesk: hedef cihaz bu özelliği desteklemiyor (eski sürüm)")

// errVersionRejected makes Dial retry with version 2.
var errVersionRejected = errors.New("rdesk: sunucu sürüm 3'ü tanımıyor")

// Limits of the version 3 messages.
const (
	echoLen = 8
	// maxBrowsePath bounds a requested path in bytes.
	maxBrowsePath = 1024
	// maxListEntries bounds one directory listing.
	maxListEntries = 2000
	// fileChunkLen is the data in one chunk message.
	fileChunkLen = 64 << 10
	// MaxFetchBytes bounds one fetched file.
	MaxFetchBytes = 4 << 30
	// maxAnnotationPoints bounds a stroke.
	maxAnnotationPoints = 64
)

// File operation status codes.
const (
	fileOK         uint8 = 0
	fileDenied     uint8 = 1
	fileNotFound   uint8 = 2
	fileNotRegular uint8 = 3
	fileTooLarge   uint8 = 4
	fileBusy       uint8 = 5
	fileFailed     uint8 = 6
	fileCancelled  uint8 = 7
)

// File errors a client sees.
var (
	ErrFileDenied   = errors.New("rdesk: dosya erişimine izin yok (kontrol oturumu, files kuralı ve sahibin seçtiği klasör gerekir)")
	ErrFileNotFound = errors.New("rdesk: dosya veya klasör bulunamadı")
	ErrFileTooLarge = errors.New("rdesk: dosya çok büyük")
	ErrFileBusy     = errors.New("rdesk: başka bir dosya işlemi sürüyor")
	ErrFileFailed   = errors.New("rdesk: dosya işlemi başarısız")
	ErrNotRegular   = errors.New("rdesk: bu bir dosya değil")
)

func fileStatusError(st uint8, reason string) error {
	var base error
	switch st {
	case fileOK:
		return nil
	case fileDenied:
		base = ErrFileDenied
	case fileNotFound:
		base = ErrFileNotFound
	case fileNotRegular:
		base = ErrNotRegular
	case fileTooLarge:
		base = ErrFileTooLarge
	case fileBusy:
		base = ErrFileBusy
	default:
		base = ErrFileFailed
	}
	if reason == "" {
		return base
	}
	return errors.Join(base, errors.New(reason))
}

// encodeHelloVersion is hello with the client's ephemeral key for version
// 2 or 3.
func (h hello) encodeHelloVersion(v uint8, pub []byte) []byte {
	p := append([]byte(helloMagic), v, uint8(h.mode), monitorByte(h.monitor), uint8(h.maxFPS), uint8(h.scale))
	return encodeMsg(msgHello, append(p, pub...))
}

// --- echo ---

func decodeEcho(p []byte) (uint64, error) {
	if len(p) != echoLen {
		return 0, ErrProtocol
	}
	return binary.BigEndian.Uint64(p), nil
}

func encodeEcho(t msgType, v uint64) []byte {
	return encodeMsg(t, binary.BigEndian.AppendUint64(nil, v))
}

// --- annotations (#425) ---

// AnnotationKind is what a viewer draws on the remote screen.
type AnnotationKind uint8

// Annotation kinds.
const (
	// AnnotatePointer is an arrow pointing at one point.
	AnnotatePointer AnnotationKind = 1
	// AnnotateStroke is a free-hand line through 2 to 64 points.
	AnnotateStroke AnnotationKind = 2
	// AnnotateClear removes every mark of the session.
	AnnotateClear AnnotationKind = 3
)

// AnnotationColors is the palette a mark's color indexes (opaque RGB).
var AnnotationColors = [8][3]uint8{
	{0xe5, 0x39, 0x35}, // red
	{0xfb, 0x8c, 0x00}, // orange
	{0xfd, 0xd8, 0x35}, // yellow
	{0x43, 0xa0, 0x47}, // green
	{0x1e, 0x88, 0xe5}, // blue
	{0x00, 0xac, 0xc1}, // teal
	{0xff, 0xff, 0xff}, // white
	{0x21, 0x21, 0x21}, // black
}

// AnnotationTTL is how long a mark stays on the remote screen.
const AnnotationTTL = 4 * time.Second

type annotationMsg struct {
	kind   AnnotationKind
	color  uint8
	points []image.Point // image pixels
}

func (a annotationMsg) encode() []byte {
	p := []byte{uint8(a.kind), a.color, uint8(len(a.points))}
	for _, pt := range a.points {
		p = binary.BigEndian.AppendUint16(p, uint16(pt.X))
		p = binary.BigEndian.AppendUint16(p, uint16(pt.Y))
	}
	return encodeMsg(msgAnnotate, p)
}

func validAnnotation(kind AnnotationKind, color uint8, n int) bool {
	if int(color) >= len(AnnotationColors) {
		return false
	}
	switch kind {
	case AnnotatePointer:
		return n == 1
	case AnnotateStroke:
		return n >= 2 && n <= maxAnnotationPoints
	case AnnotateClear:
		return n == 0
	}
	return false
}

func decodeAnnotation(p []byte) (annotationMsg, error) {
	d := dec{b: p}
	a := annotationMsg{kind: AnnotationKind(d.u8()), color: d.u8()}
	n := int(d.u8())
	if d.bad || !validAnnotation(a.kind, a.color, n) {
		return annotationMsg{}, ErrProtocol
	}
	a.points = make([]image.Point, 0, n)
	for range n {
		x, y := int(d.u16()), int(d.u16())
		if x >= maxDim || y >= maxDim {
			return annotationMsg{}, ErrProtocol
		}
		a.points = append(a.points, image.Pt(x, y))
	}
	if err := d.end(); err != nil {
		return annotationMsg{}, err
	}
	return a, nil
}

// --- files (#435) ---

func appendStr16(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func (d *dec) str16(limit int) string {
	n := int(d.u16())
	if n > limit {
		d.bad = true
		return ""
	}
	v := d.take(n)
	if !utf8.Valid(v) {
		d.bad = true
		return ""
	}
	return string(v)
}

func (d *dec) u64() uint64 {
	v := d.take(8)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func encodeFileReq(t msgType, id uint32, path string) []byte {
	return encodeMsg(t, appendStr16(binary.BigEndian.AppendUint32(nil, id), path))
}

func decodeFileReq(p []byte) (uint32, string, error) {
	d := dec{b: p}
	id := d.u32()
	path := d.str16(maxBrowsePath)
	if err := d.end(); err != nil {
		return 0, "", err
	}
	return id, path, nil
}

// splitBrowsePath checks a requested path: "" lists the roots, otherwise
// the first segment names a root and the rest is a slash separated path
// inside it. Empty, "." and ".." segments, backslashes, colons and control
// characters are refused; os.Root also keeps symbolic links inside the
// root.
func splitBrowsePath(p string) (root, rel string, ok bool) {
	if p == "" {
		return "", "", true
	}
	if len(p) > maxBrowsePath || !utf8.ValidString(p) {
		return "", "", false
	}
	for _, r := range p {
		if r == '\\' || r == ':' || r < 0x20 || r == 0x7f {
			return "", "", false
		}
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", "", false
		}
	}
	if len(segs) == 1 {
		return segs[0], ".", true
	}
	return segs[0], strings.Join(segs[1:], "/"), true
}

// FileEntry is one item of a remote directory listing.
type FileEntry struct {
	Name    string
	Dir     bool
	Size    int64
	ModTime time.Time
}

// Entry kinds on the wire.
const (
	entryFile  uint8 = 0
	entryDir   uint8 = 1
	entryOther uint8 = 2
)

const listTruncated uint8 = 1

func validEntryName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return false
	}
	for _, r := range s {
		if r == '/' || r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func encodeListing(id uint32, status uint8, reason string, entries []FileEntry, truncated bool) []byte {
	p := binary.BigEndian.AppendUint32(nil, id)
	var flags uint8
	if truncated {
		flags |= listTruncated
	}
	p = append(p, status, flags)
	p = appendStr8(p, reason, maxReasonBytes)
	p = binary.BigEndian.AppendUint16(p, uint16(len(entries)))
	for _, e := range entries {
		p = appendStr8(p, e.Name, 255)
		kind := entryFile
		if e.Dir {
			kind = entryDir
		}
		p = append(p, kind)
		p = binary.BigEndian.AppendUint64(p, uint64(max(e.Size, 0)))
		p = binary.BigEndian.AppendUint64(p, uint64(e.ModTime.Unix()))
	}
	return encodeMsg(msgFileListing, p)
}

type listing struct {
	id        uint32
	status    uint8
	reason    string
	entries   []FileEntry
	truncated bool
}

func decodeListing(p []byte) (listing, error) {
	d := dec{b: p}
	l := listing{id: d.u32(), status: d.u8()}
	flags := d.u8()
	l.reason = d.str8(maxReasonBytes)
	n := int(d.u16())
	if d.bad || n > maxListEntries || flags&^listTruncated != 0 || l.status > fileCancelled {
		return listing{}, ErrProtocol
	}
	l.truncated = flags&listTruncated != 0
	l.entries = make([]FileEntry, 0, n)
	for range n {
		name := d.str8(255)
		kind := d.u8()
		size := d.u64()
		mt := int64(d.u64())
		if d.bad || !validEntryName(name) || kind > entryOther || size > 1<<62 {
			return listing{}, ErrProtocol
		}
		l.entries = append(l.entries, FileEntry{Name: name, Dir: kind == entryDir, Size: int64(size), ModTime: time.Unix(mt, 0).UTC()})
	}
	if err := d.end(); err != nil {
		return listing{}, err
	}
	return l, nil
}

func encodeChunk(id uint32, off uint64, data []byte) []byte {
	p := binary.BigEndian.AppendUint32(make([]byte, 0, 12+len(data)), id)
	p = binary.BigEndian.AppendUint64(p, off)
	return encodeMsg(msgFileChunk, append(p, data...))
}

func decodeChunk(p []byte) (uint32, uint64, []byte, error) {
	d := dec{b: p}
	id, off := d.u32(), d.u64()
	if d.bad || len(d.b) > fileChunkLen {
		return 0, 0, nil, ErrProtocol
	}
	return id, off, d.b, nil
}

func encodeFileDone(id uint32, status uint8, reason string, size uint64, sum [sha256.Size]byte) []byte {
	p := binary.BigEndian.AppendUint32(nil, id)
	p = appendStr8(append(p, status), reason, maxReasonBytes)
	p = binary.BigEndian.AppendUint64(p, size)
	return encodeMsg(msgFileDone, append(p, sum[:]...))
}

type fileDone struct {
	id     uint32
	status uint8
	reason string
	size   uint64
	sum    [sha256.Size]byte
}

func decodeFileDone(p []byte) (fileDone, error) {
	d := dec{b: p}
	f := fileDone{id: d.u32(), status: d.u8()}
	f.reason = d.str8(maxReasonBytes)
	f.size = d.u64()
	copy(f.sum[:], d.take(sha256.Size))
	if err := d.end(); err != nil {
		return fileDone{}, err
	}
	if f.status > fileCancelled || f.size > MaxFetchBytes {
		return fileDone{}, ErrProtocol
	}
	return f, nil
}

func decodeCancel(p []byte) (uint32, error) {
	d := dec{b: p}
	id := d.u32()
	return id, d.end()
}
