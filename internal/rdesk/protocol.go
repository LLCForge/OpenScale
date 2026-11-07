package rdesk

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
	"unicode/utf8"
)

// Wire format (ADR-0055). Every message is
//
//	type u8 | length u32 (big endian) | payload
//
// The client opens with hello; the server answers with welcome and, when
// it accepts, monitors and desktop before the first frame. A frame is one
// or more tiles messages followed by frameEnd; the client acknowledges
// each frameEnd so the server keeps at most frameWindow frames in flight
// and measures the link for adaptive quality.

type msgType uint8

// Client to server.
const (
	msgHello         msgType = 0x01
	msgAck           msgType = 0x02
	msgPing          msgType = 0x03
	msgPointer       msgType = 0x04
	msgWheel         msgType = 0x05
	msgKey           msgType = 0x06
	msgText          msgType = 0x07
	msgClipboard     msgType = 0x08 // both directions
	msgSelectMonitor msgType = 0x09
	msgQuality       msgType = 0x0a
	msgActivity      msgType = 0x0b
	msgRefresh       msgType = 0x0c
)

// Server to client.
const (
	msgWelcome  msgType = 0x81
	msgMonitors msgType = 0x82
	msgDesktop  msgType = 0x83
	msgTiles    msgType = 0x84
	msgFrameEnd msgType = 0x85
	msgBye      msgType = 0x87
	// msgKeepalive keeps a session with a static screen alive.
	msgKeepalive msgType = 0x88
)

const helloMagic = "OSRD"

// Limits shared by both ends.
const (
	headerLen = 5
	// maxClientMsg bounds every client message (the clipboard is the
	// largest).
	maxClientMsg = maxClipboardBytes + 16
	// maxServerMsg bounds every server message; a tiles message carries
	// at most maxBatchRaw uncompressed bytes, so its flate stream stays
	// well below this.
	maxServerMsg = 8 << 20
	// maxBatchRaw is the uncompressed pixel data in one tiles message.
	maxBatchRaw = 2 << 20
	// maxClipboardBytes bounds clipboard text in either direction.
	maxClipboardBytes = 1 << 20
	// maxTextBytes bounds one typed text message.
	maxTextBytes = 1024
	// maxReasonBytes bounds human readable reasons.
	maxReasonBytes = 200
	// maxMonitors bounds the monitor list.
	maxMonitors = 16
	// maxDim bounds a desktop side in pixels; maxPixels bounds the area
	// so a client never allocates more than 4*maxPixels bytes for its
	// canvas.
	maxDim    = 16384
	maxPixels = 40 << 20
	// maxTileSide bounds a tile side; the server uses TileSize.
	maxTileSide = 256
	// maxTilesPerMsg bounds the tile list of one message.
	maxTilesPerMsg = 8192
)

// TileSize is the side of the square tiles the server compares and sends.
const TileSize = 64

// Welcome status codes.
const (
	statusOK          uint8 = 0
	statusDenied      uint8 = 1 // no rule allows the requested mode
	statusRefused     uint8 = 2 // the person at the device refused or did not answer
	statusBusy        uint8 = 3 // session limit reached
	statusUnsupported uint8 = 4 // the device cannot capture its screen
	statusBadRequest  uint8 = 5 // malformed hello or unknown version
)

// Bye codes.
const (
	byeNormal   uint8 = 0
	byeIdle     uint8 = 1
	byeRevoked  uint8 = 2
	byeShutdown uint8 = 3
	byeError    uint8 = 4
	byeProtocol uint8 = 5
)

// Errors a client sees when the server refuses a session.
var (
	ErrDenied   = errors.New("rdesk: kurallar bu oturuma izin vermiyor")
	ErrRefused  = errors.New("rdesk: hedef cihazdaki kişi bağlantıyı onaylamadı")
	ErrBusy     = errors.New("rdesk: hedef cihaz oturum sınırına ulaştı")
	ErrProtocol = errors.New("rdesk: protokol hatası")
	// ErrRemoteUnsupported means the device cannot capture its screen.
	ErrRemoteUnsupported = errors.New("rdesk: hedef cihaz ekranını paylaşamıyor")
)

func statusError(status uint8, reason string) error {
	var base error
	switch status {
	case statusOK:
		return nil
	case statusDenied:
		base = ErrDenied
	case statusRefused:
		base = ErrRefused
	case statusBusy:
		if reason == reasonControlTaken {
			return fmt.Errorf("%w: %w", ErrBusy, ErrControlTaken) // #853
		}
		base = ErrBusy
	case statusUnsupported:
		base = ErrRemoteUnsupported
	default:
		base = ErrProtocol
	}
	if reason == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, reason)
}

// readMsg reads one message whose payload is at most limit bytes.
func readMsg(r *bufio.Reader, limit int) (msgType, []byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if int64(n) > int64(limit) {
		return 0, nil, fmt.Errorf("%w: ileti çok büyük (%d bayt)", ErrProtocol, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return msgType(hdr[0]), buf, nil
}

// appendHeader starts a message; finishMsg fills in the length.
func appendHeader(b []byte, t msgType) []byte {
	return append(b, byte(t), 0, 0, 0, 0)
}

func finishMsg(b []byte) []byte {
	binary.BigEndian.PutUint32(b[1:headerLen], uint32(len(b)-headerLen))
	return b
}

func encodeMsg(t msgType, payload []byte) []byte {
	b := appendHeader(make([]byte, 0, headerLen+len(payload)), t)
	return finishMsg(append(b, payload...))
}

// dec reads big endian fields and remembers the first short read.
type dec struct {
	b   []byte
	bad bool
}

func (d *dec) take(n int) []byte {
	if d.bad || n < 0 || len(d.b) < n {
		d.bad = true
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *dec) u8() uint8 {
	v := d.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (d *dec) u16() uint16 {
	v := d.take(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

func (d *dec) u32() uint32 {
	v := d.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (d *dec) str8(limit int) string {
	n := int(d.u8())
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

// end reports a malformed payload: a short read or trailing bytes.
func (d *dec) end() error {
	if d.bad || len(d.b) != 0 {
		return ErrProtocol
	}
	return nil
}

func appendStr8(b []byte, s string, limit int) []byte {
	s = truncateUTF8(s, min(limit, 255))
	b = append(b, byte(len(s)))
	return append(b, s...)
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func monitorByte(sel int) uint8 {
	if sel < 0 {
		return 0xff
	}
	return uint8(sel)
}

func monitorFromByte(b uint8) int {
	if b == 0xff {
		return MonitorAll
	}
	return int(b)
}

// --- hello / welcome ---

type hello struct {
	version uint8
	mode    Mode
	monitor int
	maxFPS  int // 0: server default
	scale   int // 0: adaptive; otherwise 1, 2 or 4
}

func (h hello) encode() []byte {
	p := append([]byte(helloMagic), h.version, uint8(h.mode), monitorByte(h.monitor), uint8(h.maxFPS), uint8(h.scale))
	return encodeMsg(msgHello, p)
}

func decodeHello(p []byte) (hello, error) {
	d := dec{b: p}
	if string(d.take(len(helloMagic))) != helloMagic {
		return hello{}, ErrProtocol
	}
	h := hello{version: d.u8(), mode: Mode(d.u8()), monitor: monitorFromByte(d.u8()), maxFPS: int(d.u8()), scale: int(d.u8())}
	if err := d.end(); err != nil {
		return hello{}, err
	}
	if !h.mode.Valid() || !validScale(h.scale, true) {
		return hello{}, ErrProtocol
	}
	return h, nil
}

func validScale(s int, allowAuto bool) bool {
	return s == 1 || s == 2 || s == 4 || (allowAuto && s == 0)
}

func encodeWelcome(status uint8, reason string) []byte {
	return encodeMsg(msgWelcome, appendStr8([]byte{status}, reason, maxReasonBytes))
}

func decodeWelcome(p []byte) (uint8, string, error) {
	d := dec{b: p}
	st := d.u8()
	reason := d.str8(maxReasonBytes)
	return st, reason, d.end()
}

// --- monitors / desktop ---

func encodeMonitors(ms []Monitor) []byte {
	if len(ms) > maxMonitors {
		ms = ms[:maxMonitors]
	}
	p := []byte{uint8(len(ms))}
	for _, m := range ms {
		p = binary.BigEndian.AppendUint32(p, uint32(int32(m.Bounds.Min.X)))
		p = binary.BigEndian.AppendUint32(p, uint32(int32(m.Bounds.Min.Y)))
		p = binary.BigEndian.AppendUint16(p, uint16(m.Bounds.Dx()))
		p = binary.BigEndian.AppendUint16(p, uint16(m.Bounds.Dy()))
		var flags uint8
		if m.Primary {
			flags |= 1
		}
		p = append(p, flags)
	}
	return encodeMsg(msgMonitors, p)
}

func decodeMonitors(p []byte) ([]Monitor, error) {
	d := dec{b: p}
	n := int(d.u8())
	if n > maxMonitors {
		return nil, ErrProtocol
	}
	out := make([]Monitor, 0, n)
	for range n {
		x, y := int(int32(d.u32())), int(int32(d.u32()))
		w, h := int(d.u16()), int(d.u16())
		flags := d.u8()
		if w <= 0 || h <= 0 || w > maxDim || h > maxDim {
			return nil, ErrProtocol
		}
		out = append(out, Monitor{Bounds: image.Rect(x, y, x+w, y+h), Primary: flags&1 != 0})
	}
	return out, d.end()
}

// Desktop describes the image the client receives: its size in pixels
// (after downscaling), the downscale factor, the selected monitor
// (MonitorAll for every monitor), the tile size and the current frame rate.
type Desktop struct {
	Width, Height int
	Scale         int
	Monitor       int
	TileSize      int
	FPS           int
}

func (dk Desktop) encode() []byte {
	p := binary.BigEndian.AppendUint16(nil, uint16(dk.Width))
	p = binary.BigEndian.AppendUint16(p, uint16(dk.Height))
	p = append(p, uint8(dk.Scale), monitorByte(dk.Monitor))
	p = binary.BigEndian.AppendUint16(p, uint16(dk.TileSize))
	p = append(p, uint8(dk.FPS))
	return encodeMsg(msgDesktop, p)
}

func decodeDesktop(p []byte) (Desktop, error) {
	d := dec{b: p}
	dk := Desktop{Width: int(d.u16()), Height: int(d.u16()), Scale: int(d.u8()), Monitor: monitorFromByte(d.u8()), TileSize: int(d.u16()), FPS: int(d.u8())}
	if err := d.end(); err != nil {
		return Desktop{}, err
	}
	if dk.Width <= 0 || dk.Height <= 0 || dk.Width > maxDim || dk.Height > maxDim || dk.Width*dk.Height > maxPixels ||
		!validScale(dk.Scale, false) || dk.TileSize <= 0 || dk.TileSize > maxTileSide {
		return Desktop{}, ErrProtocol
	}
	return dk, nil
}

// --- frames ---

func encodeSeq(t msgType, seq uint32) []byte {
	return encodeMsg(t, binary.BigEndian.AppendUint32(nil, seq))
}

func decodeSeq(p []byte) (uint32, error) {
	d := dec{b: p}
	v := d.u32()
	return v, d.end()
}

// --- input ---

type pointerEvent struct {
	x, y    int
	buttons uint8
}

func (e pointerEvent) encode() []byte {
	p := binary.BigEndian.AppendUint32(nil, uint32(int32(e.x)))
	p = binary.BigEndian.AppendUint32(p, uint32(int32(e.y)))
	return encodeMsg(msgPointer, append(p, e.buttons))
}

func decodePointer(p []byte) (pointerEvent, error) {
	d := dec{b: p}
	e := pointerEvent{x: int(int32(d.u32())), y: int(int32(d.u32())), buttons: d.u8()}
	if err := d.end(); err != nil {
		return pointerEvent{}, err
	}
	if e.buttons&^(ButtonLeft|ButtonRight|ButtonMiddle) != 0 {
		return pointerEvent{}, ErrProtocol
	}
	return e, nil
}

func encodeWheel(dx, dy int) []byte {
	p := binary.BigEndian.AppendUint16(nil, uint16(int16(clampInt(dx, -100, 100))))
	p = binary.BigEndian.AppendUint16(p, uint16(int16(clampInt(dy, -100, 100))))
	return encodeMsg(msgWheel, p)
}

func decodeWheel(p []byte) (int, int, error) {
	d := dec{b: p}
	dx, dy := int(int16(d.u16())), int(int16(d.u16()))
	if err := d.end(); err != nil {
		return 0, 0, err
	}
	if dx < -100 || dx > 100 || dy < -100 || dy > 100 {
		return 0, 0, ErrProtocol
	}
	return dx, dy, nil
}

func encodeKey(usage uint16, down bool) []byte {
	p := binary.BigEndian.AppendUint16(nil, usage)
	var b uint8
	if down {
		b = 1
	}
	return encodeMsg(msgKey, append(p, b))
}

func decodeKey(p []byte) (uint16, bool, error) {
	d := dec{b: p}
	usage, down := d.u16(), d.u8()
	if err := d.end(); err != nil {
		return 0, false, err
	}
	if down > 1 {
		return 0, false, ErrProtocol
	}
	return usage, down == 1, nil
}

// decodeText validates the length and UTF-8 encoding of text.
func decodeText(p []byte, limit int) (string, error) {
	if len(p) > limit || !utf8.Valid(p) {
		return "", ErrProtocol
	}
	return string(p), nil
}

func encodeQuality(maxFPS, scale int) []byte {
	return encodeMsg(msgQuality, []byte{uint8(maxFPS), uint8(scale)})
}

func decodeQuality(p []byte) (int, int, error) {
	d := dec{b: p}
	fps, scale := int(d.u8()), int(d.u8())
	if err := d.end(); err != nil {
		return 0, 0, err
	}
	if !validScale(scale, true) {
		return 0, 0, ErrProtocol
	}
	return fps, scale, nil
}

func encodeBye(code uint8, reason string) []byte {
	return encodeMsg(msgBye, appendStr8([]byte{code}, reason, maxReasonBytes))
}

func clampInt(v, lo, hi int) int {
	return max(lo, min(v, hi))
}
