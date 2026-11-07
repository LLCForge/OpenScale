package rdesk

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"image"
	"math/rand/v2"
	"testing"
	"time"
)

func payload(t *testing.T, msg []byte, want msgType) []byte {
	t.Helper()
	typ, p, err := readMsg(bufio.NewReader(bytes.NewReader(msg)), maxServerMsg)
	if err != nil || typ != want {
		t.Fatalf("readMsg: %v %#x", err, typ)
	}
	return p
}

func TestHelloRoundTrip(t *testing.T) {
	for _, h := range []hello{
		{version: 1, mode: ModeView, monitor: 0, maxFPS: 10, scale: 0},
		{version: 1, mode: ModeControl, monitor: MonitorAll, maxFPS: 0, scale: 4},
		{version: 1, mode: ModeView, monitor: 3, maxFPS: 30, scale: 2},
	} {
		got, err := decodeHello(payload(t, h.encode(), msgHello))
		if err != nil || got != h {
			t.Fatalf("hello %+v -> %+v, %v", h, got, err)
		}
	}
	bad := [][]byte{
		nil,
		[]byte("XXXX\x01\x01\x00\x00\x00"),
		[]byte("OSRD\x01\x03\x00\x00\x00"), // unknown mode
		[]byte("OSRD\x01\x01\x00\x00\x03"), // bad scale
		[]byte("OSRD\x01\x01\x00\x00"),     // short
		[]byte("OSRD\x01\x01\x00\x00\x00\x00"),
	}
	for i, p := range bad {
		if _, err := decodeHello(p); err == nil {
			t.Errorf("bad hello %d accepted", i)
		}
	}
}

func TestReadMsgLimit(t *testing.T) {
	msg := encodeMsg(msgClipboard, make([]byte, 100))
	if _, _, err := readMsg(bufio.NewReader(bytes.NewReader(msg)), 99); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversized message: %v", err)
	}
	if _, p, err := readMsg(bufio.NewReader(bytes.NewReader(msg)), 100); err != nil || len(p) != 100 {
		t.Fatalf("exact limit: %v", err)
	}
	huge := []byte{byte(msgTiles), 0xff, 0xff, 0xff, 0xff}
	if _, _, err := readMsg(bufio.NewReader(bytes.NewReader(huge)), maxServerMsg); !errors.Is(err, ErrProtocol) {
		t.Fatalf("huge length must be refused before allocating: %v", err)
	}
}

func TestWelcomeAndStatus(t *testing.T) {
	st, reason, err := decodeWelcome(payload(t, encodeWelcome(statusRefused, "hayır"), msgWelcome))
	if err != nil || st != statusRefused || reason != "hayır" {
		t.Fatal(st, reason, err)
	}
	if !errors.Is(statusError(statusDenied, ""), ErrDenied) || !errors.Is(statusError(statusBusy, "x"), ErrBusy) ||
		!errors.Is(statusError(statusUnsupported, ""), ErrRemoteUnsupported) || !errors.Is(statusError(99, ""), ErrProtocol) ||
		statusError(statusOK, "") != nil {
		t.Fatal("statusError")
	}
	long := string(bytes.Repeat([]byte("ğ"), 300))
	_, reason, err = decodeWelcome(payload(t, encodeWelcome(statusDenied, long), msgWelcome))
	if err != nil || len(reason) > maxReasonBytes {
		t.Fatalf("long reason must be truncated on a character boundary: %d %v", len(reason), err)
	}
}

func TestMonitorsAndDesktopRoundTrip(t *testing.T) {
	ms := []Monitor{
		{Bounds: image.Rect(0, 0, 1920, 1080), Primary: true},
		{Bounds: image.Rect(-1280, 100, 0, 1124)},
	}
	got, err := decodeMonitors(payload(t, encodeMonitors(ms), msgMonitors))
	if err != nil || len(got) != 2 || got[0] != ms[0] || got[1] != ms[1] {
		t.Fatalf("monitors: %+v %v", got, err)
	}
	dk := Desktop{Width: 960, Height: 540, Scale: 2, Monitor: MonitorAll, TileSize: TileSize, FPS: 15}
	gd, err := decodeDesktop(payload(t, dk.encode(), msgDesktop))
	if err != nil || gd != dk {
		t.Fatalf("desktop: %+v %v", gd, err)
	}
	for _, bad := range []Desktop{
		{Width: 0, Height: 10, Scale: 1, TileSize: 64},
		{Width: 10, Height: 10, Scale: 3, TileSize: 64},
		{Width: 10, Height: 10, Scale: 1, TileSize: 0},
		{Width: 10, Height: 10, Scale: 1, TileSize: 1000},
		{Width: 16000, Height: 16000, Scale: 1, TileSize: 64},
	} {
		if _, err := decodeDesktop(payload(t, bad.encode(), msgDesktop)); err == nil {
			t.Errorf("bad desktop accepted: %+v", bad)
		}
	}
}

func TestInputCodecs(t *testing.T) {
	pe := pointerEvent{x: -5, y: 1200, buttons: ButtonLeft | ButtonMiddle}
	if got, err := decodePointer(payload(t, pe.encode(), msgPointer)); err != nil || got != pe {
		t.Fatalf("pointer %+v %v", got, err)
	}
	if _, err := decodePointer([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0x80}); err == nil {
		t.Fatal("unknown button bits accepted")
	}
	if dx, dy, err := decodeWheel(payload(t, encodeWheel(-3, 500), msgWheel)); err != nil || dx != -3 || dy != 100 {
		t.Fatalf("wheel %d %d %v", dx, dy, err)
	}
	if u, down, err := decodeKey(payload(t, encodeKey(0xE1, true), msgKey)); err != nil || u != 0xE1 || !down {
		t.Fatalf("key %v %v %v", u, down, err)
	}
	if _, _, err := decodeKey([]byte{0, 4, 2}); err == nil {
		t.Fatal("bad key state accepted")
	}
	if fps, sc, err := decodeQuality(payload(t, encodeQuality(5, 2), msgQuality)); err != nil || fps != 5 || sc != 2 {
		t.Fatal("quality")
	}
	if _, err := decodeText([]byte{0xff, 0xfe}, 10); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, err := decodeText(make([]byte, 11), 10); err == nil {
		t.Fatal("long text accepted")
	}
	if got := sanitizeText("a\x1b[2Jb\r\n\tç​"); got != "a[2Jb\n\tç​" {
		t.Fatalf("sanitizeText: %q", got)
	}
}

func randomImage(r *rand.Rand, w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = uint8(r.IntN(256)), uint8(r.IntN(256)), uint8(r.IntN(256)), 0xff
	}
	// A uniform region exercises the solid tile path.
	for y := 0; y < min(h, 130); y++ {
		for x := 0; x < min(w, 130); x++ {
			o := img.PixOffset(x, y)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2] = 10, 20, 30
		}
	}
	return img
}

func applyAll(t *testing.T, canvas *image.RGBA, msgs [][]byte) {
	t.Helper()
	for _, m := range msgs {
		if _, err := applyTiles(canvas, payload(t, m, msgTiles)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTilesRoundTripAndDiff(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	src := randomImage(r, 333, 211)
	rects := changedTiles(nil, src, TileSize)
	if len(rects) != 6*4 {
		t.Fatalf("full frame tiles = %d", len(rects))
	}
	var enc tileEncoder
	msgs, err := enc.encode(7, src, rects)
	if err != nil {
		t.Fatal(err)
	}
	canvas := image.NewRGBA(src.Rect)
	applyAll(t, canvas, msgs)
	if !bytes.Equal(canvas.Pix, src.Pix) {
		t.Fatal("decoded frame differs")
	}
	if seq, _ := applyTiles(canvas, payload(t, msgs[0], msgTiles)); seq != 7 {
		t.Fatal("sequence")
	}

	next := image.NewRGBA(src.Rect)
	copy(next.Pix, src.Pix)
	o := next.PixOffset(200, 150)
	next.Pix[o] ^= 0xff
	diff := changedTiles(src, next, TileSize)
	if len(diff) != 1 || diff[0] != image.Rect(192, 128, 256, 192) {
		t.Fatalf("diff = %v", diff)
	}
	enc.setLevel(flateSmall)
	msgs, err = enc.encode(8, next, diff)
	if err != nil {
		t.Fatal(err)
	}
	applyAll(t, canvas, msgs)
	if !bytes.Equal(canvas.Pix, next.Pix) {
		t.Fatal("incremental frame differs")
	}
	if len(changedTiles(next, next, TileSize)) != 0 {
		t.Fatal("unchanged frame must have no tiles")
	}
}

func TestTilesSplitIntoBatches(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	src := randomImage(r, 1200, 900) // ~3.2 MB of RGB, more than one batch
	var enc tileEncoder
	msgs, err := enc.encode(1, src, changedTiles(nil, src, TileSize))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) < 2 {
		t.Fatalf("expected several batches, got %d", len(msgs))
	}
	canvas := image.NewRGBA(src.Rect)
	for _, m := range msgs {
		if len(m) > maxServerMsg {
			t.Fatal("batch over the message limit")
		}
	}
	applyAll(t, canvas, msgs)
	if !bytes.Equal(canvas.Pix, src.Pix) {
		t.Fatal("batched frame differs")
	}
}

func tilesPayload(seq uint32, hdr []byte, n int, blob []byte) []byte {
	p := binary.BigEndian.AppendUint32(nil, seq)
	p = binary.BigEndian.AppendUint16(p, uint16(n))
	p = append(p, hdr...)
	p = binary.BigEndian.AppendUint32(p, uint32(len(blob)))
	return append(p, blob...)
}

func tileHeader(x, y, w, h int, enc uint8, extra ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(x))
	b = binary.BigEndian.AppendUint16(b, uint16(y))
	b = binary.BigEndian.AppendUint16(b, uint16(w))
	b = binary.BigEndian.AppendUint16(b, uint16(h))
	return append(append(b, enc), extra...)
}

func deflate(t *testing.T, raw []byte) []byte {
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.BestSpeed)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestApplyTilesRejectsHostileInput(t *testing.T) {
	canvas := image.NewRGBA(image.Rect(0, 0, 100, 100))
	good := tilesPayload(1, tileHeader(0, 0, 2, 2, encFlate), 1, deflate(t, make([]byte, 12)))
	if _, err := applyTiles(canvas, good); err != nil {
		t.Fatalf("good tile: %v", err)
	}
	cases := map[string][]byte{
		"outside canvas":   tilesPayload(1, tileHeader(99, 99, 2, 2, encSolid, 1, 2, 3), 1, nil),
		"huge tile":        tilesPayload(1, tileHeader(0, 0, 300, 1, encSolid, 1, 2, 3), 1, nil),
		"zero tile":        tilesPayload(1, tileHeader(0, 0, 0, 1, encSolid, 1, 2, 3), 1, nil),
		"unknown encoding": tilesPayload(1, tileHeader(0, 0, 1, 1, 9), 1, nil),
		"short data":       tilesPayload(1, tileHeader(0, 0, 2, 2, encFlate), 1, deflate(t, make([]byte, 11))),
		"extra data":       tilesPayload(1, tileHeader(0, 0, 2, 2, encFlate), 1, deflate(t, make([]byte, 13))),
		"bomb":             tilesPayload(1, tileHeader(0, 0, 2, 2, encFlate), 1, deflate(t, make([]byte, 50<<20))),
		"blob on solid":    tilesPayload(1, tileHeader(0, 0, 2, 2, encSolid, 1, 2, 3), 1, []byte{1}),
		"count mismatch":   tilesPayload(1, tileHeader(0, 0, 2, 2, encSolid, 1, 2, 3), 2, nil),
		"trailing":         append(tilesPayload(1, tileHeader(0, 0, 2, 2, encSolid, 1, 2, 3), 1, nil), 0),
	}
	for name, p := range cases {
		if _, err := applyTiles(canvas, p); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDownscale(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 5, 3))
	for i := 0; i < len(src.Pix); i += 4 {
		src.Pix[i], src.Pix[i+3] = uint8(i), 0xff
	}
	dst := downscale(src, 2, nil)
	if dst.Rect.Dx() != 3 || dst.Rect.Dy() != 2 {
		t.Fatalf("size %v", dst.Rect)
	}
	// Top-left box: pixels (0,0),(1,0),(0,1),(1,1) with red 0,4,20,24.
	if dst.Pix[0] != 12 {
		t.Fatalf("box average = %d", dst.Pix[0])
	}
	// Bottom-right edge box: only pixel (4,2), red 56.
	if dst.Pix[dst.PixOffset(2, 1)] != 56 {
		t.Fatal("edge box")
	}
	if again := downscale(src, 2, dst); again != dst {
		t.Fatal("downscale must reuse a matching buffer")
	}
}

func TestQualityAdapts(t *testing.T) {
	q := newQuality(15, 0)
	q.observe(1000, 5*time.Millisecond) // base round trip
	slow := 5*time.Millisecond + 10*q.budget()
	steps := 0
	for q.fps > minFPS && steps < 100 {
		q.observe(200<<10, slow+10*q.budget())
		steps++
	}
	if q.fps != minFPS || q.scale != 1 {
		t.Fatalf("frame rate must drop first: fps=%d scale=%d", q.fps, q.scale)
	}
	changed := false
	for range slowStreak {
		changed = q.observe(200<<10, 5*time.Millisecond+10*q.budget()) || changed
	}
	if !changed || q.scale != 2 {
		t.Fatalf("scale must grow at the minimum frame rate: %d", q.scale)
	}
	if q.level != flateSmall {
		t.Fatal("slow link must use stronger compression")
	}
	changed = false
	for range fastStreak {
		changed = q.observe(1000, 5*time.Millisecond) || changed
	}
	if !changed || q.scale != 1 {
		t.Fatalf("resolution must recover first: %d", q.scale)
	}
	for range 20 * fastStreak {
		q.observe(1000, 5*time.Millisecond)
	}
	if q.fps != 15 {
		t.Fatalf("frame rate must recover to the ceiling: %d", q.fps)
	}
	fixed := newQuality(15, 1)
	for range 50 {
		fixed.observe(200<<10, time.Second)
	}
	if fixed.scale != 1 {
		t.Fatal("a fixed scale must not change")
	}
	if fixed.setLimits(5, 4, 15) != true || fixed.maxFPS != 5 || fixed.fps > 5 {
		t.Fatal("setLimits")
	}
}

func TestKeyMap(t *testing.T) {
	cases := []struct {
		usage  uint16
		vk     uint16
		ext    bool
		keysym uint32
	}{
		{0x04, 'A', false, 'a'},
		{0x1D, 'Z', false, 'z'},
		{0x1E, '1', false, '1'},
		{0x27, '0', false, '0'},
		{0x3A, 0x70, false, 0xffbe},
		{0x45, 0x7B, false, 0xffc9},
		{0x28, 0x0D, false, 0xff0d},
		{0x50, 0x25, true, 0xff51},
		{0x59, 0x61, false, 0xffb1},
		{0xE4, 0xA3, true, 0xffe4},
	}
	for _, c := range cases {
		k, ok := lookupKey(c.usage)
		if !ok || k.vk != c.vk || k.extended != c.ext || k.keysym != c.keysym {
			t.Errorf("usage %#x -> %+v", c.usage, k)
		}
	}
	for _, u := range []uint16{0, 0x03, 0x32, 0x66, 0xE8, 0xffff} {
		if _, ok := lookupKey(u); ok {
			t.Errorf("usage %#x must be unknown", u)
		}
	}
}

func TestMapPointAndFitScale(t *testing.T) {
	view := image.Rect(-1280, 0, 0, 1024)
	if x, y := mapPoint(view, 2, 10, 20); x != -1280+21 || y != 41 {
		t.Fatalf("mapPoint %d %d", x, y)
	}
	if x, y := mapPoint(view, 1, 99999, -5); x != -1 || y != 0 {
		t.Fatalf("mapPoint clamp %d %d", x, y)
	}
	if fitScale(image.Rect(0, 0, 1920, 1080), 1) != 1 || fitScale(image.Rect(0, 0, 20000, 1000), 1) != 2 ||
		fitScale(image.Rect(0, 0, 15360, 8640), 1) != 2 || fitScale(image.Rect(0, 0, 70000, 100), 1) != 0 {
		t.Fatal("fitScale")
	}
}
