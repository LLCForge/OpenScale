package rdesk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"sync"
	"testing"
)

// fakeX11 is a tiny X server speaking just enough of the protocol for the
// client in x11.go.
type fakeX11 struct {
	t      *testing.T
	conn   net.Conn
	cookie []byte

	mu     sync.Mutex
	inputs []string
	seq    uint16
	gets   int
	lastFI uint16
}

const fakeW, fakeH = 4, 3

func fakePixel(x, y int) (r, g, b uint8) { return uint8(x * 10), uint8(y * 10), 7 }

func (f *fakeX11) setupBody() []byte {
	b := make([]byte, 0, 128)
	b = le.AppendUint32(b, 0)                // release
	b = le.AppendUint32(b, 0x200000)         // resource id base
	b = le.AppendUint32(b, 0x1fffff)         // resource id mask
	b = le.AppendUint32(b, 0)                // motion buffer
	b = le.AppendUint16(b, 4)                // vendor length
	b = le.AppendUint16(b, 0xffff)           // max request length
	b = append(b, 1, 1, 0, 0, 32, 32, 8, 10) // screens, formats, orders, scanline, keycodes
	b = append(b, 0, 0, 0, 0)                // pad
	b = append(b, "test"...)                 // vendor
	b = append(b, 24, 32, 32, 0, 0, 0, 0, 0) // format: depth 24, 32 bpp, pad 32
	b = le.AppendUint32(b, 0x100)            // root
	b = append(b, make([]byte, 16)...)       // colormap, white, black, input masks
	b = le.AppendUint16(b, fakeW)            // width
	b = le.AppendUint16(b, fakeH)            // height
	b = append(b, make([]byte, 8)...)        // mm sizes, maps
	b = le.AppendUint32(b, 0x21)             // root visual
	b = append(b, 0, 0, 24, 1)               // backing, save unders, depth, depths
	b = append(b, 24, 0, 1, 0, 0, 0, 0, 0)   // depth 24 with one visual
	b = le.AppendUint32(b, 0x21)             // visual id
	b = append(b, 4, 8, 0, 1)                // TrueColor, 8 bits, 256 entries
	b = le.AppendUint32(b, 0xff0000)         // red
	b = le.AppendUint32(b, 0x00ff00)         // green
	b = le.AppendUint32(b, 0x0000ff)         // blue
	return append(b, 0, 0, 0, 0)
}

func (f *fakeX11) serve() {
	var hdr [12]byte
	if _, err := io.ReadFull(f.conn, hdr[:]); err != nil {
		return
	}
	nameLen, dataLen := int(le.Uint16(hdr[6:])), int(le.Uint16(hdr[8:]))
	auth := make([]byte, nameLen+pad4(nameLen)+dataLen+pad4(dataLen))
	if _, err := io.ReadFull(f.conn, auth); err != nil {
		return
	}
	name := string(auth[:nameLen])
	data := auth[nameLen+pad4(nameLen) : nameLen+pad4(nameLen)+dataLen]
	if hdr[0] != 'l' || name != xauthCookieName || !bytes.Equal(data, f.cookie) {
		msg := "No protocol specified"
		rep := []byte{0, byte(len(msg))}
		rep = le.AppendUint16(rep, 11)
		rep = le.AppendUint16(rep, 0)
		rep = le.AppendUint16(rep, uint16((len(msg)+pad4(len(msg)))/4))
		rep = append(rep, msg...)
		rep = append(rep, make([]byte, pad4(len(msg)))...)
		_, _ = f.conn.Write(rep)
		return
	}
	body := f.setupBody()
	rep := []byte{1, 0}
	rep = le.AppendUint16(rep, 11)
	rep = le.AppendUint16(rep, 0)
	rep = le.AppendUint16(rep, uint16(len(body)/4))
	if _, err := f.conn.Write(append(rep, body...)); err != nil {
		return
	}
	for {
		var rh [4]byte
		if _, err := io.ReadFull(f.conn, rh[:]); err != nil {
			return
		}
		n := int(le.Uint16(rh[2:]))*4 - 4
		req := make([]byte, n)
		if _, err := io.ReadFull(f.conn, req); err != nil {
			return
		}
		f.seq++
		if err := f.handle(rh, req); err != nil {
			f.t.Error(err)
			return
		}
	}
}

func (f *fakeX11) reply(extra byte, body []byte) error {
	h := []byte{1, extra}
	h = le.AppendUint16(h, f.seq)
	words := 0
	if len(body) > 24 {
		words = (len(body) - 24 + 3) / 4
	}
	h = le.AppendUint32(h, uint32(words))
	full := make([]byte, 24+words*4)
	copy(full, body)
	_, err := f.conn.Write(append(h, full...))
	return err
}

func (f *fakeX11) handle(rh [4]byte, req []byte) error {
	switch rh[0] {
	case x11OpGetImage:
		x, y := int(int16(le.Uint16(req[4:]))), int(int16(le.Uint16(req[6:])))
		w, h := int(le.Uint16(req[8:])), int(le.Uint16(req[10:]))
		if rh[1] != x11ZPixmap || le.Uint32(req[0:]) != 0x100 {
			return fmt.Errorf("bad GetImage % x", req)
		}
		f.gets++
		if f.gets == 2 {
			// An error for an earlier no-reply request and an event must
			// be skipped by the client.
			e := make([]byte, 32)
			e[0], e[1] = 0, 2
			le.PutUint16(e[2:], f.lastFI)
			ev := make([]byte, 32)
			ev[0] = 12
			if _, err := f.conn.Write(append(e, ev...)); err != nil {
				return err
			}
		}
		body := le.AppendUint32(nil, 0x21)
		body = append(body, make([]byte, 20)...)
		for yy := y; yy < y+h; yy++ {
			for xx := x; xx < x+w; xx++ {
				r, g, b := fakePixel(xx, yy)
				body = le.AppendUint32(body, uint32(r)<<16|uint32(g)<<8|uint32(b))
			}
		}
		return f.reply(24, body)
	case x11OpQueryExtension:
		n := int(le.Uint16(req[0:]))
		if string(req[4:4+n]) != "XTEST" {
			return f.reply(0, make([]byte, 24))
		}
		body := make([]byte, 24)
		body[0], body[1] = 1, 140
		return f.reply(0, body)
	case x11OpGetKeyboardMapping:
		first, count := req[0], int(req[1])
		if first != 8 || count != 3 {
			return fmt.Errorf("bad GetKeyboardMapping %d %d", first, count)
		}
		body := make([]byte, 24)
		for _, ks := range []uint32{'a', 'A', xkShiftL, 0, '1', '!'} {
			body = le.AppendUint32(body, ks)
		}
		return f.reply(2, body)
	case x11OpGetInputFocus:
		return f.reply(0, make([]byte, 24))
	case 140:
		if rh[1] != x11XTestFakeInput || len(req) != 32 {
			return fmt.Errorf("bad FakeInput % x", req)
		}
		if le.Uint32(req[8:]) != 0x100 {
			return errors.New("FakeInput root")
		}
		f.mu.Lock()
		f.lastFI = f.seq
		f.inputs = append(f.inputs, fmt.Sprintf("%d/%d@%d,%d", req[0], req[1], int16(le.Uint16(req[20:])), int16(le.Uint16(req[22:]))))
		f.mu.Unlock()
		return nil
	}
	return fmt.Errorf("unexpected request %d", rh[0])
}

func startFakeX11(t *testing.T, cookie, clientCookie []byte) (*x11Conn, *fakeX11, error) {
	t.Helper()
	cs, ss := net.Pipe()
	f := &fakeX11{t: t, conn: ss, cookie: cookie}
	go f.serve()
	t.Cleanup(func() { _ = ss.Close(); _ = cs.Close() })
	x, err := newX11Conn(cs, clientCookie, 0)
	return x, f, err
}

func TestX11Setup(t *testing.T) {
	cookie := []byte("0123456789abcdef")
	if _, _, err := startFakeX11(t, cookie, []byte("wrong-cookie-123")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("wrong cookie must fail: %v", err)
	}
	x, _, err := startFakeX11(t, cookie, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if x.root != 0x100 || x.width != fakeW || x.height != fakeH || x.bpp != 32 || x.pad != 32 || x.redMask != 0xff0000 || x.minKey != 8 || x.maxKey != 10 {
		t.Fatalf("setup %+v", x)
	}
	if ms := x.monitors(); len(ms) != 1 || ms[0].Bounds != image.Rect(0, 0, fakeW, fakeH) || !ms[0].Primary {
		t.Fatalf("monitors %+v", ms)
	}
}

func TestX11CaptureAndInput(t *testing.T) {
	cookie := []byte("cookie")
	x, f, err := startFakeX11(t, cookie, cookie)
	if err != nil {
		t.Fatal(err)
	}
	c := &x11Capturer{x: x}
	img, err := c.Capture(image.Rect(1, 1, 4, 3), nil)
	if err != nil {
		t.Fatal(err)
	}
	if img.Rect != image.Rect(0, 0, 3, 2) {
		t.Fatalf("rect %v", img.Rect)
	}
	for y := 0; y < 2; y++ {
		for x := 0; x < 3; x++ {
			r, g, b := fakePixel(x+1, y+1)
			o := img.PixOffset(x, y)
			if img.Pix[o] != r || img.Pix[o+1] != g || img.Pix[o+2] != b || img.Pix[o+3] != 0xff {
				t.Fatalf("pixel %d,%d = % x", x, y, img.Pix[o:o+4])
			}
		}
	}

	in, err := newX11Injector(x)
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return in.Pointer(2, 99, ButtonLeft|ButtonRight) },
		func() error { return in.Pointer(3, 1, ButtonRight) },
		func() error { return in.Wheel(1, -1) },
		func() error { return in.Key(0x04, true) },  // a
		func() error { return in.Key(0xE1, false) }, // left shift
		func() error { return in.Text("A1!é") },     // é is not on the layout
	}
	for i, s := range steps {
		if err := s(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if err := in.Key(0x05, true); err == nil {
		t.Fatal("key missing from the layout must fail")
	}
	// A second capture skips the queued error and event.
	if _, err := c.Capture(image.Rect(0, 0, 4, 3), img); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	got := append([]string(nil), f.inputs...)
	f.mu.Unlock()
	want := []string{
		"6/0@2,2", "4/1@0,0", "4/3@0,0", // move (clamped), left and right down
		"6/0@3,1", "5/1@0,0", // move, left up
		"4/5@0,0", "5/5@0,0", "4/7@0,0", "5/7@0,0", // wheel down once, right once
		"2/8@0,0",                                  // a down
		"3/9@0,0",                                  // shift up
		"2/9@0,0", "2/8@0,0", "3/8@0,0", "3/9@0,0", // A
		"2/10@0,0", "3/10@0,0", // 1
		"2/9@0,0", "2/10@0,0", "3/10@0,0", "3/9@0,0", // !
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("fake input\n got %v\nwant %v", got, want)
	}
}

func TestParseDisplayAndXauthority(t *testing.T) {
	for d, want := range map[string][2]int{":0": {0, 0}, ":1.2": {1, 2}, "unix:10": {10, 0}} {
		n, s, err := parseDisplay(d)
		if err != nil || n != want[0] || s != want[1] {
			t.Errorf("%q -> %d %d %v", d, n, s, err)
		}
	}
	for _, d := range []string{"", "host:0", "10.0.0.1:0", ":x", ":0.x", ":-1"} {
		if _, _, err := parseDisplay(d); err == nil {
			t.Errorf("%q must be rejected", d)
		}
	}
	entry := func(fam uint16, addr, num, name, data string) []byte {
		b := binary.BigEndian.AppendUint16(nil, fam)
		for _, s := range []string{addr, num, name, data} {
			b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
			b = append(b, s...)
		}
		return b
	}
	var file []byte
	file = append(file, entry(xauthFamilyLocal, "baska", "0", xauthCookieName, "OTHER")...)
	file = append(file, entry(xauthFamilyLocal, "makine", "1", xauthCookieName, "ONE")...)
	file = append(file, entry(xauthFamilyLocal, "makine", "0", "XDM-AUTHORIZATION-1", "XDM")...)
	file = append(file, entry(xauthFamilyLocal, "makine", "0", xauthCookieName, "ZERO")...)
	if got := readXauthority(bytes.NewReader(file), "makine", 0); string(got) != "ZERO" {
		t.Fatalf("cookie %q", got)
	}
	if got := readXauthority(bytes.NewReader(file), "kapsayici", 0); string(got) != "OTHER" {
		t.Fatalf("fallback cookie %q", got)
	}
	if got := readXauthority(bytes.NewReader(file[:7]), "makine", 0); got != nil {
		t.Fatal("truncated file")
	}
	if _, err := dialX11("", ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("empty DISPLAY")
	}
}

func TestX11Channel(t *testing.T) {
	if channel(0xf800, 0xf800) != 0xff || channel(0x07e0, 0x07e0) != 0xff || channel(0, 0x1f) != 0 || channel(0x3ff00000, 0x3ff00000) != 0xff {
		t.Fatal("channel scaling")
	}
}
