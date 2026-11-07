package rdesk

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A minimal X11 client in pure Go (no cgo, no Xlib): connection setup
// with MIT-MAGIC-COOKIE-1, GetImage of the root window for capture and
// the XTEST extension for input. Only local displays (Unix sockets) are
// used; X11 over TCP is plaintext and is refused. MIT-SHM, RandR (several
// monitors) and the clipboard (selections) are not implemented: the whole
// root window is one monitor. Wayland sessions are not supported.

const (
	x11OpGetInputFocus      = 43
	x11OpGetImage           = 73
	x11OpQueryExtension     = 98
	x11OpGetKeyboardMapping = 101
	x11XTestFakeInput       = 2

	x11KeyPress      = 2
	x11KeyRelease    = 3
	x11ButtonPress   = 4
	x11ButtonRelease = 5
	x11MotionNotify  = 6

	x11ZPixmap      = 2
	x11GenericEvent = 35
	x11MaxReply     = 512 << 20
	x11IOTimeout    = 10 * time.Second
	x11SyncEvery    = 64

	xauthFamilyLocal = 256
	xauthFamilyWild  = 65535
	xauthCookieName  = "MIT-MAGIC-COOKIE-1"

	xkShiftL = 0xffe1
)

var le = binary.LittleEndian

type x11Format struct {
	depth, bpp, pad uint8
}

type x11Key struct {
	code  uint8
	shift bool
}

type x11Conn struct {
	mu   sync.Mutex
	c    net.Conn
	br   *bufio.Reader
	seq  uint16
	sent int

	root          uint32
	width, height int
	depth         uint8
	bpp, pad      int
	redMask       uint32
	greenMask     uint32
	blueMask      uint32
	imageMSB      bool
	minKey        uint8
	maxKey        uint8
	xtest         uint8
	keys          map[uint32]x11Key
}

// parseDisplay parses a local DISPLAY value (":0", ":1.0", "unix:0") into
// display and screen numbers.
func parseDisplay(d string) (int, int, error) {
	host, rest, ok := strings.Cut(d, ":")
	if !ok || (host != "" && host != "unix") {
		return 0, 0, fmt.Errorf("%w: yalnızca yerel X11 ekranı (:N) desteklenir", ErrUnsupported)
	}
	num, scr, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 || n > 9999 {
		return 0, 0, fmt.Errorf("%w: geçersiz DISPLAY", ErrUnsupported)
	}
	s := 0
	if scr != "" {
		if s, err = strconv.Atoi(scr); err != nil || s < 0 || s > 255 {
			return 0, 0, fmt.Errorf("%w: geçersiz DISPLAY", ErrUnsupported)
		}
	}
	return n, s, nil
}

// readXauthority returns the MIT-MAGIC-COOKIE-1 for the display from an
// Xauthority file, or nil when there is none.
func readXauthority(r io.Reader, hostname string, display int) []byte {
	br := bufio.NewReader(io.LimitReader(r, 1<<20))
	field := func() ([]byte, bool) {
		var n [2]byte
		if _, err := io.ReadFull(br, n[:]); err != nil {
			return nil, false
		}
		b := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, false
		}
		return b, true
	}
	want := strconv.Itoa(display)
	var fallback []byte
	for {
		var fam [2]byte
		if _, err := io.ReadFull(br, fam[:]); err != nil {
			return fallback
		}
		addr, ok1 := field()
		num, ok2 := field()
		name, ok3 := field()
		data, ok4 := field()
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return fallback
		}
		if string(name) != xauthCookieName || (len(num) > 0 && string(num) != want) {
			continue
		}
		switch binary.BigEndian.Uint16(fam[:]) {
		case xauthFamilyWild:
			return data
		case xauthFamilyLocal:
			if string(addr) == hostname {
				return data
			}
			if fallback == nil {
				fallback = data
			}
		}
	}
}

// dialX11 connects to the local display named by display (DISPLAY) with
// the cookie from authFile (XAUTHORITY or ~/.Xauthority).
func dialX11(display, authFile string) (*x11Conn, error) {
	if display == "" {
		return nil, fmt.Errorf("%w: DISPLAY tanımlı değil (masaüstü oturumu yok)", ErrUnsupported)
	}
	num, screen, err := parseDisplay(display)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/tmp/.X11-unix/X%d", num)
	c, err := net.DialTimeout("unix", path, x11IOTimeout)
	if err != nil {
		var err2 error
		if c, err2 = net.DialTimeout("unix", "@"+path, x11IOTimeout); err2 != nil {
			return nil, fmt.Errorf("%w: X11 soketine bağlanılamadı: %v", ErrUnsupported, err)
		}
	}
	if authFile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			authFile = filepath.Join(home, ".Xauthority")
		}
	}
	var cookie []byte
	if authFile != "" {
		if f, err := os.Open(authFile); err == nil {
			host, _ := os.Hostname()
			cookie = readXauthority(f, host, num)
			_ = f.Close()
		}
	}
	x, err := newX11Conn(c, cookie, screen)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return x, nil
}

func pad4(n int) int { return (4 - n%4) % 4 }

// newX11Conn performs the connection setup on c.
func newX11Conn(c net.Conn, cookie []byte, screen int) (*x11Conn, error) {
	x := &x11Conn{c: c, br: bufio.NewReaderSize(c, 64<<10)}
	_ = c.SetDeadline(time.Now().Add(x11IOTimeout))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	var name []byte
	if len(cookie) > 0 {
		name = []byte(xauthCookieName)
	}
	req := []byte{'l', 0}
	req = le.AppendUint16(req, 11)
	req = le.AppendUint16(req, 0)
	req = le.AppendUint16(req, uint16(len(name)))
	req = le.AppendUint16(req, uint16(len(cookie)))
	req = append(req, 0, 0)
	req = append(req, name...)
	req = append(req, make([]byte, pad4(len(name)))...)
	req = append(req, cookie...)
	req = append(req, make([]byte, pad4(len(cookie)))...)
	if _, err := c.Write(req); err != nil {
		return nil, fmt.Errorf("X11 kurulumu gönderilemedi: %w", err)
	}
	var hdr [8]byte
	if _, err := io.ReadFull(x.br, hdr[:]); err != nil {
		return nil, fmt.Errorf("X11 kurulum yanıtı okunamadı: %w", err)
	}
	extra := int(le.Uint16(hdr[6:])) * 4
	body := make([]byte, extra)
	if _, err := io.ReadFull(x.br, body); err != nil {
		return nil, fmt.Errorf("X11 kurulum yanıtı okunamadı: %w", err)
	}
	if hdr[0] != 1 {
		reason := body
		if hdr[0] == 0 && int(hdr[1]) <= len(body) {
			reason = body[:hdr[1]]
		}
		return nil, fmt.Errorf("%w: X11 bağlantıyı reddetti: %s", ErrUnsupported, strings.TrimSpace(string(bytes.ToValidUTF8(reason, nil))))
	}
	if err := x.parseSetup(body, screen); err != nil {
		return nil, err
	}
	return x, nil
}

func (x *x11Conn) parseSetup(b []byte, screen int) error {
	bad := fmt.Errorf("%w: X11 kurulum yanıtı çözülemedi", ErrProtocol)
	if len(b) < 32 {
		return bad
	}
	vendorLen := int(le.Uint16(b[16:]))
	nScreens, nFormats := int(b[20]), int(b[21])
	x.imageMSB = b[22] == 1
	x.minKey, x.maxKey = b[26], b[27]
	off := 32 + vendorLen + pad4(vendorLen)
	formats := make([]x11Format, 0, nFormats)
	for range nFormats {
		if off+8 > len(b) {
			return bad
		}
		formats = append(formats, x11Format{depth: b[off], bpp: b[off+1], pad: b[off+2]})
		off += 8
	}
	if screen >= nScreens {
		return fmt.Errorf("%w: X11 ekranı %d yok", ErrUnsupported, screen)
	}
	for i := 0; i <= screen; i++ {
		if off+40 > len(b) {
			return bad
		}
		s := b[off:]
		root, rootVisual := le.Uint32(s[0:]), le.Uint32(s[32:])
		width, height := int(le.Uint16(s[20:])), int(le.Uint16(s[22:]))
		depth, nDepths := s[38], int(s[39])
		off += 40
		var red, green, blue uint32
		found := false
		for range nDepths {
			if off+8 > len(b) {
				return bad
			}
			nVis := int(le.Uint16(b[off+2:]))
			off += 8
			for range nVis {
				if off+24 > len(b) {
					return bad
				}
				v := b[off:]
				if le.Uint32(v[0:]) == rootVisual {
					red, green, blue, found = le.Uint32(v[8:]), le.Uint32(v[12:]), le.Uint32(v[16:]), true
				}
				off += 24
			}
		}
		if i != screen {
			continue
		}
		if !found || red == 0 || green == 0 || blue == 0 {
			return fmt.Errorf("%w: X11 kök görseli TrueColor değil", ErrUnsupported)
		}
		x.root, x.width, x.height, x.depth = root, width, height, depth
		x.redMask, x.greenMask, x.blueMask = red, green, blue
		for _, f := range formats {
			if f.depth == depth {
				x.bpp, x.pad = int(f.bpp), int(f.pad)
			}
		}
		if x.bpp != 16 && x.bpp != 24 && x.bpp != 32 || x.pad == 0 || x.pad%8 != 0 {
			return fmt.Errorf("%w: X11 piksel biçimi desteklenmiyor (%d bpp)", ErrUnsupported, x.bpp)
		}
		if width <= 0 || height <= 0 {
			return bad
		}
	}
	return nil
}

func (x *x11Conn) Close() error { return x.c.Close() }

// send writes one request and returns its sequence number. Caller holds mu.
func (x *x11Conn) send(req []byte) (uint16, error) {
	_ = x.c.SetWriteDeadline(time.Now().Add(x11IOTimeout))
	if _, err := x.c.Write(req); err != nil {
		return 0, err
	}
	x.seq++
	x.sent++
	return x.seq, nil
}

// reply reads until the reply (or error) for seq, skipping events and
// errors of earlier requests that have no reply. Caller holds mu.
func (x *x11Conn) reply(seq uint16) ([]byte, error) {
	_ = x.c.SetReadDeadline(time.Now().Add(x11IOTimeout))
	defer func() { _ = x.c.SetReadDeadline(time.Time{}) }()
	for {
		var hdr [32]byte
		if _, err := io.ReadFull(x.br, hdr[:]); err != nil {
			return nil, err
		}
		got := le.Uint16(hdr[2:])
		switch hdr[0] {
		case 0:
			if got == seq {
				return nil, fmt.Errorf("X11 hatası %d", hdr[1])
			}
		case 1:
			n := int64(le.Uint32(hdr[4:])) * 4
			if n > x11MaxReply {
				return nil, fmt.Errorf("%w: X11 yanıtı çok büyük", ErrProtocol)
			}
			out := make([]byte, 32+n)
			copy(out, hdr[:])
			if _, err := io.ReadFull(x.br, out[32:]); err != nil {
				return nil, err
			}
			if got == seq {
				return out, nil
			}
		default:
			if hdr[0]&0x7f == x11GenericEvent {
				n := int64(le.Uint32(hdr[4:])) * 4
				if n > x11MaxReply {
					return nil, ErrProtocol
				}
				if _, err := io.CopyN(io.Discard, x.br, n); err != nil {
					return nil, err
				}
			}
		}
	}
}

func (x *x11Conn) monitors() []Monitor {
	return []Monitor{{Bounds: image.Rect(0, 0, x.width, x.height), Primary: true}}
}

// getImage reads rectangle r of the root window into dst.
func (x *x11Conn) getImage(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	r = r.Intersect(image.Rect(0, 0, x.width, x.height))
	w, h := r.Dx(), r.Dy()
	if w <= 0 || h <= 0 {
		return nil, errors.New("rdesk: geçersiz yakalama alanı")
	}
	req := []byte{x11OpGetImage, x11ZPixmap}
	req = le.AppendUint16(req, 5)
	req = le.AppendUint32(req, x.root)
	req = le.AppendUint16(req, uint16(int16(r.Min.X)))
	req = le.AppendUint16(req, uint16(int16(r.Min.Y)))
	req = le.AppendUint16(req, uint16(w))
	req = le.AppendUint16(req, uint16(h))
	req = le.AppendUint32(req, 0xffffffff)
	x.mu.Lock()
	seq, err := x.send(req)
	var rep []byte
	if err == nil {
		rep, err = x.reply(seq)
	}
	x.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("X11 GetImage: %w", err)
	}
	stride := (w*x.bpp + x.pad - 1) / x.pad * x.pad / 8
	data := rep[32:]
	if len(data) < stride*h {
		return nil, fmt.Errorf("%w: X11 görüntüsü kısa", ErrProtocol)
	}
	if dst == nil || dst.Rect.Dx() != w || dst.Rect.Dy() != h || dst.Rect.Min != (image.Point{}) {
		dst = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	x.convert(dst, data, stride, w, h)
	return dst, nil
}

// channel extracts one color channel from a pixel value as 8 bits.
func channel(v, mask uint32) uint8 {
	shift := bits.TrailingZeros32(mask)
	n := bits.OnesCount32(mask)
	c := (v & mask) >> shift
	switch {
	case n == 8:
		return uint8(c)
	case n > 8:
		return uint8(c >> (n - 8))
	default:
		return uint8(c * 255 / (1<<n - 1))
	}
}

func (x *x11Conn) convert(dst *image.RGBA, data []byte, stride, w, h int) {
	fast := x.bpp == 32 && !x.imageMSB && x.redMask == 0xff0000 && x.greenMask == 0xff00 && x.blueMask == 0xff
	for y := range h {
		src := data[y*stride:]
		out := dst.Pix[dst.PixOffset(0, y):]
		if fast {
			for i := 0; i < w*4; i += 4 {
				out[i], out[i+1], out[i+2], out[i+3] = src[i+2], src[i+1], src[i], 0xff
			}
			continue
		}
		bpp := x.bpp / 8
		for i := range w {
			p := src[i*bpp : i*bpp+bpp]
			var v uint32
			switch {
			case bpp == 4 && x.imageMSB:
				v = binary.BigEndian.Uint32(p)
			case bpp == 4:
				v = le.Uint32(p)
			case bpp == 3 && x.imageMSB:
				v = uint32(p[0])<<16 | uint32(p[1])<<8 | uint32(p[2])
			case bpp == 3:
				v = uint32(p[2])<<16 | uint32(p[1])<<8 | uint32(p[0])
			case x.imageMSB:
				v = uint32(binary.BigEndian.Uint16(p))
			default:
				v = uint32(le.Uint16(p))
			}
			out[i*4], out[i*4+1], out[i*4+2], out[i*4+3] = channel(v, x.redMask), channel(v, x.greenMask), channel(v, x.blueMask), 0xff
		}
	}
}

// --- XTEST input ---

func (x *x11Conn) initInput() error {
	name := "XTEST"
	req := []byte{x11OpQueryExtension, 0}
	req = le.AppendUint16(req, uint16(2+(len(name)+pad4(len(name)))/4))
	req = le.AppendUint16(req, uint16(len(name)))
	req = append(req, 0, 0)
	req = append(req, name...)
	req = append(req, make([]byte, pad4(len(name)))...)
	x.mu.Lock()
	defer x.mu.Unlock()
	seq, err := x.send(req)
	if err != nil {
		return err
	}
	rep, err := x.reply(seq)
	if err != nil {
		return err
	}
	if rep[8] == 0 {
		return fmt.Errorf("%w: X11 sunucusunda XTEST yok", ErrUnsupported)
	}
	x.xtest = rep[9]
	return x.loadKeyboard()
}

// loadKeyboard builds keysym -> keycode from GetKeyboardMapping. Caller
// holds mu.
func (x *x11Conn) loadKeyboard() error {
	if x.maxKey < x.minKey {
		return ErrProtocol
	}
	count := int(x.maxKey) - int(x.minKey) + 1
	req := []byte{x11OpGetKeyboardMapping, 0}
	req = le.AppendUint16(req, 2)
	req = append(req, x.minKey, uint8(count), 0, 0)
	seq, err := x.send(req)
	if err != nil {
		return err
	}
	rep, err := x.reply(seq)
	if err != nil {
		return err
	}
	per := int(rep[1])
	data := rep[32:]
	if per == 0 || len(data) < count*per*4 {
		return ErrProtocol
	}
	x.keys = make(map[uint32]x11Key)
	for col := range min(per, 2) {
		for i := range count {
			ks := le.Uint32(data[(i*per+col)*4:])
			if ks == 0 {
				continue
			}
			if _, ok := x.keys[ks]; !ok {
				x.keys[ks] = x11Key{code: x.minKey + uint8(i), shift: col == 1}
			}
		}
	}
	return nil
}

// fakeInput sends XTEST FakeInput requests. Caller holds mu.
func (x *x11Conn) fakeInput(typ, detail uint8, rx, ry int) error {
	req := []byte{x.xtest, x11XTestFakeInput}
	req = le.AppendUint16(req, 9)
	req = append(req, typ, detail, 0, 0)
	req = le.AppendUint32(req, 0) // CurrentTime
	req = le.AppendUint32(req, x.root)
	req = append(req, make([]byte, 8)...)
	req = le.AppendUint16(req, uint16(int16(rx)))
	req = le.AppendUint16(req, uint16(int16(ry)))
	req = append(req, make([]byte, 8)...) // 7 bytes pad + deviceid 0
	_, err := x.send(req)
	return err
}

// sync drains errors of earlier no-reply requests now and then. Caller
// holds mu.
func (x *x11Conn) sync() error {
	if x.sent < x11SyncEvery {
		return nil
	}
	x.sent = 0
	seq, err := x.send([]byte{x11OpGetInputFocus, 0, 1, 0})
	if err != nil {
		return err
	}
	_, err = x.reply(seq)
	return err
}

// x11Injector injects input with XTEST.
type x11Injector struct {
	x       *x11Conn
	buttons uint8
}

func newX11Injector(x *x11Conn) (*x11Injector, error) {
	if err := x.initInput(); err != nil {
		return nil, err
	}
	return &x11Injector{x: x}, nil
}

func (in *x11Injector) Close() error { return in.x.Close() }

func (in *x11Injector) Pointer(px, py int, buttons uint8) error {
	x := in.x
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.fakeInput(x11MotionNotify, 0, clampInt(px, 0, x.width-1), clampInt(py, 0, x.height-1)); err != nil {
		return err
	}
	for _, b := range []struct {
		bit    uint8
		button uint8
	}{{ButtonLeft, 1}, {ButtonMiddle, 2}, {ButtonRight, 3}} {
		was, is := in.buttons&b.bit != 0, buttons&b.bit != 0
		if was == is {
			continue
		}
		typ := uint8(x11ButtonRelease)
		if is {
			typ = x11ButtonPress
		}
		if err := x.fakeInput(typ, b.button, 0, 0); err != nil {
			return err
		}
	}
	in.buttons = buttons
	return x.sync()
}

func (in *x11Injector) Wheel(dx, dy int) error {
	x := in.x
	x.mu.Lock()
	defer x.mu.Unlock()
	click := func(button uint8, n int) error {
		for range n {
			if err := x.fakeInput(x11ButtonPress, button, 0, 0); err != nil {
				return err
			}
			if err := x.fakeInput(x11ButtonRelease, button, 0, 0); err != nil {
				return err
			}
		}
		return nil
	}
	var err error
	switch {
	case dy > 0:
		err = click(4, dy)
	case dy < 0:
		err = click(5, -dy)
	}
	if err == nil {
		switch {
		case dx > 0:
			err = click(7, dx)
		case dx < 0:
			err = click(6, -dx)
		}
	}
	if err != nil {
		return err
	}
	return x.sync()
}

func (in *x11Injector) Key(usage uint16, down bool) error {
	k, ok := lookupKey(usage)
	if !ok {
		return fmt.Errorf("rdesk: bilinmeyen tuş %#x", usage)
	}
	x := in.x
	x.mu.Lock()
	defer x.mu.Unlock()
	code, ok := x.keys[k.keysym]
	if !ok && k.keysym == 0xfe03 {
		code, ok = x.keys[0xffea] // Alt_R when there is no AltGr keysym
	}
	if !ok {
		return fmt.Errorf("rdesk: klavye düzeninde tuş yok %#x", k.keysym)
	}
	typ := uint8(x11KeyRelease)
	if down {
		typ = x11KeyPress
	}
	if err := x.fakeInput(typ, code.code, 0, 0); err != nil {
		return err
	}
	return x.sync()
}

// runeKeysym returns the X11 keysym of a character.
func runeKeysym(r rune) uint32 {
	switch {
	case r == '\n':
		return 0xff0d
	case r == '\t':
		return 0xff09
	case (r >= 0x20 && r <= 0x7e) || (r >= 0xa0 && r <= 0xff):
		return uint32(r)
	default:
		return 0x01000000 | uint32(r)
	}
}

func (in *x11Injector) Text(s string) error {
	x := in.x
	x.mu.Lock()
	defer x.mu.Unlock()
	shift, hasShift := x.keys[xkShiftL]
	for _, r := range s {
		k, ok := x.keys[runeKeysym(r)]
		if !ok || (k.shift && !hasShift) {
			continue // not on the current layout
		}
		if k.shift {
			if err := x.fakeInput(x11KeyPress, shift.code, 0, 0); err != nil {
				return err
			}
		}
		if err := x.fakeInput(x11KeyPress, k.code, 0, 0); err != nil {
			return err
		}
		if err := x.fakeInput(x11KeyRelease, k.code, 0, 0); err != nil {
			return err
		}
		if k.shift {
			if err := x.fakeInput(x11KeyRelease, shift.code, 0, 0); err != nil {
				return err
			}
		}
	}
	return x.sync()
}

// x11Capturer captures the root window.
type x11Capturer struct {
	x *x11Conn
}

func (c *x11Capturer) Monitors() ([]Monitor, error) { return c.x.monitors(), nil }

func (c *x11Capturer) Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	return c.x.getImage(r, dst)
}

func (c *x11Capturer) Close() error { return c.x.Close() }
