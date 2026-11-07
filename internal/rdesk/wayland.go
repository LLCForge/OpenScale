package rdesk

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"image"
	"os"
	"strings"

	"github.com/openscale/openscale/internal/dbuswire"
)

// Wayland remote desktop (ADR-0236, #854). A Wayland compositor gives no
// client the screen or synthetic input; xdg-desktop-portal does, after the
// user agrees in the portal's own dialog: the ScreenCast interface hands
// out PipeWire video streams and the RemoteDesktop interface takes pointer
// and keyboard events. The parts here are free of the bus and of PipeWire,
// so they are tested on every system; wayland_linux.go speaks to the
// portal over internal/dbuswire and wayland_pipewire_cgo.go reads frames.

// platformDevices, when set, opens the screen and (for control) input
// together; handled is false when the platform has nothing special to do
// and the separate NewScreenCapturer / NewInputInjector are used.
var platformDevices func(control bool) (c Capturer, inj Injector, handled bool, err error)

// ErrWaylandNeedsCgo: this build cannot read PipeWire video.
var ErrWaylandNeedsCgo = errors.New("rdesk: Wayland ekranı için cgo ile derlenmiş OpenScale gerekir (PipeWire); X11 oturumu veya cgo derlemesi kullanın")

// ErrPortalDenied: the user refused or closed the portal dialog.
var ErrPortalDenied = errors.New("rdesk: ekran paylaşımı izni verilmedi (portal penceresi)")

// WaylandSession reports whether this process runs in a Wayland desktop
// session: XDG_SESSION_TYPE says so, or, when it is unset, only
// WAYLAND_DISPLAY is there.
func WaylandSession() bool { return waylandSession(os.Getenv) }

func waylandSession(getenv func(string) string) bool {
	switch strings.ToLower(strings.TrimSpace(getenv("XDG_SESSION_TYPE"))) {
	case "wayland":
		return true
	case "":
		return getenv("WAYLAND_DISPLAY") != "" && getenv("DISPLAY") == ""
	}
	return false
}

// Portal names.
const (
	portalBus          = "org.freedesktop.portal.Desktop"
	portalPath         = dbuswire.ObjectPath("/org/freedesktop/portal/desktop")
	portalScreenCast   = "org.freedesktop.portal.ScreenCast"
	portalRemote       = "org.freedesktop.portal.RemoteDesktop"
	portalRequest      = "org.freedesktop.portal.Request"
	portalSessionIface = "org.freedesktop.portal.Session"
)

// ScreenCast and RemoteDesktop option values.
const (
	sourceMonitor     uint32 = 1
	cursorHidden      uint32 = 1
	cursorEmbedded    uint32 = 2
	deviceKeyboard    uint32 = 1
	devicePointer     uint32 = 2
	portalAxisVert    uint32 = 0
	portalAxisHoriz   uint32 = 1
	portalKeyReleased uint32 = 0
	portalKeyPressed  uint32 = 1
)

// newPortalToken returns a handle token: letters, digits and "_" only.
func newPortalToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "openscale_" + hex.EncodeToString(b[:])
}

// portalSender is the unique name as it appears in request paths: no
// leading ":" and "_" for ".".
func portalSender(unique string) string {
	return strings.ReplaceAll(strings.TrimPrefix(unique, ":"), ".", "_")
}

// portalRequestPath is where the portal will create the request object
// for token, so the caller can listen before it calls.
func portalRequestPath(unique, token string) dbuswire.ObjectPath {
	return dbuswire.ObjectPath("/org/freedesktop/portal/desktop/request/" + portalSender(unique) + "/" + token)
}

// portalStream is one shared monitor.
type portalStream struct {
	node uint32
	// pos and size are in the compositor's logical coordinates; hasPos
	// is false when the portal did not say.
	pos    image.Point
	size   image.Point
	hasPos bool
}

// maxPortalStreams bounds what a portal answer may list.
const maxPortalStreams = 8

// parseStreams reads Start's "streams" result: a(ua{sv}).
func parseStreams(results map[string]dbuswire.Variant) ([]portalStream, error) {
	v, ok := results["streams"]
	if !ok || v.Sig != "a(ua{sv})" {
		return nil, errors.New("rdesk: portal ekran akışı vermedi")
	}
	list, _ := v.Value.([]any)
	if len(list) == 0 || len(list) > maxPortalStreams {
		return nil, errors.New("rdesk: portal akış sayısı geçersiz")
	}
	var out []portalStream
	for _, e := range list {
		st, ok := e.(dbuswire.Struct)
		if !ok || len(st) != 2 {
			return nil, errors.New("rdesk: portal akışı bozuk")
		}
		node, ok := st[0].(uint32)
		if !ok || node == 0 {
			return nil, errors.New("rdesk: portal akış düğümü geçersiz")
		}
		s := portalStream{node: node}
		props := variantMap(st[1])
		if p, ok := intPair(props["position"]); ok {
			s.pos, s.hasPos = p, true
		}
		if sz, ok := intPair(props["size"]); ok && sz.X > 0 && sz.Y > 0 && sz.X <= maxDim && sz.Y <= maxDim {
			s.size = sz
		}
		out = append(out, s)
	}
	return out, nil
}

// variantMap turns a decoded a{sv} into a map.
func variantMap(v any) map[string]dbuswire.Variant {
	out := map[string]dbuswire.Variant{}
	entries, _ := v.([]dbuswire.DictEntry)
	for _, e := range entries {
		k, ok1 := e.Key.(string)
		val, ok2 := e.Value.(dbuswire.Variant)
		if ok1 && ok2 {
			out[k] = val
		}
	}
	return out
}

func intPair(v dbuswire.Variant) (image.Point, bool) {
	if v.Sig != "(ii)" {
		return image.Point{}, false
	}
	st, ok := v.Value.(dbuswire.Struct)
	if !ok || len(st) != 2 {
		return image.Point{}, false
	}
	x, ok1 := st[0].(int32)
	y, ok2 := st[1].(int32)
	if !ok1 || !ok2 || x < -maxDim || x > maxDim || y < -maxDim || y > maxDim {
		return image.Point{}, false
	}
	return image.Pt(int(x), int(y)), true
}

// waylandLayout places the streams on the virtual desktop in frame
// pixels. frames[i] is the frame size of stream i (0 when none arrived);
// the logical position is scaled by the stream's own frame/logical ratio,
// which keeps monitors apart when every monitor has the same scale.
// Streams without a position follow each other from left to right.
func waylandLayout(streams []portalStream, frames []image.Point) []Monitor {
	out := make([]Monitor, len(streams))
	nextX := 0
	for i, s := range streams {
		size := s.size
		if i < len(frames) && frames[i].X > 0 && frames[i].Y > 0 {
			size = frames[i]
		}
		if size.X <= 0 || size.Y <= 0 {
			size = image.Pt(1, 1)
		}
		var min image.Point
		if s.hasPos {
			sx, sy := scaleOf(s, size)
			min = image.Pt(int(float64(s.pos.X)*sx), int(float64(s.pos.Y)*sy))
		} else {
			min = image.Pt(nextX, 0)
		}
		out[i] = Monitor{Bounds: image.Rectangle{Min: min, Max: min.Add(size)}, Primary: i == 0}
		nextX = max(nextX, out[i].Bounds.Max.X)
	}
	return out
}

// scaleOf is frame pixels per logical unit of a stream.
func scaleOf(s portalStream, frame image.Point) (float64, float64) {
	if s.size.X <= 0 || s.size.Y <= 0 || frame.X <= 0 || frame.Y <= 0 {
		return 1, 1
	}
	return float64(frame.X) / float64(s.size.X), float64(frame.Y) / float64(s.size.Y)
}

// pointerTarget finds the stream under a virtual desktop point and the
// logical coordinates the portal expects for it.
func pointerTarget(streams []portalStream, mons []Monitor, x, y int) (node uint32, lx, ly float64, ok bool) {
	p := image.Pt(x, y)
	best := -1
	for i, m := range mons {
		if i < len(streams) && p.In(m.Bounds) {
			best = i
			break
		}
	}
	if best < 0 {
		// Outside every monitor: clamp to the first one.
		if len(mons) == 0 || len(streams) == 0 {
			return 0, 0, 0, false
		}
		best = 0
		b := mons[0].Bounds
		p.X = min(max(p.X, b.Min.X), b.Max.X-1)
		p.Y = min(max(p.Y, b.Min.Y), b.Max.Y-1)
	}
	m, s := mons[best], streams[best]
	sx, sy := scaleOf(s, m.Bounds.Size())
	return s.node, float64(p.X-m.Bounds.Min.X) / sx, float64(p.Y-m.Bounds.Min.Y) / sy, true
}

// Linux evdev buttons (input-event-codes.h).
const (
	btnLeft   int32 = 0x110
	btnRight  int32 = 0x111
	btnMiddle int32 = 0x112
)

// hidToEvdev maps USB HID keyboard usages to Linux evdev key codes (the
// kernel's hid_keyboard table); the portal takes evdev codes, which do
// not depend on the keyboard layout, like HID usages.
var hidToEvdev = map[uint16]int32{
	0x04: 30, 0x05: 48, 0x06: 46, 0x07: 32, 0x08: 18, 0x09: 33, 0x0a: 34, 0x0b: 35,
	0x0c: 23, 0x0d: 36, 0x0e: 37, 0x0f: 38, 0x10: 50, 0x11: 49, 0x12: 24, 0x13: 25,
	0x14: 16, 0x15: 19, 0x16: 31, 0x17: 20, 0x18: 22, 0x19: 47, 0x1a: 17, 0x1b: 45,
	0x1c: 21, 0x1d: 44, 0x1e: 2, 0x1f: 3, 0x20: 4, 0x21: 5, 0x22: 6, 0x23: 7,
	0x24: 8, 0x25: 9, 0x26: 10, 0x27: 11, 0x28: 28, 0x29: 1, 0x2a: 14, 0x2b: 15,
	0x2c: 57, 0x2d: 12, 0x2e: 13, 0x2f: 26, 0x30: 27, 0x31: 43, 0x32: 43, 0x33: 39,
	0x34: 40, 0x35: 41, 0x36: 51, 0x37: 52, 0x38: 53, 0x39: 58, 0x3a: 59, 0x3b: 60,
	0x3c: 61, 0x3d: 62, 0x3e: 63, 0x3f: 64, 0x40: 65, 0x41: 66, 0x42: 67, 0x43: 68,
	0x44: 87, 0x45: 88, 0x46: 99, 0x47: 70, 0x48: 119, 0x49: 110, 0x4a: 102, 0x4b: 104,
	0x4c: 111, 0x4d: 107, 0x4e: 109, 0x4f: 106, 0x50: 105, 0x51: 108, 0x52: 103, 0x53: 69,
	0x54: 98, 0x55: 55, 0x56: 74, 0x57: 78, 0x58: 96, 0x59: 79, 0x5a: 80, 0x5b: 81,
	0x5c: 75, 0x5d: 76, 0x5e: 77, 0x5f: 71, 0x60: 72, 0x61: 73, 0x62: 82, 0x63: 83,
	0x64: 86, 0x65: 127, 0x66: 116, 0x67: 117, 0x68: 183, 0x69: 184, 0x6a: 185, 0x6b: 186,
	0x6c: 187, 0x6d: 188, 0x6e: 189, 0x6f: 190, 0x70: 191, 0x71: 192, 0x72: 193, 0x73: 194,
	0x7f: 113, 0x80: 115, 0x81: 114, 0x87: 89, 0x88: 93, 0x89: 124, 0x8a: 92, 0x8b: 94,
	0x90: 122, 0x91: 123,
	0xe0: 29, 0xe1: 42, 0xe2: 56, 0xe3: 125, 0xe4: 97, 0xe5: 54, 0xe6: 100, 0xe7: 126,
}

// frameToRGBA converts one PipeWire frame (4 bytes per pixel, BGRx/BGRA
// or RGBx/RGBA, rows of stride bytes) into opaque RGBA rows of dst.
func frameToRGBA(dst []byte, src []byte, w, h, stride int, bgr bool) bool {
	if w <= 0 || h <= 0 || stride < w*4 || len(src) < stride*(h-1)+w*4 || len(dst) < w*h*4 {
		return false
	}
	for y := 0; y < h; y++ {
		row := src[y*stride : y*stride+w*4]
		out := dst[y*w*4 : (y+1)*w*4]
		for x := 0; x < w*4; x += 4 {
			if bgr {
				out[x], out[x+1], out[x+2] = row[x+2], row[x+1], row[x]
			} else {
				out[x], out[x+1], out[x+2] = row[x], row[x+1], row[x+2]
			}
			out[x+3] = 0xff
		}
	}
	return true
}
