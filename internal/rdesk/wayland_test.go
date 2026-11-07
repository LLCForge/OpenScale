package rdesk

import (
	"image"
	"testing"

	"github.com/openscale/openscale/internal/dbuswire"
)

func TestWaylandSessionDetection(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{"XDG_SESSION_TYPE": "wayland"}, true},
		{map[string]string{"XDG_SESSION_TYPE": "Wayland", "DISPLAY": ":0"}, true},
		{map[string]string{"XDG_SESSION_TYPE": "x11", "WAYLAND_DISPLAY": "wayland-0"}, false},
		{map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, true},
		{map[string]string{"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, false},
		{map[string]string{"XDG_SESSION_TYPE": "tty"}, false},
		{map[string]string{}, false},
	}
	for _, c := range cases {
		if got := waylandSession(func(k string) string { return c.env[k] }); got != c.want {
			t.Errorf("%v: %v", c.env, got)
		}
	}
}

func TestPortalRequestPath(t *testing.T) {
	if p := portalRequestPath(":1.42", "openscale_ab"); p != "/org/freedesktop/portal/desktop/request/1_42/openscale_ab" {
		t.Fatal(p)
	}
	tok := newPortalToken()
	if len(tok) != len("openscale_")+16 || !dbuswire.ValidObjectPath(string(portalRequestPath(":1.1", tok))) {
		t.Fatalf("token %q", tok)
	}
}

func streamEntry(node uint32, props map[string]dbuswire.Variant) dbuswire.Struct {
	var entries []dbuswire.DictEntry
	for k, v := range props {
		entries = append(entries, dbuswire.DictEntry{Key: k, Value: v})
	}
	return dbuswire.Struct{node, entries}
}

func pair(x, y int32) dbuswire.Variant { return dbuswire.NewVariant("(ii)", dbuswire.Struct{x, y}) }

func TestParseStreamsAndLayout(t *testing.T) {
	results := map[string]dbuswire.Variant{"streams": dbuswire.NewVariant("a(ua{sv})", []any{
		streamEntry(41, map[string]dbuswire.Variant{"position": pair(0, 0), "size": pair(1920, 1080)}),
		streamEntry(42, map[string]dbuswire.Variant{"position": pair(1920, 0), "size": pair(1280, 1024), "source_type": dbuswire.MakeVariant(uint32(1))}),
	})}
	streams, err := parseStreams(results)
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 2 || streams[1].node != 42 || streams[1].pos != image.Pt(1920, 0) || streams[1].size != image.Pt(1280, 1024) {
		t.Fatalf("%+v", streams)
	}
	// No frames yet: logical sizes.
	mons := waylandLayout(streams, nil)
	if mons[0].Bounds != image.Rect(0, 0, 1920, 1080) || mons[1].Bounds != image.Rect(1920, 0, 3200, 1024) || !mons[0].Primary || mons[1].Primary {
		t.Fatalf("%+v", mons)
	}
	// HiDPI: frames at twice the logical size, positions scale too.
	mons = waylandLayout(streams, []image.Point{{3840, 2160}, {2560, 2048}})
	if mons[1].Bounds != image.Rect(3840, 0, 6400, 2048) {
		t.Fatalf("hidpi %+v", mons)
	}
	node, lx, ly, ok := pointerTarget(streams, mons, 3840+1280, 1024)
	if !ok || node != 42 || lx != 640 || ly != 512 {
		t.Fatalf("pointer %d %v %v %v", node, lx, ly, ok)
	}
	// Off-screen points clamp to the first monitor.
	if node, lx, _, ok := pointerTarget(streams, mons, -50, 10); !ok || node != 41 || lx != 0 {
		t.Fatalf("clamp %d %v", node, lx)
	}
	// Streams without a position follow each other.
	streams[1].hasPos = false
	mons = waylandLayout(streams, nil)
	if mons[1].Bounds.Min != image.Pt(1920, 0) {
		t.Fatalf("no position %+v", mons)
	}
}

func TestParseStreamsRejects(t *testing.T) {
	bad := []map[string]dbuswire.Variant{
		{},
		{"streams": dbuswire.MakeVariant("x")},
		{"streams": dbuswire.NewVariant("a(ua{sv})", []any{})},
		{"streams": dbuswire.NewVariant("a(ua{sv})", []any{streamEntry(0, nil)})},
		{"streams": dbuswire.NewVariant("a(ua{sv})", make([]any, maxPortalStreams+1))},
	}
	for i, r := range bad {
		if _, err := parseStreams(r); err == nil {
			t.Errorf("%d kabul edildi", i)
		}
	}
	// Out-of-range sizes are ignored, not trusted.
	s, err := parseStreams(map[string]dbuswire.Variant{"streams": dbuswire.NewVariant("a(ua{sv})", []any{
		streamEntry(7, map[string]dbuswire.Variant{"size": pair(1<<30, 5), "position": pair(1<<30, 0)}),
	})})
	if err != nil || s[0].size != (image.Point{}) || s[0].hasPos {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestHIDToEvdev(t *testing.T) {
	want := map[uint16]int32{0x04: 30, 0x1d: 44, 0x28: 28, 0x29: 1, 0x2c: 57, 0x3a: 59, 0x45: 88, 0x4f: 106, 0x52: 103, 0xe0: 29, 0xe7: 126, 0x64: 86}
	for usage, code := range want {
		if hidToEvdev[usage] != code {
			t.Errorf("%#x: %d, want %d", usage, hidToEvdev[usage], code)
		}
	}
	// Every key the X11 path knows has an evdev code.
	for usage := range hidKeys {
		if _, ok := hidToEvdev[usage]; !ok {
			t.Errorf("HID %#x has no evdev code", usage)
		}
	}
}

func TestFrameToRGBA(t *testing.T) {
	// 2x1 BGRx with a 12-byte stride.
	src := []byte{1, 2, 3, 0, 4, 5, 6, 0, 9, 9, 9, 9}
	dst := make([]byte, 8)
	if !frameToRGBA(dst, src, 2, 1, 12, true) {
		t.Fatal("refused")
	}
	if string(dst) != string([]byte{3, 2, 1, 255, 6, 5, 4, 255}) {
		t.Fatalf("%v", dst)
	}
	if frameToRGBA(dst, src, 2, 2, 12, true) || frameToRGBA(dst, src, 3, 1, 8, false) || frameToRGBA(dst[:4], src, 2, 1, 8, false) {
		t.Fatal("short buffer accepted")
	}
}
