//go:build windows

package rdesk

import (
	"errors"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// These tests never call SendInput or touch the clipboard: injecting input
// would interfere with the person using the machine.

func TestInputStructLayout(t *testing.T) {
	want := uintptr(28)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 40
	}
	if unsafe.Sizeof(mouseInputEvent{}) != want || unsafe.Sizeof(keyInputEvent{}) != want {
		t.Fatalf("INPUT size: mouse %d key %d, want %d", unsafe.Sizeof(mouseInputEvent{}), unsafe.Sizeof(keyInputEvent{}), want)
	}
	if unsafe.Offsetof(keyInputEvent{}.Ki) != unsafe.Offsetof(mouseInputEvent{}.Mi) {
		t.Fatal("union offset")
	}
}

func TestAbsCoord(t *testing.T) {
	cases := []struct {
		v, origin, size int
		want            int32
	}{
		{0, 0, 1920, 0},
		{1919, 0, 1920, 65535},
		{-1280, -1280, 3200, 0},
		{1919, -1280, 3200, 65535},
		{99999, 0, 100, 65535},
		{-5, 0, 100, 0},
		{5, 0, 1, 0},
	}
	for _, c := range cases {
		if got := absCoord(c.v, c.origin, c.size); got != c.want {
			t.Errorf("absCoord(%d, %d, %d) = %d, want %d", c.v, c.origin, c.size, got, c.want)
		}
	}
}

func TestButtonAndTextEvents(t *testing.T) {
	ev := buttonEvents(ButtonLeft, ButtonRight|ButtonMiddle)
	if len(ev) != 3 || ev[0] != mouseeventfLeftUp || ev[1] != mouseeventfRightDown || ev[2] != mouseeventfMiddleDown {
		t.Fatalf("buttonEvents %v", ev)
	}
	if len(buttonEvents(ButtonLeft, ButtonLeft)) != 0 {
		t.Fatal("no change, no events")
	}
	te := textEvents("a\n😀")
	if len(te) != 2+2+4 {
		t.Fatalf("text events %d", len(te))
	}
	if te[0].Ki.Scan != 'a' || te[0].Ki.Flags != keyeventfUnicode || te[1].Ki.Flags != keyeventfUnicode|keyeventfKeyUp {
		t.Fatal("unicode key events")
	}
	if te[2].Ki.Vk != 0x0D || te[3].Ki.Flags&keyeventfKeyUp == 0 {
		t.Fatal("newline must be the Enter key")
	}
	if te[4].Ki.Scan != 0xD83D || te[6].Ki.Scan != 0xDE00 {
		t.Fatal("surrogate pair")
	}
	k := keyEvent(keyMap{vk: 0x25, extended: true}, false)
	if k.Type != inputKeyboard || k.Ki.Flags != keyeventfExtendedKey|keyeventfKeyUp {
		t.Fatal("extended key up")
	}
	src := []byte{1, 2, 3, 0, 4, 5, 6, 0}
	dst := make([]byte, 8)
	bgraToRGBA(dst, src)
	if string(dst) != string([]byte{3, 2, 1, 255, 6, 5, 4, 255}) {
		t.Fatal("bgraToRGBA")
	}
}

// TestGDICapture reads the real screen. It runs only when
// OPENSCALE_RDESK_CAPTURE_TEST=1, so routine test runs never capture the
// desktop; the PNG goes to a temporary directory that the test removes.
func TestGDICapture(t *testing.T) {
	if os.Getenv("OPENSCALE_RDESK_CAPTURE_TEST") != "1" {
		t.Skip("OPENSCALE_RDESK_CAPTURE_TEST=1 ile çalışır")
	}
	c, err := NewScreenCapturer()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ms, err := c.Monitors()
	if err != nil || len(ms) == 0 {
		t.Fatalf("monitors: %v %v", ms, err)
	}
	primary := ms[primaryIndex(ms)]
	t.Logf("%d monitor; birincil %v", len(ms), primary.Bounds)
	img, err := c.Capture(primary.Bounds, nil)
	if errors.Is(err, ErrScreenUnavailable) {
		t.Skipf("masaüstü şu anda okunamıyor (kilitli ekran veya simge durumundaki/bağlantısı kesik uzak oturum): %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if img.Rect != image.Rect(0, 0, primary.Bounds.Dx(), primary.Bounds.Dy()) {
		t.Fatalf("rect %v", img.Rect)
	}
	nonBlack := 0
	for i := 0; i < len(img.Pix); i += 4 {
		if img.Pix[i]|img.Pix[i+1]|img.Pix[i+2] != 0 {
			nonBlack++
		}
		if img.Pix[i+3] != 0xff {
			t.Fatal("alpha must be opaque")
		}
	}
	t.Logf("siyah olmayan piksel: %d / %d", nonBlack, len(img.Pix)/4)
	again, err := c.Capture(primary.Bounds, img)
	if err != nil || again != img {
		t.Fatalf("buffer reuse: %v", err)
	}
	all := viewRect(ms, MonitorAll)
	if _, err := c.Capture(all, nil); err != nil {
		t.Fatalf("all monitors: %v", err)
	}
	path := filepath.Join(t.TempDir(), "yakalama.png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		t.Fatal("png not written")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
