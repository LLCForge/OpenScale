package winapp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func pixelAt(pix []byte, size, x, y int) (b, g, r, a uint8) {
	i := (y*size + x) * 4
	return pix[i], pix[i+1], pix[i+2], pix[i+3]
}

func TestRenderDefaultIcon(t *testing.T) {
	const size = 32
	pix := renderDefaultIcon(size)
	if len(pix) != size*size*4 {
		t.Fatalf("len = %d, want %d", len(pix), size*size*4)
	}
	for _, c := range [][2]int{{0, 0}, {size - 1, 0}, {0, size - 1}, {size - 1, size - 1}} {
		if _, _, _, a := pixelAt(pix, size, c[0], c[1]); a != 0 {
			t.Errorf("corner %v alpha = %d, want 0", c, a)
		}
	}
	// Edge midpoint of the square: fully opaque teal background.
	if b, g, r, a := pixelAt(pix, size, size/2, 1); a != 255 || r != iconTealR || g != iconTealG || b != iconTealB {
		t.Errorf("background = (%d,%d,%d,%d), want opaque teal", r, g, b, a)
	}
	// Center of the top dot (16, 8): white.
	if b, g, r, a := pixelAt(pix, size, 16, 8); a != 255 || r != 255 || g != 255 || b != 255 {
		t.Errorf("top dot = (%d,%d,%d,%d), want opaque white", r, g, b, a)
	}

	if got := len(renderDefaultIcon(0)); got != 32*32*4 {
		t.Errorf("default size len = %d", got)
	}
	if got := len(renderDefaultIcon(16)); got != 16*16*4 {
		t.Errorf("16px len = %d", got)
	}
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeAndScalePNG(t *testing.T) {
	// 64x32 image: left half opaque red, right half transparent.
	src := image.NewNRGBA(image.Rect(0, 0, 64, 32))
	for y := range 32 {
		for x := range 32 {
			src.SetNRGBA(x, y, color.NRGBA{R: 255, A: 255})
		}
	}
	img, err := decodePNG(encodePNG(t, src))
	if err != nil {
		t.Fatal(err)
	}
	out := scaleToBGRA(img, 16)
	if len(out) != 16*16*4 {
		t.Fatalf("len = %d", len(out))
	}
	// Aspect ratio preserved: 64x32 -> 16x8, centered vertically (rows 4..11).
	if _, _, _, a := pixelAt(out, 16, 2, 0); a != 0 {
		t.Errorf("letterbox row alpha = %d, want 0", a)
	}
	if b, g, r, a := pixelAt(out, 16, 2, 6); a != 255 || r != 255 || g != 0 || b != 0 {
		t.Errorf("left pixel = (%d,%d,%d,%d), want opaque red", r, g, b, a)
	}
	if _, _, _, a := pixelAt(out, 16, 13, 6); a != 0 {
		t.Errorf("right pixel alpha = %d, want 0", a)
	}

	// Upscaling a tiny image also works.
	tiny := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	tiny.SetNRGBA(0, 0, color.NRGBA{G: 255, A: 128})
	img, err = decodePNG(encodePNG(t, tiny))
	if err != nil {
		t.Fatal(err)
	}
	out = scaleToBGRA(img, 32)
	if b, g, r, a := pixelAt(out, 32, 0, 0); a < 127 || a > 129 || g != 255 || r != 0 || b != 0 {
		t.Errorf("upscaled pixel = (%d,%d,%d,%d), want half-transparent green", r, g, b, a)
	}
}

func TestDecodePNGRejects(t *testing.T) {
	if _, err := decodePNG(nil); err == nil {
		t.Error("empty input accepted")
	}
	if _, err := decodePNG([]byte("not a png")); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := decodePNG(make([]byte, maxPNGBytes+1)); err == nil {
		t.Error("oversized input accepted")
	}
	big := image.NewGray(image.Rect(0, 0, maxPNGDim+1, 1))
	if _, err := decodePNG(encodePNG(t, big)); err == nil {
		t.Error("oversized dimensions accepted")
	}
}
