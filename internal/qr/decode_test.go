package qr

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
)

// gridOf returns the module grid of an encoded symbol.
func gridOf(c *Code) []bool {
	out := make([]bool, c.Size*c.Size)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			out[y*c.Size+x] = c.Dark(x, y)
		}
	}
	return out
}

// payload returns a deterministic printable payload of n bytes, like an
// invite code (base64url after a prefix).
func payload(n int, seed uint64) []byte {
	const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	r := rand.New(rand.NewPCG(seed, 7))
	b := make([]byte, n)
	for i := range b {
		b[i] = set[r.IntN(len(set))]
	}
	return b
}

func TestDecodeGridRoundTrip(t *testing.T) {
	inputs := [][]byte{
		[]byte("HELLO WORLD"),
		[]byte("osinv1.abc"),
		{},
		[]byte("ÇĞİÖŞÜ çğıöşü"),
		payload(120, 1),
		payload(400, 2),
		[]byte(strings.Repeat("OSPB1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 6)),
		payload(1200, 3),
	}
	for _, in := range inputs {
		for lvl := L; lvl <= H; lvl++ {
			c, err := Encode(in, lvl)
			if errors.Is(err, ErrTooLong) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeGrid(c.Size, gridOf(c))
			if err != nil {
				t.Fatalf("%d bytes at %v (version %d): %v", len(in), lvl, c.Version, err)
			}
			if !bytes.Equal(got, in) {
				t.Fatalf("%d bytes at %v: got %q", len(in), lvl, got)
			}
		}
	}
}

func TestDecodeGridEveryVersionAndMask(t *testing.T) {
	for ver := 1; ver <= 40; ver++ {
		lvl := Level(ver % 4)
		// The largest byte payload of this version.
		n := (numDataCodewords(ver, lvl)*8 - 4 - countBits(modeByte, ver)) / 8
		in := payload(n, uint64(ver))
		c, err := Encode(in, lvl)
		if err != nil {
			t.Fatal(err)
		}
		if c.Version != ver {
			t.Fatalf("payload %d at %v went to version %d, want %d", n, lvl, c.Version, ver)
		}
		got, err := DecodeGrid(c.Size, gridOf(c))
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("version %d-%v: %v", ver, lvl, err)
		}
	}
	// Every mask, by forcing it.
	data := []byte("maske denemesi 0123456789")
	for m := 0; m < 8; m++ {
		c, err := Encode(data, M)
		if err != nil {
			t.Fatal(err)
		}
		var bb bitBuffer
		bb.append(modeByte, 4)
		bb.append(len(data), countBits(modeByte, c.Version))
		for _, b := range data {
			bb.append(int(b), 8)
		}
		capacity := numDataCodewords(c.Version, M) * 8
		bb.append(0, min(4, capacity-len(bb)))
		bb.append(0, (8-len(bb)%8)%8)
		for pad := 0xEC; len(bb) < capacity; pad ^= 0xEC ^ 0x11 {
			bb.append(pad, 8)
		}
		cw := make([]byte, len(bb)/8)
		for i, bit := range bb {
			if bit {
				cw[i>>3] |= 1 << (7 - i&7)
			}
		}
		forced := build(c.Version, M, addECCAndInterleave(cw, c.Version, M), m)
		got, err := DecodeGrid(forced.Size, gridOf(forced))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("mask %d: %q %v", m, got, err)
		}
	}
}

func TestDecodeGridCorrectsErrors(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	for _, tc := range []struct {
		n     int
		lvl   Level
		flips int
	}{{80, H, 12}, {200, Q, 8}, {300, M, 6}, {20, L, 1}} {
		in := payload(tc.n, uint64(tc.n))
		c, err := Encode(in, tc.lvl)
		if err != nil {
			t.Fatal(err)
		}
		b := &builder{size: c.Size, ver: c.Version, lvl: tc.lvl, modules: make([]bool, c.Size*c.Size), isFunction: make([]bool, c.Size*c.Size)}
		b.drawFunctionPatterns()
		// Each flipped data module damages at most one codeword; the
		// flip count stays within what every block can correct.
		g := gridOf(c)
		for done := 0; done < tc.flips; {
			i := r.IntN(len(g))
			if b.isFunction[i] {
				continue
			}
			g[i] = !g[i]
			done++
		}
		got, err := DecodeGrid(c.Size, g)
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("%d bytes at %v with %d flips: %v", tc.n, tc.lvl, tc.flips, err)
		}
	}
	// Destroyed symbol: an error, never a panic.
	c, _ := Encode(payload(50, 1), L)
	g := gridOf(c)
	for i := range g {
		if r.IntN(3) == 0 {
			g[i] = !g[i]
		}
	}
	if _, err := DecodeGrid(c.Size, g); err == nil {
		t.Fatal("a scrambled symbol decoded")
	}
}

func TestDecodeGridMirroredAndBadInput(t *testing.T) {
	in := []byte("aynalı kod")
	c, _ := Encode(in, Q)
	g := &grid{size: c.Size, dark: gridOf(c)}
	got, err := DecodeGrid(c.Size, g.transposed().dark)
	if err != nil || !bytes.Equal(got, in) {
		t.Fatalf("mirrored: %q %v", got, err)
	}
	if _, err := DecodeGrid(22, make([]bool, 22*22)); !errors.Is(err, ErrBadGridSize) {
		t.Fatalf("size 22: %v", err)
	}
	if _, err := DecodeGrid(21, make([]bool, 10)); err == nil {
		t.Fatal("short grid accepted")
	}
	if _, err := DecodeGrid(21, make([]bool, 21*21)); err == nil {
		t.Fatal("blank grid decoded")
	}
}

func TestRSCorrect(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for trial := 0; trial < 300; trial++ {
		ecc := 2 + r.IntN(29)
		n := ecc + 1 + r.IntN(255-ecc)
		data := make([]byte, n-ecc)
		for i := range data {
			data[i] = byte(r.Uint32())
		}
		block := append(append([]byte(nil), data...), rsRemainder(data, rsDivisor(ecc))...)
		orig := append([]byte(nil), block...)
		errs := r.IntN(ecc/2 + 1)
		for _, p := range r.Perm(n)[:errs] {
			block[p] ^= byte(1 + r.IntN(255))
		}
		if err := rsCorrect(block, ecc, ecc/2); err != nil {
			t.Fatalf("n=%d ecc=%d errors=%d: %v", n, ecc, errs, err)
		}
		if !bytes.Equal(block, orig) {
			t.Fatalf("n=%d ecc=%d errors=%d: wrong correction", n, ecc, errs)
		}
	}
	// More errors than allowed: refused (or, rarely for a full-strength
	// decoder, a different valid codeword; never a panic).
	data := []byte("0123456789")
	block := append(append([]byte(nil), data...), rsRemainder(data, rsDivisor(10))...)
	for i := 0; i < 6; i++ {
		block[i] ^= 0x5A
	}
	if err := rsCorrect(block, 10, 5); err == nil && bytes.Equal(block[:10], data) {
		t.Fatal("six errors corrected with five allowed")
	}
}

func TestParseSegmentsNumericECI(t *testing.T) {
	var bb bitBuffer
	bb.append(modeECI, 4)
	bb.append(26, 8) // UTF-8 designator, skipped
	bb.append(modeNumeric, 4)
	bb.append(8, 10)
	bb.append(123, 10)
	bb.append(456, 10)
	bb.append(78, 7)
	bb.append(modeAlphanumeric, 4)
	bb.append(3, 9)
	bb.append(alphanumericValue('A')*45+alphanumericValue(':'), 11)
	bb.append(alphanumericValue('Z'), 6)
	bb.append(modeTerminator, 4)
	bb.append(0, (8-len(bb)%8)%8)
	data := make([]byte, len(bb)/8)
	for i, bit := range bb {
		if bit {
			data[i>>3] |= 1 << (7 - i&7)
		}
	}
	got, err := parseSegments(data, 1)
	if err != nil || string(got) != "12345678A:Z" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := parseSegments([]byte{0x80, 0x00}, 1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("kanji: %v", err)
	}
	if _, err := parseSegments([]byte{0x40, 0xFF}, 1); err == nil {
		t.Fatal("byte segment longer than the data accepted")
	}
}

// renderGray draws a code with a quiet zone at scale pixels per module.
func renderGray(c *Code, scale int) ([]byte, int) {
	side := (c.Size + 2*QuietZone) * scale
	pix := make([]byte, side*side)
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			if c.Dark(x/scale-QuietZone, y/scale-QuietZone) {
				pix[y*side+x] = 20
			} else {
				pix[y*side+x] = 235
			}
		}
	}
	return pix, side
}

// warp draws src (side×side) into a w×h canvas through the inverse of the
// map canvas→src, with bilinear filtering; outside is a mid-light gray.
func warp(src []byte, side, w, h int, inv func(x, y float64) (float64, float64)) []byte {
	out := make([]byte, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sx, sy := inv(float64(x)+0.5, float64(y)+0.5)
			sx, sy = sx-0.5, sy-0.5
			x0, y0 := int(math.Floor(sx)), int(math.Floor(sy))
			fx, fy := sx-float64(x0), sy-float64(y0)
			px := func(xx, yy int) float64 {
				if xx < 0 || yy < 0 || xx >= side || yy >= side {
					return 200
				}
				return float64(src[yy*side+xx])
			}
			v := px(x0, y0)*(1-fx)*(1-fy) + px(x0+1, y0)*fx*(1-fy) + px(x0, y0+1)*(1-fx)*fy + px(x0+1, y0+1)*fx*fy
			out[y*w+x] = byte(math.Round(v))
		}
	}
	return out
}

func rotated(src []byte, side int, deg float64) ([]byte, int) {
	w := int(float64(side)*1.5) + 10
	a := deg * math.Pi / 180
	cos, sin := math.Cos(a), math.Sin(a)
	c := float64(w) / 2
	s := float64(side) / 2
	return warp(src, side, w, w, func(x, y float64) (float64, float64) {
		dx, dy := x-c, y-c
		return cos*dx + sin*dy + s, -sin*dx + cos*dy + s
	}), w
}

func TestDecodeGrayRotations(t *testing.T) {
	in := payload(300, 11) // an invite-sized payload
	c, err := Encode(in, L)
	if err != nil {
		t.Fatal(err)
	}
	src, side := renderGray(c, 4)
	got, err := DecodeGray(src, side, side, side)
	if err != nil || !bytes.Equal(got, in) {
		t.Fatalf("upright (version %d): %v", c.Version, err)
	}
	for _, deg := range []float64{90, 180, 270, 7, 23, 45, 61, 133, 200, 318} {
		img, w := rotated(src, side, deg)
		got, err := DecodeGray(img, w, w, w)
		if err != nil || !bytes.Equal(got, in) {
			t.Errorf("rotated %v°: %v", deg, err)
		}
	}
}

func TestDecodeGrayPerspectiveNoiseInverted(t *testing.T) {
	for _, tc := range []struct {
		n     int
		lvl   Level
		scale int
	}{{11, Q, 6}, {60, M, 5}, {250, L, 4}, {500, L, 3}} {
		in := payload(tc.n, uint64(tc.n))
		c, err := Encode(in, tc.lvl)
		if err != nil {
			t.Fatal(err)
		}
		src, side := renderGray(c, tc.scale)
		// A keystone: the top edge narrower than the bottom.
		w := side + side/3
		k := float64(side) * 0.08
		canvas := [4]point{{k + 20, 20}, {float64(side) + 20 - k, 25}, {20, float64(side) + 20}, {float64(side) + 25, float64(side) + 15}}
		srcPts := [4]point{{0, 0}, {float64(side), 0}, {0, float64(side)}, {float64(side), float64(side)}}
		hinv, ok := homography(canvas, srcPts)
		if !ok {
			t.Fatal("homography")
		}
		img := warp(src, side, w, w, func(x, y float64) (float64, float64) {
			p, _ := hinv.apply(x, y)
			return p.x, p.y
		})
		r := rand.New(rand.NewPCG(uint64(tc.n), 3))
		for i := range img {
			v := int(img[i]) + r.IntN(41) - 20
			img[i] = byte(max(0, min(255, v)))
		}
		got, err := DecodeGray(img, w, w, w)
		if err != nil || !bytes.Equal(got, in) {
			t.Errorf("perspective %d bytes (version %d): %v", tc.n, c.Version, err)
		}
		for i := range img {
			img[i] = 255 - img[i]
		}
		got, err = DecodeGray(img, w, w, w)
		if err != nil || !bytes.Equal(got, in) {
			t.Errorf("inverted %d bytes (version %d): %v", tc.n, c.Version, err)
		}
	}
}

func TestDecodeGrayStrideAndImage(t *testing.T) {
	in := []byte("osreq1.ornek")
	c, _ := Encode(in, M)
	src, side := renderGray(c, 5)
	// A camera row stride wider than the image.
	stride := side + 37
	pix := make([]byte, (side-1)*stride+side)
	for y := 0; y < side; y++ {
		copy(pix[y*stride:], src[y*side:(y+1)*side])
		if y < side-1 {
			for x := side; x < stride; x++ {
				pix[y*stride+x] = 0
			}
		}
	}
	got, err := DecodeGray(pix, side, side, stride)
	if err != nil || !bytes.Equal(got, in) {
		t.Fatalf("stride: %v", err)
	}
	rgba := image.NewRGBA(image.Rect(10, 10, 10+side, 10+side))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			v := src[y*side+x]
			rgba.Set(10+x, 10+y, color.RGBA{v, v, v, 255})
		}
	}
	got, err = DecodeImage(rgba)
	if err != nil || !bytes.Equal(got, in) {
		t.Fatalf("image: %v", err)
	}
}

func TestDecodeGrayRejects(t *testing.T) {
	for _, tc := range []struct{ w, h, stride, n int }{
		{0, 10, 10, 100}, {10, 0, 10, 0}, {10, 10, 9, 100}, {10, 10, 10, 99},
		{MaxDecodeSide + 1, 1, MaxDecodeSide + 1, MaxDecodeSide + 1}, {4096, 4096, 4096, 4096 * 4096},
	} {
		if _, err := DecodeGray(make([]byte, tc.n), tc.w, tc.h, tc.stride); !errors.Is(err, ErrImageSize) {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	blank := bytes.Repeat([]byte{255}, 300*200)
	if _, err := DecodeGray(blank, 300, 200, 300); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blank: %v", err)
	}
	r := rand.New(rand.NewPCG(5, 5))
	noise := make([]byte, 320*240)
	for i := range noise {
		noise[i] = byte(r.Uint32())
	}
	if _, err := DecodeGray(noise, 320, 240, 320); err == nil {
		t.Fatal("noise decoded")
	}
}

func BenchmarkDecodeGrayFrame(b *testing.B) {
	in := payload(300, 1)
	c, _ := Encode(in, L)
	src, side := renderGray(c, 6)
	// Centered in a 1280x720 frame.
	const w, h = 1280, 720
	frame := bytes.Repeat([]byte{180}, w*h)
	ox, oy := (w-side)/2, (h-side)/2
	if side > h {
		b.Skip(fmt.Sprintf("symbol %d px does not fit", side))
	}
	for y := 0; y < side; y++ {
		copy(frame[(oy+y)*w+ox:], src[y*side:(y+1)*side])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeGray(frame, w, h, w); err != nil {
			b.Fatal(err)
		}
	}
}
