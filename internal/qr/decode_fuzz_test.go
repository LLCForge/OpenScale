package qr

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDecodeRoundTrip: everything Encode writes, DecodeGrid reads back.
func FuzzDecodeRoundTrip(f *testing.F) {
	f.Add([]byte("HELLO WORLD"), uint8(2))
	f.Add([]byte("osinv1.eyJyIjoi"), uint8(0))
	f.Add([]byte{0, 1, 2, 255}, uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, lvl uint8) {
		c, err := Encode(data, Level(lvl%4))
		if errors.Is(err, ErrTooLong) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeGrid(c.Size, gridOf(c))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("got %q, want %q", got, data)
		}
	})
}

// FuzzDecodeGrid: arbitrary module grids never panic.
func FuzzDecodeGrid(f *testing.F) {
	c, _ := Encode([]byte("tohum"), M)
	seed := make([]byte, (c.Size*c.Size+7)/8)
	for i, d := range gridOf(c) {
		if d {
			seed[i>>3] |= 1 << (i & 7)
		}
	}
	f.Add(uint8(0), seed)
	f.Add(uint8(6), []byte{0xFF, 0x00, 0xAA})
	f.Fuzz(func(t *testing.T, ver uint8, bits []byte) {
		size := 17 + 4*(1+int(ver)%40)
		mods := make([]bool, size*size)
		for i := range mods {
			if len(bits) > 0 {
				mods[i] = bits[(i>>3)%len(bits)]>>(i&7)&1 == 1
			}
		}
		_, _ = DecodeGrid(size, mods)
	})
}

// FuzzDecodeGray: arbitrary images never panic.
func FuzzDecodeGray(f *testing.F) {
	c, _ := Encode([]byte("kamera"), L)
	src, side := renderGray(c, 2)
	f.Add(uint16(side), uint16(side), src)
	f.Add(uint16(40), uint16(30), bytes.Repeat([]byte{0, 255}, 600))
	f.Fuzz(func(t *testing.T, w, h uint16, pix []byte) {
		width, height := int(w%400), int(h%400)
		if width == 0 || height == 0 || len(pix) < width*height {
			_, _ = DecodeGray(pix, width, height, width)
			return
		}
		_, _ = DecodeGray(pix, width, height, width)
	})
}
