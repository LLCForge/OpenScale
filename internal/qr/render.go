package qr

import (
	"bufio"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
)

// QuietZone is the light border, in modules, that scanners need.
const QuietZone = 4

// MaxPNGScale bounds the pixels per module of a PNG.
const MaxPNGScale = 32

// Terminal writes the code with Unicode half blocks, two module rows per
// text line. Terminals usually draw light text on a dark background, so by
// default the light modules are drawn as blocks; set darkOnLight for a
// terminal with a light background.
func (c *Code) Terminal(w io.Writer, darkOnLight bool) error {
	bw := bufio.NewWriter(w)
	ink := func(x, y int) bool { return c.Dark(x, y) == darkOnLight }
	for y := -QuietZone; y < c.Size+QuietZone; y += 2 {
		for x := -QuietZone; x < c.Size+QuietZone; x++ {
			top := ink(x, y)
			bottom := y+1 < c.Size+QuietZone && ink(x, y+1)
			if y+1 >= c.Size+QuietZone {
				bottom = !darkOnLight
			}
			switch {
			case top && bottom:
				bw.WriteString("█")
			case top:
				bw.WriteString("▀")
			case bottom:
				bw.WriteString("▄")
			default:
				bw.WriteByte(' ')
			}
		}
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

// Image returns the code as a black-and-white image with scale pixels per
// module and the quiet zone.
func (c *Code) Image(scale int) (image.Image, error) {
	if scale < 1 || scale > MaxPNGScale {
		return nil, errors.New("scale must be between 1 and 32 pixels per module")
	}
	side := (c.Size + 2*QuietZone) * scale
	img := image.NewPaletted(image.Rect(0, 0, side, side), color.Palette{color.White, color.Black})
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			if c.Dark(x/scale-QuietZone, y/scale-QuietZone) {
				img.SetColorIndex(x, y, 1)
			}
		}
	}
	return img, nil
}

// PNG writes the code as a PNG image.
func (c *Code) PNG(w io.Writer, scale int) error {
	img, err := c.Image(scale)
	if err != nil {
		return err
	}
	return png.Encode(w, img)
}
