package webview

import (
	"encoding/binary"
	"errors"
)

// icoImage is one image of a .ico file.
type icoImage struct {
	width, height int
	bitCount      int
	data          []byte // BMP (DIB without file header) or PNG bytes
}

const maxICOImages = 64

var errICO = errors.New("webview: IconICO geçerli bir .ico dosyası değil")

// parseICO reads the directory of a .ico file and returns its images. Every
// offset and size is checked against the file.
func parseICO(b []byte) ([]icoImage, error) {
	if len(b) < 6 || binary.LittleEndian.Uint16(b[0:]) != 0 || binary.LittleEndian.Uint16(b[2:]) != 1 {
		return nil, errICO
	}
	n := int(binary.LittleEndian.Uint16(b[4:]))
	if n == 0 || n > maxICOImages || len(b) < 6+16*n {
		return nil, errICO
	}
	out := make([]icoImage, 0, n)
	for i := range n {
		e := b[6+16*i : 6+16*(i+1)]
		w, h := int(e[0]), int(e[1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		size := binary.LittleEndian.Uint32(e[8:])
		off := binary.LittleEndian.Uint32(e[12:])
		if size < 8 || uint64(off) < uint64(6+16*n) || uint64(off)+uint64(size) > uint64(len(b)) {
			return nil, errICO
		}
		data := b[off : off+size]
		if !isPNG(data) && binary.LittleEndian.Uint32(data) != 40 {
			// Neither PNG nor a BITMAPINFOHEADER.
			return nil, errICO
		}
		out = append(out, icoImage{
			width:    w,
			height:   h,
			bitCount: int(binary.LittleEndian.Uint16(e[6:])),
			data:     data,
		})
	}
	return out, nil
}

// pickICO returns the image that best fits a square of size pixels: the
// smallest one at least that large (the deepest colour among equals), or
// the largest one when all are smaller.
func pickICO(images []icoImage, size int) (icoImage, bool) {
	if len(images) == 0 {
		return icoImage{}, false
	}
	best := -1
	for i, im := range images {
		if im.width < size {
			continue
		}
		if best < 0 || im.width < images[best].width ||
			(im.width == images[best].width && im.bitCount > images[best].bitCount) {
			best = i
		}
	}
	if best >= 0 {
		return images[best], true
	}
	for i, im := range images {
		if best < 0 || im.width > images[best].width ||
			(im.width == images[best].width && im.bitCount > images[best].bitCount) {
			best = i
		}
	}
	return images[best], true
}
