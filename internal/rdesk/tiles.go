package rdesk

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"image"
	"io"
)

// Tile encodings inside a tiles message.
const (
	encSolid uint8 = 1 // one RGB color for the whole tile
	encFlate uint8 = 2 // RGB rows, left-delta filtered, in the message's flate stream
)

// Flate levels adaptive quality chooses between.
const (
	flateFast  = flate.BestSpeed
	flateSmall = 6
)

// changedTiles returns the tiles of cur that differ from prev. When prev
// is nil or has another size every tile is returned.
func changedTiles(prev, cur *image.RGBA, tile int) []image.Rectangle {
	b := cur.Rect
	full := prev == nil || prev.Rect != b
	var out []image.Rectangle
	for y := b.Min.Y; y < b.Max.Y; y += tile {
		for x := b.Min.X; x < b.Max.X; x += tile {
			r := image.Rect(x, y, min(x+tile, b.Max.X), min(y+tile, b.Max.Y))
			if full || !tileEqual(prev, cur, r) {
				out = append(out, r)
			}
		}
	}
	return out
}

func tileEqual(a, b *image.RGBA, r image.Rectangle) bool {
	n := r.Dx() * 4
	for y := r.Min.Y; y < r.Max.Y; y++ {
		ia, ib := a.PixOffset(r.Min.X, y), b.PixOffset(r.Min.X, y)
		if !bytes.Equal(a.Pix[ia:ia+n], b.Pix[ib:ib+n]) {
			return false
		}
	}
	return true
}

// solidColor reports whether every pixel of r has the same RGB value.
func solidColor(img *image.RGBA, r image.Rectangle) ([3]byte, bool) {
	i0 := img.PixOffset(r.Min.X, r.Min.Y)
	c := [3]byte{img.Pix[i0], img.Pix[i0+1], img.Pix[i0+2]}
	for y := r.Min.Y; y < r.Max.Y; y++ {
		row := img.Pix[img.PixOffset(r.Min.X, y):]
		for x := 0; x < r.Dx(); x++ {
			p := row[x*4 : x*4+3]
			if p[0] != c[0] || p[1] != c[1] || p[2] != c[2] {
				return c, false
			}
		}
	}
	return c, true
}

// tileEncoder turns changed tiles into tiles messages. It is reused for a
// whole session.
type tileEncoder struct {
	level int
	zw    *flate.Writer
	blob  bytes.Buffer
	raw   []byte
}

func (e *tileEncoder) setLevel(level int) {
	if level != e.level {
		e.level, e.zw = level, nil
	}
}

// encode returns the tiles messages for rects of img. Each message holds
// at most maxBatchRaw bytes of uncompressed pixel data.
func (e *tileEncoder) encode(seq uint32, img *image.RGBA, rects []image.Rectangle) ([][]byte, error) {
	if e.level == 0 {
		e.level = flateFast
	}
	var msgs [][]byte
	for len(rects) > 0 {
		var hdr []byte
		e.raw = e.raw[:0]
		n := 0
		for n < len(rects) && n < maxTilesPerMsg {
			r := rects[n]
			if n > 0 && len(e.raw)+r.Dx()*r.Dy()*3 > maxBatchRaw {
				break
			}
			hdr = binary.BigEndian.AppendUint16(hdr, uint16(r.Min.X-img.Rect.Min.X))
			hdr = binary.BigEndian.AppendUint16(hdr, uint16(r.Min.Y-img.Rect.Min.Y))
			hdr = binary.BigEndian.AppendUint16(hdr, uint16(r.Dx()))
			hdr = binary.BigEndian.AppendUint16(hdr, uint16(r.Dy()))
			if c, ok := solidColor(img, r); ok {
				hdr = append(hdr, encSolid, c[0], c[1], c[2])
			} else {
				hdr = append(hdr, encFlate)
				e.raw = appendFiltered(e.raw, img, r)
			}
			n++
		}
		blob, err := e.compress(e.raw)
		if err != nil {
			return nil, err
		}
		m := appendHeader(make([]byte, 0, headerLen+10+len(hdr)+len(blob)), msgTiles)
		m = binary.BigEndian.AppendUint32(m, seq)
		m = binary.BigEndian.AppendUint16(m, uint16(n))
		m = append(m, hdr...)
		m = binary.BigEndian.AppendUint32(m, uint32(len(blob)))
		m = append(m, blob...)
		msgs = append(msgs, finishMsg(m))
		rects = rects[n:]
	}
	return msgs, nil
}

func (e *tileEncoder) compress(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	e.blob.Reset()
	if e.zw == nil {
		zw, err := flate.NewWriter(&e.blob, e.level)
		if err != nil {
			return nil, err
		}
		e.zw = zw
	} else {
		e.zw.Reset(&e.blob)
	}
	if _, err := e.zw.Write(raw); err != nil {
		return nil, err
	}
	if err := e.zw.Close(); err != nil {
		return nil, err
	}
	return bytes.Clone(e.blob.Bytes()), nil
}

// appendFiltered appends the tile's RGB rows, each byte minus the same
// channel of the pixel to its left (the PNG "sub" filter).
func appendFiltered(dst []byte, img *image.RGBA, r image.Rectangle) []byte {
	for y := r.Min.Y; y < r.Max.Y; y++ {
		row := img.Pix[img.PixOffset(r.Min.X, y):]
		var pr, pg, pb byte
		for x := 0; x < r.Dx(); x++ {
			p := row[x*4 : x*4+3]
			dst = append(dst, p[0]-pr, p[1]-pg, p[2]-pb)
			pr, pg, pb = p[0], p[1], p[2]
		}
	}
	return dst
}

// applyTiles decodes a tiles message into canvas and returns its frame
// sequence number. It checks every tile against the canvas and bounds the
// decompressed size before inflating, so a hostile server cannot make
// the client allocate or write outside the canvas.
func applyTiles(canvas *image.RGBA, p []byte) (uint32, error) {
	d := dec{b: p}
	seq := d.u32()
	n := int(d.u16())
	if d.bad || n > maxTilesPerMsg {
		return 0, ErrProtocol
	}
	type tileHdr struct {
		r   image.Rectangle
		enc uint8
		rgb [3]byte
	}
	tiles := make([]tileHdr, 0, n)
	rawLen := 0
	bounds := canvas.Rect
	for range n {
		x, y, w, h := int(d.u16()), int(d.u16()), int(d.u16()), int(d.u16())
		t := tileHdr{enc: d.u8()}
		if d.bad || w <= 0 || h <= 0 || w > maxTileSide || h > maxTileSide {
			return 0, ErrProtocol
		}
		t.r = image.Rect(x, y, x+w, y+h).Add(bounds.Min)
		if !t.r.In(bounds) {
			return 0, fmt.Errorf("%w: karo tuvalin dışında", ErrProtocol)
		}
		switch t.enc {
		case encSolid:
			copy(t.rgb[:], d.take(3))
		case encFlate:
			rawLen += w * h * 3
		default:
			return 0, ErrProtocol
		}
		if rawLen > maxBatchRaw {
			return 0, ErrProtocol
		}
		tiles = append(tiles, t)
	}
	blobLen := int(d.u32())
	blob := d.take(blobLen)
	if err := d.end(); err != nil {
		return 0, err
	}
	var raw []byte
	if rawLen > 0 {
		zr := flate.NewReader(bytes.NewReader(blob))
		raw = make([]byte, rawLen)
		if _, err := io.ReadFull(zr, raw); err != nil {
			return 0, fmt.Errorf("%w: karo verisi açılamadı", ErrProtocol)
		}
		var one [1]byte
		if k, _ := zr.Read(one[:]); k != 0 {
			return 0, fmt.Errorf("%w: fazla karo verisi", ErrProtocol)
		}
		_ = zr.Close()
	} else if blobLen != 0 {
		return 0, ErrProtocol
	}
	off := 0
	for _, t := range tiles {
		switch t.enc {
		case encSolid:
			for y := t.r.Min.Y; y < t.r.Max.Y; y++ {
				row := canvas.Pix[canvas.PixOffset(t.r.Min.X, y):]
				for x := 0; x < t.r.Dx(); x++ {
					row[x*4], row[x*4+1], row[x*4+2], row[x*4+3] = t.rgb[0], t.rgb[1], t.rgb[2], 0xff
				}
			}
		case encFlate:
			for y := t.r.Min.Y; y < t.r.Max.Y; y++ {
				row := canvas.Pix[canvas.PixOffset(t.r.Min.X, y):]
				var pr, pg, pb byte
				for x := 0; x < t.r.Dx(); x++ {
					pr, pg, pb = raw[off]+pr, raw[off+1]+pg, raw[off+2]+pb
					row[x*4], row[x*4+1], row[x*4+2], row[x*4+3] = pr, pg, pb, 0xff
					off += 3
				}
			}
		}
	}
	return seq, nil
}

// downscale averages s x s boxes of src into dst (reallocated when its
// size differs). Edge boxes average only the pixels that exist.
func downscale(src *image.RGBA, s int, dst *image.RGBA) *image.RGBA {
	sw, sh := src.Rect.Dx(), src.Rect.Dy()
	w, h := (sw+s-1)/s, (sh+s-1)/s
	if dst == nil || dst.Rect.Dx() != w || dst.Rect.Dy() != h {
		dst = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	for y := range h {
		y0, y1 := y*s, min(y*s+s, sh)
		drow := dst.Pix[dst.PixOffset(0, y):]
		for x := range w {
			x0, x1 := x*s, min(x*s+s, sw)
			var r, g, b, cnt uint32
			for yy := y0; yy < y1; yy++ {
				row := src.Pix[src.PixOffset(src.Rect.Min.X+x0, src.Rect.Min.Y+yy):]
				for xx := 0; xx < x1-x0; xx++ {
					r += uint32(row[xx*4])
					g += uint32(row[xx*4+1])
					b += uint32(row[xx*4+2])
					cnt++
				}
			}
			drow[x*4], drow[x*4+1], drow[x*4+2], drow[x*4+3] = uint8(r/cnt), uint8(g/cnt), uint8(b/cnt), 0xff
		}
	}
	return dst
}
