package winapp

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"math"
)

// Default icon colors: brand teal #1F7A72 and white.
const (
	iconTealR = 0x1F
	iconTealG = 0x7A
	iconTealB = 0x72

	defaultIconSize = 32
	maxIconSize     = 256

	maxPNGBytes = 8 << 20
	maxPNGDim   = 2048
)

// renderDefaultIcon draws the fallback OpenScale icon: three white dots joined
// in a triangle on a rounded teal square. It returns size*size pixels as
// top-down BGRA with straight (non-premultiplied) alpha, which is the layout
// CreateIconIndirect expects for a 32-bit DIB section.
func renderDefaultIcon(size int) []byte {
	if size <= 0 {
		size = defaultIconSize
	}
	size = min(size, maxIconSize)

	k := float64(size) / defaultIconSize
	radius := 6.5 * k
	dotR := 3.6 * k
	lineHalf := math.Max(1.1*k, 0.6)
	verts := [3][2]float64{{16 * k, 8 * k}, {8 * k, 22.5 * k}, {24 * k, 22.5 * k}}
	side := float64(size)

	const ss = 4 // supersampling factor per axis for anti-aliased edges
	out := make([]byte, size*size*4)
	for y := range size {
		for x := range size {
			var covered, white int
			for sy := range ss {
				for sx := range ss {
					px := float64(x) + (float64(sx)+0.5)/ss
					py := float64(y) + (float64(sy)+0.5)/ss
					if !inRoundedSquare(px, py, side, radius) {
						continue
					}
					covered++
					if onTriangleMark(px, py, verts, dotR, lineHalf) {
						white++
					}
				}
			}
			if covered == 0 {
				continue
			}
			f := float64(white) / float64(covered)
			i := (y*size + x) * 4
			out[i+0] = mixChannel(iconTealB, f)
			out[i+1] = mixChannel(iconTealG, f)
			out[i+2] = mixChannel(iconTealR, f)
			out[i+3] = uint8(math.Round(float64(covered) * 255 / (ss * ss)))
		}
	}
	return out
}

func mixChannel(base uint8, whiteFrac float64) uint8 {
	return uint8(math.Round(float64(base)*(1-whiteFrac) + 255*whiteFrac))
}

func inRoundedSquare(px, py, side, r float64) bool {
	if px < 0 || py < 0 || px > side || py > side {
		return false
	}
	cx := math.Min(math.Max(px, r), side-r)
	cy := math.Min(math.Max(py, r), side-r)
	dx, dy := px-cx, py-cy
	return dx*dx+dy*dy <= r*r
}

func onTriangleMark(px, py float64, v [3][2]float64, dotR, lineHalf float64) bool {
	for i := range v {
		dx, dy := px-v[i][0], py-v[i][1]
		if dx*dx+dy*dy <= dotR*dotR {
			return true
		}
	}
	for i := range v {
		a, b := v[i], v[(i+1)%3]
		if distToSegment(px, py, a[0], a[1], b[0], b[1]) <= lineHalf {
			return true
		}
	}
	return false
}

func distToSegment(px, py, ax, ay, bx, by float64) float64 {
	vx, vy := bx-ax, by-ay
	l2 := vx*vx + vy*vy
	t := 0.0
	if l2 > 0 {
		t = math.Min(math.Max(((px-ax)*vx+(py-ay)*vy)/l2, 0), 1)
	}
	dx, dy := px-(ax+t*vx), py-(ay+t*vy)
	return math.Hypot(dx, dy)
}

// decodePNG decodes and bounds-checks a PNG before any large allocation.
func decodePNG(data []byte) (*image.RGBA, error) {
	if len(data) == 0 {
		return nil, errors.New("PNG verisi boş")
	}
	if len(data) > maxPNGBytes {
		return nil, errors.New("PNG dosyası çok büyük (en fazla 8 MB)")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("geçersiz PNG: %w", err)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxPNGDim || cfg.Height > maxPNGDim {
		return nil, fmt.Errorf("PNG boyutu desteklenmiyor: %dx%d (en fazla %dx%d)", cfg.Width, cfg.Height, maxPNGDim, maxPNGDim)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("geçersiz PNG: %w", err)
	}
	b := img.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), img, b.Min, draw.Src)
	return dst, nil
}

// scaleToBGRA fits src (premultiplied RGBA) into a size x size square,
// preserving aspect ratio and centering it, using area averaging. The result
// is top-down BGRA with straight alpha.
func scaleToBGRA(src *image.RGBA, size int) []byte {
	if size <= 0 {
		size = defaultIconSize
	}
	size = min(size, maxIconSize)
	out := make([]byte, size*size*4)
	w, h := src.Bounds().Dx(), src.Bounds().Dy()
	if w == 0 || h == 0 {
		return out
	}
	scale := math.Min(float64(size)/float64(w), float64(size)/float64(h))
	offX := (float64(size) - float64(w)*scale) / 2
	offY := (float64(size) - float64(h)*scale) / 2
	area := 1 / (scale * scale) // source area covered by one destination pixel

	for y := range size {
		sy0 := math.Max((float64(y)-offY)/scale, 0)
		sy1 := math.Min((float64(y+1)-offY)/scale, float64(h))
		if sy1 <= sy0 {
			continue
		}
		for x := range size {
			sx0 := math.Max((float64(x)-offX)/scale, 0)
			sx1 := math.Min((float64(x+1)-offX)/scale, float64(w))
			if sx1 <= sx0 {
				continue
			}
			var r, g, b, a float64
			for iy := int(sy0); float64(iy) < sy1 && iy < h; iy++ {
				wy := math.Min(sy1, float64(iy+1)) - math.Max(sy0, float64(iy))
				row := src.Pix[iy*src.Stride:]
				for ix := int(sx0); float64(ix) < sx1 && ix < w; ix++ {
					wx := math.Min(sx1, float64(ix+1)) - math.Max(sx0, float64(ix))
					wgt := wx * wy
					p := row[ix*4 : ix*4+4]
					r += wgt * float64(p[0])
					g += wgt * float64(p[1])
					b += wgt * float64(p[2])
					a += wgt * float64(p[3])
				}
			}
			alpha := math.Round(a / area)
			if alpha <= 0 {
				continue
			}
			i := (y*size + x) * 4
			out[i+0] = clamp255(b * 255 / a)
			out[i+1] = clamp255(g * 255 / a)
			out[i+2] = clamp255(r * 255 / a)
			out[i+3] = clamp255(alpha)
		}
	}
	return out
}

func clamp255(v float64) uint8 {
	switch {
	case v <= 0:
		return 0
	case v >= 255:
		return 255
	default:
		return uint8(math.Round(v))
	}
}
