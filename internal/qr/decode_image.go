package qr

import (
	"errors"
	"image"
	"image/color"
	"math"
	"sort"
)

// Image limits of DecodeGray: a camera frame is about 1-2 megapixels.
const (
	MaxDecodeSide   = 4096
	MaxDecodePixels = 8 << 20
)

// ErrImageSize is returned for an empty, too large or inconsistent image.
var ErrImageSize = errors.New("qr: image size or stride is invalid")

// bitImage is a binarized image; true is dark.
type bitImage struct {
	w, h int
	dark []bool
}

func (b *bitImage) at(x, y int) bool {
	if x < 0 || y < 0 || x >= b.w || y >= b.h {
		return false
	}
	return b.dark[y*b.w+x]
}

// DecodeGray finds and decodes one QR symbol in an 8-bit grayscale image
// (0 is black). pix holds height rows of stride bytes; only the first
// width bytes of each row are read. It is meant for camera frames (the Y
// plane of YUV_420_888 on Android) and screenshots. Dark-on-light and
// light-on-dark symbols, any rotation, mirroring and mild perspective are
// handled.
func DecodeGray(pix []byte, width, height, stride int) ([]byte, error) {
	if width <= 0 || height <= 0 || width > MaxDecodeSide || height > MaxDecodeSide ||
		width*height > MaxDecodePixels || stride < width || len(pix) < (height-1)*stride+width {
		return nil, ErrImageSize
	}
	if width < 21 || height < 21 {
		return nil, ErrNotFound
	}
	gray := make([]byte, width*height)
	for y := 0; y < height; y++ {
		copy(gray[y*width:(y+1)*width], pix[y*stride:y*stride+width])
	}
	inverted := make([]byte, len(gray))
	for i, v := range gray {
		inverted[i] = 255 - v
	}
	// Light-on-dark symbols are binarized from the inverted image: the
	// local threshold is not symmetric, so flipping its output is not the
	// same.
	var firstErr error
	for _, try := range []struct {
		bin func([]byte, int, int) *bitImage
		pix []byte
	}{{binarizeLocal, gray}, {binarizeLocal, inverted}, {binarizeGlobal, gray}, {binarizeGlobal, inverted}} {
		data, err := decodeBits(try.bin(try.pix, width, height))
		if err == nil {
			return data, nil
		}
		if firstErr == nil || errors.Is(firstErr, ErrNotFound) {
			firstErr = err
		}
	}
	return nil, firstErr
}

// DecodeImage decodes a QR symbol in any image (a PNG or JPEG from a
// screenshot or a photo).
func DecodeImage(img image.Image) ([]byte, error) {
	r := img.Bounds()
	w, h := r.Dx(), r.Dy()
	if w <= 0 || h <= 0 || w > MaxDecodeSide || h > MaxDecodeSide || w*h > MaxDecodePixels {
		return nil, ErrImageSize
	}
	pix := make([]byte, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			pix[y*w+x] = color.GrayModel.Convert(img.At(r.Min.X+x, r.Min.Y+y)).(color.Gray).Y
		}
	}
	return DecodeGray(pix, w, h, w)
}

// binarizeLocal thresholds every pixel against the mean of its
// neighbourhood (Bradley's method on an integral image), which copes with
// uneven light on a phone screen or paper.
func binarizeLocal(gray []byte, w, h int) *bitImage {
	integral := make([]uint32, (w+1)*(h+1))
	for y := 0; y < h; y++ {
		var row uint32
		for x := 0; x < w; x++ {
			row += uint32(gray[y*w+x])
			integral[(y+1)*(w+1)+x+1] = integral[y*(w+1)+x+1] + row
		}
	}
	half := max(min(w, h)/16, 4)
	img := &bitImage{w: w, h: h, dark: make([]bool, w*h)}
	for y := 0; y < h; y++ {
		y0, y1 := max(y-half, 0), min(y+half+1, h)
		for x := 0; x < w; x++ {
			x0, x1 := max(x-half, 0), min(x+half+1, w)
			sum := integral[y1*(w+1)+x1] - integral[y0*(w+1)+x1] - integral[y1*(w+1)+x0] + integral[y0*(w+1)+x0]
			count := uint64((x1 - x0) * (y1 - y0))
			// Dark when 15% below the local mean.
			img.dark[y*w+x] = uint64(gray[y*w+x])*count*100 < uint64(sum)*85
		}
	}
	return img
}

// binarizeGlobal uses one Otsu threshold for the whole image.
func binarizeGlobal(gray []byte, w, h int) *bitImage {
	var hist [256]int
	for _, v := range gray {
		hist[v]++
	}
	total := len(gray)
	var sumAll float64
	for i, c := range hist {
		sumAll += float64(i * c)
	}
	var sumB float64
	wB, best, threshold := 0, -1.0, 128
	for t := 0; t < 256; t++ {
		wB += hist[t]
		if wB == 0 {
			continue
		}
		wF := total - wB
		if wF == 0 {
			break
		}
		sumB += float64(t * hist[t])
		mB, mF := sumB/float64(wB), (sumAll-sumB)/float64(wF)
		if between := float64(wB) * float64(wF) * (mB - mF) * (mB - mF); between > best {
			best, threshold = between, t
		}
	}
	img := &bitImage{w: w, h: h, dark: make([]bool, w*h)}
	for i, v := range gray {
		img.dark[i] = int(v) <= threshold
	}
	return img
}

type point struct{ x, y float64 }

func dist(a, b point) float64 { return math.Hypot(a.x-b.x, a.y-b.y) }

// finder is a finder pattern candidate.
type finder struct {
	point
	module float64
	count  int
}

const (
	maxFinderCandidates = 32
	maxTriplesTried     = 6
)

// decodeBits finds the finder patterns and tries the best triples.
func decodeBits(img *bitImage) ([]byte, error) {
	cands := findFinders(img)
	if len(cands) < 3 {
		return nil, ErrNotFound
	}
	triples := bestTriples(cands)
	if len(triples) == 0 {
		return nil, ErrNotFound
	}
	var firstErr error
	for i, t := range triples {
		if i >= maxTriplesTried {
			break
		}
		data, err := decodeTriple(img, t)
		if err == nil {
			return data, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// foundFinderCross reports whether run lengths look like 1:1:3:1:1.
func foundFinderCross(sc [5]int) bool {
	total := 0
	for _, c := range sc {
		if c == 0 {
			return false
		}
		total += c
	}
	if total < 7 {
		return false
	}
	m := float64(total) / 7
	v := m / 2
	return math.Abs(m-float64(sc[0])) < v && math.Abs(m-float64(sc[1])) < v &&
		math.Abs(3*m-float64(sc[2])) < 3*v && math.Abs(m-float64(sc[3])) < v && math.Abs(m-float64(sc[4])) < v
}

func centerFromEnd(sc [5]int, end int) float64 {
	return float64(end-sc[4]-sc[3]) - float64(sc[2])/2
}

// findFinders scans rows for 1:1:3:1:1 runs and confirms them across.
func findFinders(img *bitImage) []finder {
	var cands []finder
	skip := max(1, 3*img.h/(4*177))
	for y := skip - 1; y < img.h; y += skip {
		var sc [5]int
		state := 0
		for x := 0; x < img.w; x++ {
			if img.at(x, y) {
				if state&1 == 1 {
					state++
				}
				sc[state]++
				continue
			}
			if state&1 == 1 {
				sc[state]++
				continue
			}
			if state != 4 {
				state++
				sc[state]++
				continue
			}
			if foundFinderCross(sc) && confirmFinder(img, sc, y, x, &cands) {
				sc, state = [5]int{}, 0
				continue
			}
			sc = [5]int{sc[2], sc[3], sc[4], 1, 0}
			state = 3
		}
		if foundFinderCross(sc) {
			confirmFinder(img, sc, y, img.w, &cands)
		}
		if len(cands) > 4*maxFinderCandidates {
			break // a noise image; give up early
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].count > cands[j].count })
	if len(cands) > maxFinderCandidates {
		cands = cands[:maxFinderCandidates]
	}
	return cands
}

// crossCheck counts the five runs through (cx, cy) along (dx, dy) and
// returns the refined center coordinate along that axis.
func crossCheck(img *bitImage, cx, cy, dx, dy, maxCount, origTotal int) (float64, [5]int, bool) {
	var sc [5]int
	x, y := cx, cy
	for img.inside(x, y) && img.at(x, y) {
		sc[2]++
		x, y = x-dx, y-dy
	}
	if !img.inside(x, y) {
		return 0, sc, false
	}
	for img.inside(x, y) && !img.at(x, y) && sc[1] <= maxCount {
		sc[1]++
		x, y = x-dx, y-dy
	}
	if !img.inside(x, y) || sc[1] > maxCount {
		return 0, sc, false
	}
	for img.inside(x, y) && img.at(x, y) && sc[0] <= maxCount {
		sc[0]++
		x, y = x-dx, y-dy
	}
	if sc[0] > maxCount {
		return 0, sc, false
	}
	x, y = cx+dx, cy+dy
	for img.inside(x, y) && img.at(x, y) {
		sc[2]++
		x, y = x+dx, y+dy
	}
	if !img.inside(x, y) {
		return 0, sc, false
	}
	for img.inside(x, y) && !img.at(x, y) && sc[3] < maxCount {
		sc[3]++
		x, y = x+dx, y+dy
	}
	if !img.inside(x, y) || sc[3] >= maxCount {
		return 0, sc, false
	}
	for img.inside(x, y) && img.at(x, y) && sc[4] < maxCount {
		sc[4]++
		x, y = x+dx, y+dy
	}
	if sc[4] >= maxCount {
		return 0, sc, false
	}
	total := sc[0] + sc[1] + sc[2] + sc[3] + sc[4]
	if 5*abs(total-origTotal) >= 2*origTotal || !foundFinderCross(sc) {
		return 0, sc, false
	}
	// x or y is now one past the last run along the axis.
	end := x
	if dx == 0 {
		end = y
	}
	return centerFromEnd(sc, end), sc, true
}

func (b *bitImage) inside(x, y int) bool { return x >= 0 && y >= 0 && x < b.w && y < b.h }

// confirmFinder checks a row hit vertically and horizontally and records it.
func confirmFinder(img *bitImage, sc [5]int, y, end int, cands *[]finder) bool {
	total := sc[0] + sc[1] + sc[2] + sc[3] + sc[4]
	cx := int(centerFromEnd(sc, end))
	cy, _, ok := crossCheck(img, cx, y, 0, 1, sc[2], total)
	if !ok {
		return false
	}
	cxf, hsc, ok := crossCheck(img, cx, int(cy), 1, 0, sc[2], total)
	if !ok {
		return false
	}
	module := float64(hsc[0]+hsc[1]+hsc[2]+hsc[3]+hsc[4]) / 7
	p := point{cxf, cy}
	for i := range *cands {
		c := &(*cands)[i]
		if math.Abs(c.x-p.x) <= module && math.Abs(c.y-p.y) <= module &&
			(math.Abs(module-c.module) <= 1 || math.Abs(module-c.module) <= c.module) {
			n := float64(c.count)
			c.x, c.y = (c.x*n+p.x)/(n+1), (c.y*n+p.y)/(n+1)
			c.module = (c.module*n + module) / (n + 1)
			c.count++
			return true
		}
	}
	*cands = append(*cands, finder{point: p, module: module, count: 1})
	return true
}

type triple struct {
	tl, tr, bl finder
	score      float64
}

// bestTriples returns the candidate triples that look like the three
// finder patterns of one symbol, best first, ordered top-left, top-right,
// bottom-left.
func bestTriples(cands []finder) []triple {
	var out []triple
	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			for k := j + 1; k < len(cands); k++ {
				if t, ok := makeTriple(cands[i], cands[j], cands[k]); ok {
					out = append(out, t)
				}
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].score < out[b].score })
	return out
}

func makeTriple(a, b, c finder) (triple, bool) {
	ms := []float64{a.module, b.module, c.module}
	lo, hi := math.Min(ms[0], math.Min(ms[1], ms[2])), math.Max(ms[0], math.Max(ms[1], ms[2]))
	if lo <= 0 || hi/lo > 1.5 {
		return triple{}, false
	}
	// The corner is opposite the longest side.
	ab, bc, ca := dist(a.point, b.point), dist(b.point, c.point), dist(c.point, a.point)
	var tl, p, q finder
	var hyp, s1, s2 float64
	switch {
	case bc >= ab && bc >= ca:
		tl, p, q, hyp, s1, s2 = a, b, c, bc, ab, ca
	case ca >= ab && ca >= bc:
		tl, p, q, hyp, s1, s2 = b, c, a, ca, ab, bc
	default:
		tl, p, q, hyp, s1, s2 = c, a, b, ab, bc, ca
	}
	mean := (a.module + b.module + c.module) / 3
	// Finder centers are at least 14 modules apart; perspective can
	// shorten one side.
	if s1 < 10*mean || s2 < 10*mean || s1 > 180*mean || s2 > 180*mean {
		return triple{}, false
	}
	sideRatio := math.Max(s1, s2) / math.Min(s1, s2)
	right := math.Abs(hyp*hyp-(s1*s1+s2*s2)) / (s1*s1 + s2*s2)
	if sideRatio > 1.4 || right > 0.35 {
		return triple{}, false
	}
	// Orientation: top-right is clockwise from bottom-left around top-left
	// (image y grows downwards).
	tr, bl := p, q
	if (tr.x-tl.x)*(bl.y-tl.y)-(tr.y-tl.y)*(bl.x-tl.x) < 0 {
		tr, bl = bl, tr
	}
	score := (sideRatio - 1) + right + (hi/lo - 1) - 0.01*float64(min(a.count+b.count+c.count, 30))
	return triple{tl: tl, tr: tr, bl: bl, score: score}, true
}

// runBWB walks from a finder center towards (tx, ty) and returns the
// distance to the end of its black-white-black runs (3.5 modules), or -1.
func runBWB(img *bitImage, from point, tx, ty float64) float64 {
	dx, dy := tx-from.x, ty-from.y
	length := math.Hypot(dx, dy)
	if length < 1 {
		return -1
	}
	dx, dy = dx/length, dy/length
	state := 0
	for s := 0.0; s <= length; s += 0.5 {
		x, y := int(math.Floor(from.x+dx*s)), int(math.Floor(from.y+dy*s))
		if !img.inside(x, y) {
			if state == 2 {
				return s
			}
			return -1
		}
		d := img.at(x, y)
		switch {
		case state == 0 && !d:
			state = 1 // left the 3-module center
		case state == 1 && d:
			state = 2 // entered the outer ring
		case state == 2 && !d:
			return s // left the outer ring
		}
	}
	return -1
}

// moduleAlong estimates the module size from the finder at a toward b.
func moduleAlong(img *bitImage, a, b point) float64 {
	fwd := runBWB(img, a, b.x, b.y)
	back := runBWB(img, a, 2*a.x-b.x, 2*a.y-b.y)
	if fwd <= 0 || back <= 0 {
		return -1
	}
	return (fwd + back) / 7
}

func decodeTriple(img *bitImage, t triple) ([]byte, error) {
	module := 0.0
	n := 0
	for _, pair := range [][2]point{{t.tl.point, t.tr.point}, {t.tr.point, t.tl.point}, {t.tl.point, t.bl.point}, {t.bl.point, t.tl.point}} {
		if m := moduleAlong(img, pair[0], pair[1]); m > 0 {
			module += m
			n++
		}
	}
	if n > 0 {
		module /= float64(n)
	} else {
		module = (t.tl.module + t.tr.module + t.bl.module) / 3
	}
	if module < 1 {
		return nil, ErrNotFound
	}
	span := (dist(t.tl.point, t.tr.point) + dist(t.tl.point, t.bl.point)) / 2
	dim := int(math.Round(span/module)) + 7
	switch dim & 3 {
	case 0:
		dim++
	case 2:
		dim--
	case 3:
		dim -= 2
	}
	var firstErr error
	tried := map[int]bool{}
	for _, d := range []int{dim, dim + 4, dim - 4} {
		if d < 21 || d > 177 || tried[d] {
			continue
		}
		tried[d] = true
		data, err := sampleAndDecode(img, t, d, module, tried)
		if err == nil {
			return data, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// sampleAndDecode samples a dim×dim grid. For version 7 and up the version
// information can name another size, which is then sampled once. Without
// an alignment pattern the fourth corner is only a parallelogram guess;
// small symbols then try nearby corners, which absorbs a keystone.
func sampleAndDecode(img *bitImage, t triple, dim int, module float64, tried map[int]bool) ([]byte, error) {
	g, aligned, err := sampleGrid(img, t, dim, module, point{})
	if err != nil {
		return nil, err
	}
	data, err := DecodeGrid(dim, g.dark)
	if err == nil {
		return data, nil
	}
	if !aligned && dim <= maxShiftedDim {
		for _, s := range cornerShifts {
			g2, _, err2 := sampleGrid(img, t, dim, module, s)
			if err2 != nil {
				continue
			}
			if data2, err2 := DecodeGrid(dim, g2.dark); err2 == nil {
				return data2, nil
			}
		}
	}
	if dim < 45 {
		return nil, err
	}
	for _, gg := range []*grid{g, g.transposed()} {
		if v := gg.readVersion(); v != 0 && 17+4*v != dim && !tried[17+4*v] {
			d2 := 17 + 4*v
			tried[d2] = true
			g2, _, err2 := sampleGrid(img, t, d2, module, point{})
			if err2 != nil {
				continue
			}
			if data2, err2 := DecodeGrid(d2, g2.dark); err2 == nil {
				return data2, nil
			}
		}
	}
	return nil, err
}

// sampleGrid maps module centers to the image with a homography fixed by
// the three finder centers and the bottom-right alignment pattern (or the
// parallelogram corner when there is none).
func sampleGrid(img *bitImage, t triple, dim int, module float64, shift point) (*grid, bool, error) {
	far := float64(dim) - 3.5
	src := [4]point{{3.5, 3.5}, {far, 3.5}, {3.5, far}, {far, far}}
	br := point{t.tr.x + t.bl.x - t.tl.x, t.tr.y + t.bl.y - t.tl.y}
	// shift moves the guessed corner by whole modules along the sides.
	span := float64(dim) - 7
	ux, uy := (t.tr.x-t.tl.x)/span, (t.tr.y-t.tl.y)/span
	vx, vy := (t.bl.x-t.tl.x)/span, (t.bl.y-t.tl.y)/span
	guess := point{br.x + shift.x*ux + shift.y*vx, br.y + shift.x*uy + shift.y*vy}
	dst := [4]point{t.tl.point, t.tr.point, t.bl.point, guess}
	aligned := false
	if dim > 21 && shift == (point{}) {
		// The alignment pattern center is 3 modules inside the corner.
		corr := 1 - 3/(float64(dim)-7)
		est := point{t.tl.x + corr*(br.x-t.tl.x), t.tl.y + corr*(br.y-t.tl.y)}
		for _, allowance := range []float64{4, 8, 16} {
			if ap, ok := findAlignment(img, est, module, allowance); ok {
				src[3] = point{float64(dim) - 6.5, float64(dim) - 6.5}
				dst[3] = ap
				aligned = true
				break
			}
		}
	}
	h, ok := homography(src, dst)
	if !ok {
		return nil, aligned, ErrNotFound
	}
	g := &grid{size: dim, dark: make([]bool, dim*dim)}
	for y := 0; y < dim; y++ {
		for x := 0; x < dim; x++ {
			p, ok := h.apply(float64(x)+0.5, float64(y)+0.5)
			if !ok {
				return nil, aligned, ErrNotFound
			}
			ix, iy := int(math.Floor(p.x)), int(math.Floor(p.y))
			// One module of slack at the border, read as light.
			if !img.inside(ix, iy) {
				if p.x < -module || p.y < -module || p.x > float64(img.w)+module || p.y > float64(img.h)+module {
					return nil, aligned, ErrNotFound
				}
				continue
			}
			g.dark[y*dim+x] = img.at(ix, iy)
		}
	}
	return g, aligned, nil
}

// maxShiftedDim is the largest symbol (version 10) whose fourth corner is
// searched when no alignment pattern was found.
const maxShiftedDim = 57

// cornerShifts are the fourth-corner offsets in modules, nearest first.
var cornerShifts = func() []point {
	var out []point
	for r := 1; r <= 3; r++ {
		for dy := -r; dy <= r; dy++ {
			for dx := -r; dx <= r; dx++ {
				if max(abs(dx), abs(dy)) == r {
					out = append(out, point{float64(dx), float64(dy)})
				}
			}
		}
	}
	return out
}()

// findAlignment searches a square around est for the light-dark-light
// core of an alignment pattern and returns the candidate nearest est.
func findAlignment(img *bitImage, est point, module, allowance float64) (point, bool) {
	r := allowance * module
	x0, x1 := max(int(est.x-r), 0), min(int(est.x+r), img.w-1)
	y0, y1 := max(int(est.y-r), 0), min(int(est.y+r), img.h-1)
	if x1-x0 < int(3*module) || y1-y0 < int(3*module) {
		return point{}, false
	}
	near := func(n int) bool { return float64(n) >= 0.5*module && float64(n) <= 1.6*module }
	best, bestD := point{}, math.Inf(1)
	for y := y0; y <= y1; y++ {
		// Run lengths of the row segment.
		var runs []int
		var starts []int
		cur, n := img.at(x0, y), 0
		for x := x0; x <= x1; x++ {
			if d := img.at(x, y); d != cur {
				runs, starts = append(runs, n), append(starts, x-n)
				cur, n = d, 0
			}
			n++
		}
		runs, starts = append(runs, n), append(starts, x1+1-n)
		first := img.at(x0, y)
		for i := 2; i+2 < len(runs); i++ {
			// Runs alternate colors starting with the first pixel's.
			if dark := (i%2 == 0) == first; !dark {
				continue
			}
			// Dark ring, light ring, dark center, light ring, dark ring; the
			// outer rings may merge with neighbouring dark modules.
			if !near(runs[i]) || !near(runs[i-1]) || !near(runs[i+1]) ||
				float64(runs[i-2]) < 0.4*module || float64(runs[i+2]) < 0.4*module {
				continue
			}
			cx := float64(starts[i]) + float64(runs[i])/2
			cy, ok := alignmentCross(img, int(cx), y, module)
			if !ok {
				continue
			}
			p := point{cx, cy}
			if d := dist(p, est); d < bestD {
				best, bestD = p, d
			}
		}
	}
	return best, !math.IsInf(bestD, 1)
}

// alignmentCross checks the light-dark-light core vertically through
// (x, y) and returns the center row.
func alignmentCross(img *bitImage, x, y int, module float64) (float64, bool) {
	if !img.at(x, y) {
		return 0, false
	}
	near := func(n int) bool { return float64(n) >= 0.5*module && float64(n) <= 1.6*module }
	limit := int(2*module) + 2
	up, down := 0, 0
	for img.at(x, y-up-1) && up < limit {
		up++
	}
	for img.at(x, y+down+1) && down < limit {
		down++
	}
	center := up + down + 1
	if !near(center) {
		return 0, false
	}
	top, bottom := y-up-1, y+down+1
	lu, ld := 0, 0
	for img.inside(x, top-lu) && !img.at(x, top-lu) && lu < limit {
		lu++
	}
	for img.inside(x, bottom+ld) && !img.at(x, bottom+ld) && ld < limit {
		ld++
	}
	if !near(lu) || !near(ld) || !img.at(x, top-lu) || !img.at(x, bottom+ld) {
		return 0, false
	}
	return float64(y-up) + float64(center)/2, true
}

// homo is a 3x3 homography with h[8] = 1.
type homo [9]float64

func (h homo) apply(u, v float64) (point, bool) {
	w := h[6]*u + h[7]*v + h[8]
	if math.Abs(w) < 1e-12 {
		return point{}, false
	}
	return point{(h[0]*u + h[1]*v + h[2]) / w, (h[3]*u + h[4]*v + h[5]) / w}, true
}

// homography solves the projective map taking src[i] to dst[i].
func homography(src, dst [4]point) (homo, bool) {
	var a [8][9]float64
	for i := 0; i < 4; i++ {
		u, v, X, Y := src[i].x, src[i].y, dst[i].x, dst[i].y
		a[2*i] = [9]float64{u, v, 1, 0, 0, 0, -u * X, -v * X, X}
		a[2*i+1] = [9]float64{0, 0, 0, u, v, 1, -u * Y, -v * Y, Y}
	}
	for col := 0; col < 8; col++ {
		pivot := col
		for r := col + 1; r < 8; r++ {
			if math.Abs(a[r][col]) > math.Abs(a[pivot][col]) {
				pivot = r
			}
		}
		if math.Abs(a[pivot][col]) < 1e-9 {
			return homo{}, false
		}
		a[col], a[pivot] = a[pivot], a[col]
		for r := 0; r < 8; r++ {
			if r == col {
				continue
			}
			f := a[r][col] / a[col][col]
			for c := col; c < 9; c++ {
				a[r][c] -= f * a[col][c]
			}
		}
	}
	var h homo
	for i := 0; i < 8; i++ {
		h[i] = a[i][8] / a[i][i]
		if math.IsNaN(h[i]) || math.IsInf(h[i], 0) {
			return homo{}, false
		}
	}
	h[8] = 1
	return h, true
}
