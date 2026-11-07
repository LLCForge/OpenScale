package qr

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"
)

// The decoder (P27, #182) reads a QR symbol back: DecodeGrid works on an
// already sampled module grid, DecodeGray (decode_image.go) finds and
// samples the symbol in a camera frame first. It supports what Encode
// writes and what common generators write: numeric, alphanumeric and byte
// segments, ECI headers (skipped), versions 1-40 and all levels. Kanji,
// structured append and FNC1 are refused. Decoding never trusts its input:
// format and version information are BCH-checked, every block is
// Reed-Solomon corrected within the spec's misdecode margin and checked
// again, and segment lengths are bounded by the data actually present.

// Decode errors.
var (
	ErrNotFound     = errors.New("qr: no QR code found")
	ErrFormat       = errors.New("qr: format information is unreadable")
	ErrCorrupt      = errors.New("qr: too many errors to correct")
	ErrUnsupported  = errors.New("qr: unsupported segment mode")
	ErrBadGridSize  = errors.New("qr: grid size is not a QR version")
	errVersionMatch = errors.New("qr: version information does not match the size")
)

// Segment modes not written by Encode.
const (
	modeTerminator     = 0x0
	modeNumeric        = 0x1
	modeStructuredApp  = 0x3
	modeFNC1First      = 0x5
	modeECI            = 0x7
	modeKanji          = 0x8
	modeFNC1Second     = 0x9
	maxBCHDistance     = 3
	maxDecodedDataSize = 4 * 1024
)

// gf holds exp/log tables of GF(2^8) with generator 2 (built from gfMul).
var gf struct {
	once sync.Once
	exp  [512]byte
	log  [256]int
}

func gfTables() {
	gf.once.Do(func() {
		x := byte(1)
		for i := 0; i < 255; i++ {
			gf.exp[i] = x
			gf.log[x] = i
			x = gfMul(x, 2)
		}
		for i := 255; i < 512; i++ {
			gf.exp[i] = gf.exp[i-255]
		}
	})
}

func gfInv(x byte) byte { return gf.exp[255-gf.log[x]] }

func gfDiv(x, y byte) byte {
	if x == 0 {
		return 0
	}
	return gf.exp[gf.log[x]+255-gf.log[y]]
}

// misdecodeProtection is the "p" of ISO/IEC 18004 table 9: codewords of
// small symbols reserved for error detection instead of correction.
func misdecodeProtection(ver int, lvl Level) int {
	switch {
	case ver == 1 && lvl == L:
		return 3
	case ver == 1 && lvl == M, ver == 2 && lvl == L:
		return 2
	case ver == 1 && (lvl == Q || lvl == H), ver == 3 && lvl == L:
		return 1
	}
	return 0
}

// rsCorrect corrects block (data followed by ecc check codewords, highest
// degree first) in place. At most maxErrors errors are corrected; the
// corrected block is checked again.
func rsCorrect(block []byte, ecc, maxErrors int) error {
	gfTables()
	n := len(block)
	if n > 255 || ecc <= 0 || ecc >= n {
		return ErrCorrupt
	}
	synd := make([]byte, ecc)
	nonzero := false
	for j := range synd {
		synd[j] = polyEvalHigh(block, gf.exp[j])
		if synd[j] != 0 {
			nonzero = true
		}
	}
	if !nonzero {
		return nil
	}
	// Berlekamp-Massey: lambda is the error locator, lowest degree first.
	lambda := make([]byte, ecc+1)
	prev := make([]byte, ecc+1)
	lambda[0], prev[0] = 1, 1
	length, shift, lastD := 0, 1, byte(1)
	tmp := make([]byte, ecc+1)
	for k := 0; k < ecc; k++ {
		d := synd[k]
		for i := 1; i <= length; i++ {
			d ^= gfMul(lambda[i], synd[k-i])
		}
		if d == 0 {
			shift++
			continue
		}
		coef := gfDiv(d, lastD)
		if 2*length <= k {
			copy(tmp, lambda)
			for i := 0; i+shift <= ecc; i++ {
				lambda[i+shift] ^= gfMul(coef, prev[i])
			}
			length = k + 1 - length
			copy(prev, tmp)
			lastD, shift = d, 1
		} else {
			for i := 0; i+shift <= ecc; i++ {
				lambda[i+shift] ^= gfMul(coef, prev[i])
			}
			shift++
		}
	}
	if length == 0 || length > maxErrors {
		return ErrCorrupt
	}
	// Chien search: an error at degree e makes lambda(2^-e) zero.
	positions := make([]int, 0, length)
	for e := 0; e < n; e++ {
		if polyEvalLow(lambda[:length+1], gf.exp[(255-e)%255]) == 0 {
			positions = append(positions, e)
		}
	}
	if len(positions) != length {
		return ErrCorrupt
	}
	// Forney (first consecutive root 2^0): e = X * omega(X^-1) / lambda'(X^-1).
	omega := make([]byte, ecc)
	for i := 0; i < ecc; i++ {
		var v byte
		for j := 0; j <= i && j <= length; j++ {
			v ^= gfMul(synd[i-j], lambda[j])
		}
		omega[i] = v
	}
	for _, e := range positions {
		x := gf.exp[e%255]
		xInv := gfInv(x)
		var deriv byte
		for i := 1; i <= length; i += 2 {
			deriv ^= gfMul(lambda[i], gfPowByte(xInv, i-1))
		}
		if deriv == 0 {
			return ErrCorrupt
		}
		mag := gfMul(x, gfDiv(polyEvalLow(omega, xInv), deriv))
		block[n-1-e] ^= mag
	}
	for j := 0; j < ecc; j++ {
		if polyEvalHigh(block, gf.exp[j]) != 0 {
			return ErrCorrupt
		}
	}
	return nil
}

func gfPowByte(x byte, e int) byte {
	if e == 0 {
		return 1
	}
	if x == 0 {
		return 0
	}
	return gf.exp[(gf.log[x]*e)%255]
}

// polyEvalHigh evaluates a polynomial stored highest degree first.
func polyEvalHigh(p []byte, x byte) byte {
	var v byte
	for _, c := range p {
		v = gfMul(v, x) ^ c
	}
	return v
}

// polyEvalLow evaluates a polynomial stored lowest degree first.
func polyEvalLow(p []byte, x byte) byte {
	var v byte
	for i := len(p) - 1; i >= 0; i-- {
		v = gfMul(v, x) ^ p[i]
	}
	return v
}

// grid is a sampled symbol, row-major, true is dark.
type grid struct {
	size int
	dark []bool
}

func (g *grid) at(x, y int) bool { return g.dark[y*g.size+x] }

func (g *grid) transposed() *grid {
	t := &grid{size: g.size, dark: make([]bool, len(g.dark))}
	for y := 0; y < g.size; y++ {
		for x := 0; x < g.size; x++ {
			t.dark[x*g.size+y] = g.dark[y*g.size+x]
		}
	}
	return t
}

// readFormat returns the level and mask from the two format copies.
func (g *grid) readFormat() (Level, int, error) {
	var a, b int
	for i := 0; i <= 5; i++ {
		a |= bitOf(g.at(8, i)) << i
	}
	a |= bitOf(g.at(8, 7)) << 6
	a |= bitOf(g.at(8, 8)) << 7
	a |= bitOf(g.at(7, 8)) << 8
	for i := 9; i < 15; i++ {
		a |= bitOf(g.at(14-i, 8)) << i
	}
	for i := 0; i < 8; i++ {
		b |= bitOf(g.at(g.size-1-i, 8)) << i
	}
	for i := 8; i < 15; i++ {
		b |= bitOf(g.at(8, g.size-15+i)) << i
	}
	best, bestDist := -1, maxBCHDistance+1
	for lvl := L; lvl <= H; lvl++ {
		for m := 0; m < 8; m++ {
			want := formatInfo(lvl, m)
			for _, got := range [2]int{a, b} {
				if d := bits.OnesCount(uint(want ^ got)); d < bestDist {
					best, bestDist = int(lvl)<<3|m, d
				}
			}
		}
	}
	if best < 0 {
		return 0, 0, ErrFormat
	}
	return Level(best >> 3), best & 7, nil
}

// readVersion decodes the version information of a symbol of version 7 or
// more; it returns 0 when neither copy is within the BCH distance.
func (g *grid) readVersion() int {
	var a, b int
	for i := 0; i < 18; i++ {
		x := g.size - 11 + i%3
		y := i / 3
		a |= bitOf(g.at(x, y)) << i
		b |= bitOf(g.at(y, x)) << i
	}
	best, bestDist := 0, maxBCHDistance+1
	for v := 7; v <= maxVersion; v++ {
		want := versionInfo(v)
		for _, got := range [2]int{a, b} {
			if d := bits.OnesCount(uint(want ^ got)); d < bestDist {
				best, bestDist = v, d
			}
		}
	}
	return best
}

func bitOf(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DecodeGrid decodes a sampled symbol of size×size modules (row-major,
// true is dark, no quiet zone). A mirrored symbol is also read.
func DecodeGrid(size int, modules []bool) ([]byte, error) {
	if size < 21 || size > 177 || (size-17)%4 != 0 {
		return nil, ErrBadGridSize
	}
	if len(modules) != size*size {
		return nil, errors.New("qr: module count does not match the size")
	}
	g := &grid{size: size, dark: modules}
	data, err := g.decode()
	if err == nil {
		return data, nil
	}
	if data2, err2 := g.transposed().decode(); err2 == nil {
		return data2, nil
	}
	return nil, err
}

func (g *grid) decode() ([]byte, error) {
	ver := (g.size - 17) / 4
	if ver >= 7 {
		if v := g.readVersion(); v != ver {
			return nil, errVersionMatch
		}
	}
	lvl, mask, err := g.readFormat()
	if err != nil {
		return nil, err
	}
	// The function pattern map of this version.
	b := &builder{size: g.size, ver: ver, lvl: lvl, modules: make([]bool, g.size*g.size), isFunction: make([]bool, g.size*g.size)}
	b.drawFunctionPatterns()

	raw := numRawDataModules(ver) / 8
	codewords := make([]byte, raw)
	i := 0
	for right := g.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < g.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = g.size - 1 - vert
				}
				if b.isFunction[y*g.size+x] || i >= raw*8 {
					continue
				}
				if g.at(x, y) != maskBit(mask, x, y) {
					codewords[i>>3] |= 1 << (7 - i&7)
				}
				i++
			}
		}
	}
	if i < raw*8 {
		return nil, ErrCorrupt
	}
	data, err := deinterleaveAndCorrect(codewords, ver, lvl)
	if err != nil {
		return nil, err
	}
	return parseSegments(data, ver)
}

// deinterleaveAndCorrect reverses addECCAndInterleave and corrects each
// block; it returns the data codewords.
func deinterleaveAndCorrect(raw []byte, ver int, lvl Level) ([]byte, error) {
	numBlocks := numErrorCorrectionBlocks[lvl][ver]
	blockECCLen := eccCodewordsPerBlock[lvl][ver]
	rawCodewords := numRawDataModules(ver) / 8
	if len(raw) != rawCodewords {
		return nil, ErrCorrupt
	}
	numShortBlocks := numBlocks - rawCodewords%numBlocks
	shortBlockLen := rawCodewords / numBlocks
	blocks := make([][]byte, numBlocks)
	for j := range blocks {
		blocks[j] = make([]byte, shortBlockLen+1)
	}
	k := 0
	for i := 0; i <= shortBlockLen; i++ {
		for j := range blocks {
			if i == shortBlockLen-blockECCLen && j < numShortBlocks {
				continue // the placeholder of a short block
			}
			blocks[j][i] = raw[k]
			k++
		}
	}
	maxErrors := (blockECCLen - misdecodeProtection(ver, lvl)) / 2
	out := make([]byte, 0, numDataCodewords(ver, lvl))
	for j, block := range blocks {
		datLen := shortBlockLen - blockECCLen
		if j < numShortBlocks {
			block = append(block[:datLen:datLen], block[datLen+1:]...)
		} else {
			datLen++
		}
		if err := rsCorrect(block, blockECCLen, maxErrors); err != nil {
			return nil, err
		}
		out = append(out, block[:datLen]...)
	}
	return out, nil
}

// segReader reads bits most significant first.
type segReader struct {
	data []byte
	pos  int
}

func (r *segReader) left() int { return len(r.data)*8 - r.pos }

func (r *segReader) read(n int) (int, bool) {
	if n < 0 || n > r.left() {
		return 0, false
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<1 | int(r.data[r.pos>>3]>>(7-r.pos&7)&1)
		r.pos++
	}
	return v, true
}

func numericCountBits(ver int) int {
	switch {
	case ver <= 9:
		return 10
	case ver <= 26:
		return 12
	}
	return 14
}

// parseSegments reads the segments of the data codewords.
func parseSegments(data []byte, ver int) ([]byte, error) {
	r := &segReader{data: data}
	var out []byte
	for r.left() >= 4 {
		mode, _ := r.read(4)
		switch mode {
		case modeTerminator:
			return out, nil
		case modeECI:
			// The designator is 1-3 bytes; the content is returned as bytes
			// whatever character set it names.
			first, ok := r.read(8)
			if !ok {
				return nil, ErrCorrupt
			}
			extra := 0
			switch {
			case first&0x80 == 0:
			case first&0xC0 == 0x80:
				extra = 8
			case first&0xE0 == 0xC0:
				extra = 16
			default:
				return nil, ErrCorrupt
			}
			if _, ok := r.read(extra); !ok {
				return nil, ErrCorrupt
			}
		case modeNumeric:
			n, ok := r.read(numericCountBits(ver))
			if !ok {
				return nil, ErrCorrupt
			}
			for n >= 3 {
				v, ok := r.read(10)
				if !ok || v > 999 {
					return nil, ErrCorrupt
				}
				out = append(out, byte('0'+v/100), byte('0'+v/10%10), byte('0'+v%10))
				n -= 3
			}
			switch n {
			case 2:
				v, ok := r.read(7)
				if !ok || v > 99 {
					return nil, ErrCorrupt
				}
				out = append(out, byte('0'+v/10), byte('0'+v%10))
			case 1:
				v, ok := r.read(4)
				if !ok || v > 9 {
					return nil, ErrCorrupt
				}
				out = append(out, byte('0'+v))
			}
		case modeAlphanumeric:
			n, ok := r.read(countBits(modeAlphanumeric, ver))
			if !ok || payloadBits(modeAlphanumeric, n) > r.left() {
				return nil, ErrCorrupt
			}
			for n >= 2 {
				v, _ := r.read(11)
				if v >= 45*45 {
					return nil, ErrCorrupt
				}
				out = append(out, alphanumericCharset[v/45], alphanumericCharset[v%45])
				n -= 2
			}
			if n == 1 {
				v, _ := r.read(6)
				if v >= 45 {
					return nil, ErrCorrupt
				}
				out = append(out, alphanumericCharset[v])
			}
		case modeByte:
			n, ok := r.read(countBits(modeByte, ver))
			if !ok || n*8 > r.left() {
				return nil, ErrCorrupt
			}
			for ; n > 0; n-- {
				v, _ := r.read(8)
				out = append(out, byte(v))
			}
		case modeKanji, modeStructuredApp, modeFNC1First, modeFNC1Second:
			return nil, fmt.Errorf("%w (%d)", ErrUnsupported, mode)
		default:
			return nil, ErrCorrupt
		}
		if len(out) > maxDecodedDataSize {
			return nil, ErrCorrupt
		}
	}
	return out, nil
}
