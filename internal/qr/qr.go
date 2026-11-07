// Package qr is a dependency-free QR Code (ISO/IEC 18004) encoder used to
// show enrollment requests, fingerprints and paper backups (#18, #19,
// ADR-0063). It encodes one segment in byte or alphanumeric mode, picks the
// smallest version (1-40) for the requested error correction level, and
// chooses the mask with the lowest penalty. The decoder (decode.go,
// decode_image.go; P27, #182) reads symbols back from a camera frame or an
// image for the Android app and "device add --request-image".
package qr

import (
	"errors"
	"fmt"
)

// Level is the error correction level.
type Level int

// Error correction levels: L recovers about 7% of the code, M 15%, Q 25%
// and H 30%.
const (
	L Level = iota
	M
	Q
	H
)

func (l Level) String() string {
	switch l {
	case L:
		return "L"
	case M:
		return "M"
	case Q:
		return "Q"
	case H:
		return "H"
	}
	return fmt.Sprintf("Level(%d)", int(l))
}

// ErrTooLong is returned when the data does not fit version 40.
var ErrTooLong = errors.New("data is too long for a QR code")

// MaxInput bounds the input accepted by Encode (version 40-L byte mode).
const MaxInput = 2953

const (
	minVersion = 1
	maxVersion = 40
)

// Code is an encoded QR symbol without the quiet zone.
type Code struct {
	Version int
	Level   Level
	Mask    int
	Size    int
	modules []bool // row-major, true is dark
}

// Dark reports whether the module at column x, row y is dark. Coordinates
// outside the symbol (the quiet zone) are light.
func (c *Code) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.modules[y*c.Size+x]
}

// Error correction tables, indexed [level][version] (Nayuki's layout of the
// ISO/IEC 18004 table 9). Index 0 is unused.
var eccCodewordsPerBlock = [4][41]int{
	{-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	{-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
}

var numErrorCorrectionBlocks = [4][41]int{
	{-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	{-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	{-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
}

// formatBits are the two error correction bits of the format information.
var formatBits = [4]int{L: 1, M: 0, Q: 3, H: 2}

// numRawDataModules is the number of modules left for data and error
// correction after the function patterns of a version.
func numRawDataModules(ver int) int {
	result := (16*ver+128)*ver + 64
	if ver >= 2 {
		numAlign := ver/7 + 2
		result -= (25*numAlign-10)*numAlign - 55
		if ver >= 7 {
			result -= 36
		}
	}
	return result
}

// numDataCodewords is the data capacity of a version and level in bytes.
func numDataCodewords(ver int, lvl Level) int {
	return numRawDataModules(ver)/8 - eccCodewordsPerBlock[lvl][ver]*numErrorCorrectionBlocks[lvl][ver]
}

// Segment modes.
const (
	modeAlphanumeric = 0x2
	modeByte         = 0x4
)

const alphanumericCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

func alphanumericValue(c byte) int {
	for i := 0; i < len(alphanumericCharset); i++ {
		if alphanumericCharset[i] == c {
			return i
		}
	}
	return -1
}

func isAlphanumeric(data []byte) bool {
	for _, c := range data {
		if alphanumericValue(c) < 0 {
			return false
		}
	}
	return true
}

func countBits(mode, ver int) int {
	switch mode {
	case modeAlphanumeric:
		switch {
		case ver <= 9:
			return 9
		case ver <= 26:
			return 11
		}
		return 13
	default:
		if ver <= 9 {
			return 8
		}
		return 16
	}
}

func payloadBits(mode, n int) int {
	if mode == modeAlphanumeric {
		return n/2*11 + n%2*6
	}
	return n * 8
}

// bitBuffer collects bits most significant first.
type bitBuffer []bool

func (b *bitBuffer) append(v, n int) {
	for i := n - 1; i >= 0; i-- {
		*b = append(*b, (v>>i)&1 == 1)
	}
}

// Encode encodes data at level lvl in the smallest version that fits. Data
// made only of QR alphanumeric characters (digits, uppercase letters and
// " $%*+-./:") uses alphanumeric mode, everything else byte mode.
func Encode(data []byte, lvl Level) (*Code, error) {
	if lvl < L || lvl > H {
		return nil, errors.New("invalid error correction level")
	}
	if len(data) > MaxInput {
		return nil, ErrTooLong
	}
	mode := modeByte
	if len(data) > 0 && isAlphanumeric(data) {
		mode = modeAlphanumeric
	}
	ver := 0
	for v := minVersion; v <= maxVersion; v++ {
		cb := countBits(mode, v)
		if len(data) >= 1<<cb {
			continue
		}
		if 4+cb+payloadBits(mode, len(data)) <= numDataCodewords(v, lvl)*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}

	var bb bitBuffer
	bb.append(mode, 4)
	bb.append(len(data), countBits(mode, ver))
	if mode == modeAlphanumeric {
		i := 0
		for ; i+1 < len(data); i += 2 {
			bb.append(alphanumericValue(data[i])*45+alphanumericValue(data[i+1]), 11)
		}
		if i < len(data) {
			bb.append(alphanumericValue(data[i]), 6)
		}
	} else {
		for _, c := range data {
			bb.append(int(c), 8)
		}
	}
	capacity := numDataCodewords(ver, lvl) * 8
	bb.append(0, min(4, capacity-len(bb)))
	bb.append(0, (8-len(bb)%8)%8)
	for pad := 0xEC; len(bb) < capacity; pad ^= 0xEC ^ 0x11 {
		bb.append(pad, 8)
	}
	codewords := make([]byte, len(bb)/8)
	for i, bit := range bb {
		if bit {
			codewords[i>>3] |= 1 << (7 - i&7)
		}
	}
	return build(ver, lvl, addECCAndInterleave(codewords, ver, lvl), -1), nil
}

// EncodeText encodes a string.
func EncodeText(s string, lvl Level) (*Code, error) { return Encode([]byte(s), lvl) }

// addECCAndInterleave splits the data into blocks, appends Reed-Solomon
// error correction to each, and interleaves the blocks.
func addECCAndInterleave(data []byte, ver int, lvl Level) []byte {
	numBlocks := numErrorCorrectionBlocks[lvl][ver]
	blockECCLen := eccCodewordsPerBlock[lvl][ver]
	rawCodewords := numRawDataModules(ver) / 8
	numShortBlocks := numBlocks - rawCodewords%numBlocks
	shortBlockLen := rawCodewords / numBlocks

	divisor := rsDivisor(blockECCLen)
	blocks := make([][]byte, 0, numBlocks)
	k := 0
	for i := 0; i < numBlocks; i++ {
		datLen := shortBlockLen - blockECCLen
		if i >= numShortBlocks {
			datLen++
		}
		dat := data[k : k+datLen]
		k += datLen
		block := make([]byte, 0, shortBlockLen+1)
		block = append(block, dat...)
		if i < numShortBlocks {
			block = append(block, 0) // placeholder, skipped when interleaving
		}
		block = append(block, rsRemainder(dat, divisor)...)
		blocks = append(blocks, block)
	}
	result := make([]byte, 0, rawCodewords)
	for i := 0; i < len(blocks[0]); i++ {
		for j, block := range blocks {
			if i != shortBlockLen-blockECCLen || j >= numShortBlocks {
				result = append(result, block[i])
			}
		}
	}
	return result
}

// gfMul multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
func gfMul(x, y byte) byte {
	var z int
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= int((y>>i)&1) * int(x)
	}
	return byte(z)
}

// rsDivisor returns the generator polynomial of the given degree, without
// the leading 1, highest power first.
func rsDivisor(degree int) []byte {
	result := make([]byte, degree)
	result[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			result[j] = gfMul(result[j], root)
			if j+1 < degree {
				result[j] ^= result[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return result
}

func rsRemainder(data, divisor []byte) []byte {
	result := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ result[0]
		copy(result, result[1:])
		result[len(result)-1] = 0
		for i, d := range divisor {
			result[i] ^= gfMul(d, factor)
		}
	}
	return result
}

// builder holds the symbol while it is drawn.
type builder struct {
	size       int
	ver        int
	lvl        Level
	modules    []bool
	isFunction []bool
}

func (b *builder) set(x, y int, dark bool) { b.modules[y*b.size+x] = dark }
func (b *builder) get(x, y int) bool       { return b.modules[y*b.size+x] }

func (b *builder) setFunction(x, y int, dark bool) {
	b.modules[y*b.size+x] = dark
	b.isFunction[y*b.size+x] = true
}

// build draws the symbol. A mask of -1 selects the lowest-penalty mask.
func build(ver int, lvl Level, codewords []byte, mask int) *Code {
	size := ver*4 + 17
	b := &builder{size: size, ver: ver, lvl: lvl, modules: make([]bool, size*size), isFunction: make([]bool, size*size)}
	b.drawFunctionPatterns()
	b.drawCodewords(codewords)
	if mask < 0 {
		best := 1 << 30
		for m := 0; m < 8; m++ {
			b.applyMask(m)
			b.drawFormatBits(m)
			if p := b.penalty(); p < best {
				best, mask = p, m
			}
			b.applyMask(m) // XOR undoes the mask
		}
	}
	b.applyMask(mask)
	b.drawFormatBits(mask)
	return &Code{Version: ver, Level: lvl, Mask: mask, Size: size, modules: b.modules}
}

func (b *builder) drawFunctionPatterns() {
	for i := 0; i < b.size; i++ {
		b.setFunction(6, i, i%2 == 0)
		b.setFunction(i, 6, i%2 == 0)
	}
	b.drawFinder(3, 3)
	b.drawFinder(b.size-4, 3)
	b.drawFinder(3, b.size-4)
	align := alignmentPositions(b.ver)
	n := len(align)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			b.drawAlignment(align[i], align[j])
		}
	}
	b.drawFormatBits(0) // reserves the area; redrawn with the real mask
	b.drawVersion()
}

// alignmentPositions returns the row and column centers of the alignment
// patterns of a version.
func alignmentPositions(ver int) []int {
	if ver == 1 {
		return nil
	}
	numAlign := ver/7 + 2
	step := (ver*8 + numAlign*3 + 5) / (numAlign*4 - 4) * 2
	result := make([]int, numAlign)
	result[0] = 6
	pos := ver*4 + 10
	for i := numAlign - 1; i >= 1; i-- {
		result[i] = pos
		pos -= step
	}
	return result
}

func (b *builder) drawFinder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			dist := max(abs(dx), abs(dy))
			xx, yy := x+dx, y+dy
			if xx >= 0 && xx < b.size && yy >= 0 && yy < b.size {
				b.setFunction(xx, yy, dist != 2 && dist != 4)
			}
		}
	}
}

func (b *builder) drawAlignment(x, y int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			b.setFunction(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
		}
	}
}

// formatInfo returns the 15-bit BCH-protected format information.
func formatInfo(lvl Level, mask int) int {
	data := formatBits[lvl]<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	return (data<<10 | rem) ^ 0x5412
}

func (b *builder) drawFormatBits(mask int) {
	bits := formatInfo(b.lvl, mask)
	bit := func(i int) bool { return (bits>>i)&1 == 1 }
	for i := 0; i <= 5; i++ {
		b.setFunction(8, i, bit(i))
	}
	b.setFunction(8, 7, bit(6))
	b.setFunction(8, 8, bit(7))
	b.setFunction(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		b.setFunction(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		b.setFunction(b.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		b.setFunction(8, b.size-15+i, bit(i))
	}
	b.setFunction(8, b.size-8, true) // the dark module
}

// versionInfo returns the 18-bit BCH-protected version information.
func versionInfo(ver int) int {
	rem := ver
	for i := 0; i < 12; i++ {
		rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
	}
	return ver<<12 | rem
}

func (b *builder) drawVersion() {
	if b.ver < 7 {
		return
	}
	bits := versionInfo(b.ver)
	for i := 0; i < 18; i++ {
		dark := (bits>>i)&1 == 1
		a := b.size - 11 + i%3
		c := i / 3
		b.setFunction(a, c, dark)
		b.setFunction(c, a, dark)
	}
}

// drawCodewords places the bits in the two-column zigzag, skipping
// function modules. Remainder modules stay light before masking.
func (b *builder) drawCodewords(data []byte) {
	i := 0
	for right := b.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // skip the vertical timing pattern
		}
		for vert := 0; vert < b.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = b.size - 1 - vert
				}
				if !b.isFunction[y*b.size+x] && i < len(data)*8 {
					b.set(x, y, (data[i>>3]>>(7-i&7))&1 == 1)
					i++
				}
			}
		}
	}
}

// maskBit reports whether mask m inverts the module at column x, row y.
func maskBit(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (b *builder) applyMask(m int) {
	for y := 0; y < b.size; y++ {
		for x := 0; x < b.size; x++ {
			if !b.isFunction[y*b.size+x] && maskBit(m, x, y) {
				b.modules[y*b.size+x] = !b.modules[y*b.size+x]
			}
		}
	}
}

// Penalty weights of ISO/IEC 18004 section 7.8.3.
const (
	penaltyN1 = 3
	penaltyN2 = 3
	penaltyN3 = 40
	penaltyN4 = 10
)

func (b *builder) penalty() int {
	result := 0
	n := b.size
	line := make([]bool, n)
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				if pass == 0 {
					line[j] = b.get(j, i)
				} else {
					line[j] = b.get(i, j)
				}
			}
			result += linePenalty(line)
		}
	}
	for y := 0; y < n-1; y++ {
		for x := 0; x < n-1; x++ {
			c := b.get(x, y)
			if c == b.get(x+1, y) && c == b.get(x, y+1) && c == b.get(x+1, y+1) {
				result += penaltyN2
			}
		}
	}
	dark := 0
	for _, m := range b.modules {
		if m {
			dark++
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1
	result += k * penaltyN4
	return result
}

// finderLike is 1:1:3:1:1 dark-light pattern with four light modules on
// one side.
var finderLike = [2][11]bool{
	{true, false, true, true, true, false, true, false, false, false, false},
	{false, false, false, false, true, false, true, true, true, false, true},
}

func linePenalty(line []bool) int {
	result := 0
	run := 1
	for i := 1; i <= len(line); i++ {
		if i < len(line) && line[i] == line[i-1] {
			run++
			continue
		}
		if run >= 5 {
			result += penaltyN1 + run - 5
		}
		run = 1
	}
	for i := 0; i+11 <= len(line); i++ {
		for _, p := range finderLike {
			match := true
			for k := 0; k < 11; k++ {
				if line[i+k] != p[k] {
					match = false
					break
				}
			}
			if match {
				result += penaltyN3
			}
		}
	}
	return result
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
