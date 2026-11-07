package qr

import (
	"bytes"
	"crypto/rand"
	"image/png"
	"strings"
	"testing"
)

// gfPow returns 2^e in GF(2^8), computed independently of rsDivisor.
func gfPow(e int) byte {
	v := byte(1)
	for i := 0; i < e; i++ {
		v = gfMul(v, 2)
	}
	return v
}

// syndromesZero evaluates the codeword polynomial at 2^0..2^(n-1); a valid
// Reed-Solomon block has all syndromes zero.
func syndromesZero(block []byte, n int) bool {
	for i := 0; i < n; i++ {
		x := gfPow(i)
		var s byte
		for _, c := range block {
			s = gfMul(s, x) ^ c
		}
		if s != 0 {
			return false
		}
	}
	return true
}

func TestHelloWorldKnownAnswer(t *testing.T) {
	// The worked example of the alphanumeric "HELLO WORLD" at 1-Q.
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236}
	ecc := []byte{168, 72, 22, 82, 217, 54, 156, 0, 46, 15, 180, 122, 16}
	if got := rsRemainder(data, rsDivisor(13)); !bytes.Equal(got, ecc) {
		t.Fatalf("ecc = %v", got)
	}
	c, err := EncodeText("HELLO WORLD", Q)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.Size != 21 {
		t.Fatalf("version %d size %d", c.Version, c.Size)
	}
	if got := readBack(t, c); string(got) != "HELLO WORLD" {
		t.Fatalf("read back %q", got)
	}
}

func TestCapacities(t *testing.T) {
	// Byte mode capacities from the standard's capacity table.
	for _, tc := range []struct {
		ver  int
		lvl  Level
		want int
	}{
		{1, L, 17}, {1, M, 14}, {1, Q, 11}, {1, H, 7},
		{10, M, 213}, {10, H, 119}, {20, L, 858}, {40, L, 2953}, {40, H, 1273},
	} {
		got := (numDataCodewords(tc.ver, tc.lvl)*8 - 4 - countBits(modeByte, tc.ver)) / 8
		if got != tc.want {
			t.Errorf("%d-%s byte capacity %d, want %d", tc.ver, tc.lvl, got, tc.want)
		}
	}
	for _, tc := range []struct {
		ver  int
		want []int
	}{
		{2, []int{6, 18}}, {7, []int{6, 22, 38}}, {15, []int{6, 26, 48, 70}},
		{32, []int{6, 34, 60, 86, 112, 138}}, {36, []int{6, 24, 50, 76, 102, 128, 154}},
	} {
		if got := alignmentPositions(tc.ver); !equalInts(got, tc.want) {
			t.Errorf("v%d alignment %v, want %v", tc.ver, got, tc.want)
		}
	}
	// Version 7 information from the standard's example: 000111110010010100.
	if got := versionInfo(7); got != 0x07C94 {
		t.Errorf("version 7 info %#x", got)
	}
	// Format information for M, mask 5 (example in the standard): 100000011001110.
	if got := formatInfo(M, 5); got != 0x40CE {
		t.Errorf("format M/5 %#x", got)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRoundTrip(t *testing.T) {
	inputs := [][]byte{
		[]byte("osreq1." + strings.Repeat("eyJjb250ZXh0Ijoib3BlbnNjYWxlL2Vucm9sbG1lbnQ", 14)),
		[]byte("OSPB1:" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 7)),
		[]byte("ABCD-EFGH-IJKL-MNOP"),
		{},
		{0x00, 0xff, 0x10},
	}
	random := make([]byte, 700)
	_, _ = rand.Read(random)
	inputs = append(inputs, random)
	for _, in := range inputs {
		for lvl := L; lvl <= H; lvl++ {
			c, err := Encode(in, lvl)
			if err != nil {
				t.Fatalf("%d bytes at %s: %v", len(in), lvl, err)
			}
			if got := readBack(t, c); !bytes.Equal(got, in) {
				t.Fatalf("%d bytes at %s: read back differs", len(in), lvl)
			}
		}
	}
	if _, err := Encode(make([]byte, MaxInput+1), L); err != ErrTooLong {
		t.Fatalf("too long: %v", err)
	}
	if _, err := Encode(make([]byte, 1300), H); err != ErrTooLong {
		t.Fatalf("too long for H: %v", err)
	}
	if c, err := Encode(make([]byte, MaxInput), L); err != nil || c.Version != 40 {
		t.Fatalf("max input: %v", err)
	}
}

func FuzzEncode(f *testing.F) {
	f.Add([]byte("HELLO WORLD"), uint8(2))
	f.Add([]byte("osreq1.abc"), uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, lvl uint8) {
		if len(data) > 400 {
			return
		}
		c, err := Encode(data, Level(lvl%4))
		if err != nil {
			t.Fatal(err)
		}
		if got := readBack(t, c); !bytes.Equal(got, data) {
			t.Fatal("read back differs")
		}
	})
}

func TestRender(t *testing.T) {
	c, err := EncodeText("OPENSCALE", M)
	if err != nil {
		t.Fatal(err)
	}
	var term bytes.Buffer
	if err := c.Terminal(&term, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(term.String(), "\n"), "\n")
	if len(lines) != (c.Size+2*QuietZone+1)/2 {
		t.Fatalf("%d terminal lines", len(lines))
	}
	var img bytes.Buffer
	if err := c.PNG(&img, 4); err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(&img)
	if err != nil {
		t.Fatal(err)
	}
	side := (c.Size + 2*QuietZone) * 4
	if decoded.Bounds().Dx() != side {
		t.Fatalf("png side %d", decoded.Bounds().Dx())
	}
	// Top-left finder corner is dark, the quiet zone light.
	if r, _, _, _ := decoded.At(QuietZone*4, QuietZone*4).RGBA(); r != 0 {
		t.Fatal("finder corner must be black")
	}
	if r, _, _, _ := decoded.At(0, 0).RGBA(); r == 0 {
		t.Fatal("quiet zone must be white")
	}
	if _, err := c.Image(0); err == nil {
		t.Fatal("scale 0 accepted")
	}
}

// readBack decodes a symbol with an independent reader: it checks the
// finder patterns and the format information, removes the mask, reads the
// zigzag, de-interleaves the blocks, checks every Reed-Solomon block by its
// syndromes and parses the segment.
func readBack(t *testing.T, c *Code) []byte {
	t.Helper()
	n := c.Size
	for _, corner := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		for d := 0; d < 7; d++ {
			if !c.Dark(corner[0]+d, corner[1]) || !c.Dark(corner[0], corner[1]+d) {
				t.Fatal("finder pattern border missing")
			}
		}
		if !c.Dark(corner[0]+3, corner[1]+3) || c.Dark(corner[0]+1, corner[1]+1) {
			t.Fatal("finder pattern center wrong")
		}
	}
	for i := 8; i < n-8; i++ {
		if c.Dark(i, 6) != (i%2 == 0) || c.Dark(6, i) != (i%2 == 0) {
			t.Fatal("timing pattern wrong")
		}
	}
	// Format information, first copy.
	var f1 int
	pos := [][2]int{{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8}, {7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8}}
	for i, p := range pos {
		if c.Dark(p[0], p[1]) {
			f1 |= 1 << i
		}
	}
	var f2 int
	for i := 0; i < 8; i++ {
		if c.Dark(n-1-i, 8) {
			f2 |= 1 << i
		}
	}
	for i := 8; i < 15; i++ {
		if c.Dark(8, n-15+i) {
			f2 |= 1 << i
		}
	}
	if f1 != f2 || f1 != formatInfo(c.Level, c.Mask) {
		t.Fatalf("format information %#x / %#x", f1, f2)
	}
	if !c.Dark(8, n-8) {
		t.Fatal("dark module missing")
	}
	// Function modules: rebuild the map for this version.
	b := &builder{size: n, ver: c.Version, lvl: c.Level, modules: make([]bool, n*n), isFunction: make([]bool, n*n)}
	b.drawFunctionPatterns()
	// Read the zigzag.
	var bits []bool
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = n - 1 - vert
				}
				if b.isFunction[y*n+x] {
					continue
				}
				bits = append(bits, c.Dark(x, y) != maskBit(c.Mask, x, y))
			}
		}
	}
	raw := numRawDataModules(c.Version) / 8
	if len(bits) < raw*8 {
		t.Fatalf("only %d data modules", len(bits))
	}
	cw := make([]byte, raw)
	for i := 0; i < raw*8; i++ {
		if bits[i] {
			cw[i/8] |= 1 << (7 - i%8)
		}
	}
	// De-interleave.
	nb := numErrorCorrectionBlocks[c.Level][c.Version]
	eccLen := eccCodewordsPerBlock[c.Level][c.Version]
	short := nb - raw%nb
	dataLens := make([]int, nb)
	for i := range dataLens {
		dataLens[i] = raw/nb - eccLen
		if i >= short {
			dataLens[i]++
		}
	}
	blocks := make([][]byte, nb)
	k := 0
	maxData := dataLens[nb-1]
	for i := 0; i < maxData; i++ {
		for j := 0; j < nb; j++ {
			if i < dataLens[j] {
				blocks[j] = append(blocks[j], cw[k])
				k++
			}
		}
	}
	for i := 0; i < eccLen; i++ {
		for j := 0; j < nb; j++ {
			blocks[j] = append(blocks[j], cw[k])
			k++
		}
	}
	var data []byte
	for j, blk := range blocks {
		if !syndromesZero(blk, eccLen) {
			t.Fatalf("block %d fails the Reed-Solomon check", j)
		}
		data = append(data, blk[:dataLens[j]]...)
	}
	// Parse the segment.
	r := bitReader{data: data}
	mode := r.read(4)
	switch mode {
	case modeByte:
		count := r.read(countBits(modeByte, c.Version))
		out := make([]byte, count)
		for i := range out {
			out[i] = byte(r.read(8))
		}
		return out
	case modeAlphanumeric:
		count := r.read(countBits(modeAlphanumeric, c.Version))
		var out []byte
		for ; count >= 2; count -= 2 {
			v := r.read(11)
			out = append(out, alphanumericCharset[v/45], alphanumericCharset[v%45])
		}
		if count == 1 {
			out = append(out, alphanumericCharset[r.read(6)])
		}
		return out
	}
	t.Fatalf("unknown mode %d", mode)
	return nil
}

type bitReader struct {
	data []byte
	pos  int
}

func (r *bitReader) read(n int) int {
	v := 0
	for i := 0; i < n; i++ {
		bit := (r.data[r.pos/8] >> (7 - r.pos%8)) & 1
		v = v<<1 | int(bit)
		r.pos++
	}
	return v
}
