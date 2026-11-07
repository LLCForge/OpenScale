package trust

import (
	"crypto/sha256"
	"strings"
	"unicode"
)

// Visual fingerprints (#351): an OpenSSH-style "drunken bishop" picture of
// a fingerprint, shown next to the text so a wrong fingerprint stands out
// at a glance. It is an aid only; the text (and its words, #20) stays the
// thing that is compared.

const (
	artWidth  = 17
	artHeight = 9
	// artMaxTitle bounds the title written into the frame.
	artMaxTitle = artWidth - 2
)

// artSymbols are the visit counts' characters, as in OpenSSH.
const artSymbols = " .o+=*BOX@%&#/^"

// normalizeFingerprint drops separators and case so the same fingerprint
// typed or shown differently draws the same picture.
func normalizeFingerprint(fp string) string {
	var b strings.Builder
	for _, r := range fp {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// RandomArt draws fp as a 17x9 picture framed with title (for example
// "KÖK", "KOORDİNATÖR"). It returns artHeight+2 lines.
func RandomArt(title, fp string) []string {
	sum := sha256.Sum256([]byte("openscale/randomart/v1\x00" + normalizeFingerprint(fp)))
	var field [artWidth][artHeight]int
	x, y := artWidth/2, artHeight/2
	sx, sy := x, y
	// 16 bytes, 4 moves each: 64 steps like OpenSSH's MD5 pictures.
	for _, b := range sum[:16] {
		for i := 0; i < 4; i++ {
			if b&1 != 0 {
				x++
			} else {
				x--
			}
			if b&2 != 0 {
				y++
			} else {
				y--
			}
			x = min(max(x, 0), artWidth-1)
			y = min(max(y, 0), artHeight-1)
			if field[x][y] < len(artSymbols)-3 {
				field[x][y]++
			}
			b >>= 2
		}
	}
	lines := make([]string, 0, artHeight+2)
	lines = append(lines, artFrame(title))
	for row := 0; row < artHeight; row++ {
		var b strings.Builder
		b.WriteByte('|')
		for col := 0; col < artWidth; col++ {
			switch {
			case col == sx && row == sy:
				b.WriteByte('S')
			case col == x && row == y:
				b.WriteByte('E')
			default:
				b.WriteByte(artSymbols[field[col][row]])
			}
		}
		b.WriteByte('|')
		lines = append(lines, b.String())
	}
	lines = append(lines, "+"+strings.Repeat("-", artWidth)+"+")
	return lines
}

func artFrame(title string) string {
	t := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, title))
	if len(t) > artMaxTitle {
		t = t[:artMaxTitle]
	}
	if len(t) == 0 {
		return "+" + strings.Repeat("-", artWidth) + "+"
	}
	label := "[" + string(t) + "]"
	n := len([]rune(label))
	left := (artWidth - n) / 2
	return "+" + strings.Repeat("-", left) + label + strings.Repeat("-", artWidth-n-left) + "+"
}

// SideBySide joins pictures horizontally with two spaces between them.
func SideBySide(arts ...[]string) []string {
	rows := 0
	for _, a := range arts {
		rows = max(rows, len(a))
	}
	out := make([]string, rows)
	for r := range rows {
		parts := make([]string, 0, len(arts))
		for _, a := range arts {
			line := strings.Repeat(" ", artWidth+2)
			if r < len(a) {
				line = a[r]
			}
			parts = append(parts, line)
		}
		out[r] = strings.Join(parts, "  ")
	}
	return out
}

// DeviceFingerprint is the fingerprint the owner confirmed when the device
// enrolled (EnrollmentRequest.Fingerprint) for its current keys.
func DeviceFingerprint(d Device) string {
	r := EnrollmentRequest{DeviceID: d.ID, SigningKey: d.SigningKey, WireGuardKey: d.WireGuardKey}
	return r.Fingerprint()
}
