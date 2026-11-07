package webview

import (
	"strconv"
	"strings"
)

// themeMessage is the only message the panel may post to the native window:
// "theme:<light|dark>:#rrggbb". The colour is the page background, used for
// the title bar so the window chrome matches the panel theme. Anything else
// is ignored.
type themeMessage struct {
	dark bool
	r    uint8
	g    uint8
	b    uint8
}

const maxThemeMessageBytes = 32

// parseThemeMessage validates a message strictly; ok is false for anything
// that is not exactly the documented form.
func parseThemeMessage(s string) (themeMessage, bool) {
	var m themeMessage
	if len(s) > maxThemeMessageBytes || !strings.HasPrefix(s, "theme:") {
		return m, false
	}
	rest := s[len("theme:"):]
	mode, color, found := strings.Cut(rest, ":")
	if !found {
		return m, false
	}
	switch mode {
	case "dark":
		m.dark = true
	case "light":
	default:
		return m, false
	}
	if len(color) != 7 || color[0] != '#' {
		return m, false
	}
	for _, c := range color[1:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return m, false
		}
	}
	v, err := strconv.ParseUint(color[1:], 16, 32)
	if err != nil {
		return m, false
	}
	m.r, m.g, m.b = uint8(v>>16), uint8(v>>8), uint8(v)
	return m, true
}

// textOn returns a readable title text colour (near white or near black)
// for the given background, by relative luminance.
func (m themeMessage) textOn() (r, g, b uint8) {
	lum := 0.2126*float64(m.r) + 0.7152*float64(m.g) + 0.0722*float64(m.b)
	if lum < 140 {
		return 0xf4, 0xf4, 0xf5
	}
	return 0x18, 0x18, 0x1b
}
