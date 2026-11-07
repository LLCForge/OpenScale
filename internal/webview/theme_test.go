package webview

import "testing"

func TestParseThemeMessage(t *testing.T) {
	good := []struct {
		in      string
		dark    bool
		r, g, b uint8
	}{
		{"theme:dark:#18181b", true, 0x18, 0x18, 0x1b},
		{"theme:light:#fafafa", false, 0xfa, 0xfa, 0xfa},
		{"theme:light:#000000", false, 0, 0, 0},
	}
	for _, c := range good {
		m, ok := parseThemeMessage(c.in)
		if !ok || m.dark != c.dark || m.r != c.r || m.g != c.g || m.b != c.b {
			t.Fatalf("%q: got %+v ok=%v", c.in, m, ok)
		}
	}
	bad := []string{
		"", "theme:", "theme:dark", "theme:dark:", "theme:dim:#18181b",
		"theme:dark:#18181", "theme:dark:#18181bb", "theme:dark:18181b",
		"theme:dark:#18181B", "theme:dark:#gg0000", "Theme:dark:#18181b",
		"theme:dark:#18181b:x", "theme:dark:#18181b\x00", "x theme:dark:#18181b",
		"theme:dark:#18181b                    ",
	}
	for _, s := range bad {
		if _, ok := parseThemeMessage(s); ok {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestThemeTextContrast(t *testing.T) {
	if r, _, _ := (themeMessage{r: 0x18, g: 0x18, b: 0x1b}).textOn(); r < 0x80 {
		t.Fatal("dark background must get light text")
	}
	if r, _, _ := (themeMessage{r: 0xfa, g: 0xfa, b: 0xfa}).textOn(); r > 0x80 {
		t.Fatal("light background must get dark text")
	}
}
