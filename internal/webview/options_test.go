package webview

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// testPNG is a minimal PNG signature plus header bytes; the options check
// only the signature.
var testPNG = append(append([]byte{}, pngSignature...), 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 16)

// makeICO builds a .ico file with one PNG image per size.
func makeICO(sizes ...int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	off := 6 + 16*len(sizes)
	for _, s := range sizes {
		w := byte(s)
		if s >= 256 {
			w = 0
		}
		b.Write([]byte{w, w, 0, 0})
		_ = binary.Write(&b, binary.LittleEndian, [2]uint16{1, 32})
		_ = binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(testPNG)), uint32(off)})
		off += len(testPNG)
	}
	for range sizes {
		b.Write(testPNG)
	}
	return b.Bytes()
}

func TestOptionsDefaults(t *testing.T) {
	c, err := Options{URL: "http://127.0.0.1:8080/login?t=abc"}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if c.title != "OpenScale" || c.width != DefaultWidth || c.height != DefaultHeight ||
		c.minWidth != DefaultMinWidth || c.minHeight != DefaultMinHeight {
		t.Errorf("varsayılanlar yanlış: %+v", c)
	}
	if c.origin.String() != "http://127.0.0.1:8080" {
		t.Errorf("kaynak URL'den türetilmedi: %v", c.origin)
	}
}

func TestOptionsValidation(t *testing.T) {
	abs, _ := filepath.Abs("veri")
	ok := Options{URL: "http://127.0.0.1:8080/", AllowedOrigin: "http://127.0.0.1:8080"}
	for _, tc := range []struct {
		name string
		mod  func(*Options)
		ok   bool
	}{
		{"geçerli", func(*Options) {}, true},
		{"simgeler", func(o *Options) { o.IconICO = makeICO(16, 32, 256); o.IconPNG = testPNG }, true},
		{"boyutlar", func(o *Options) { o.Width, o.Height, o.MinWidth, o.MinHeight = 900, 700, 800, 600 }, true},
		{"veri klasörü", func(o *Options) { o.DataDir = abs }, true},
		{"başlık", func(o *Options) { o.Title = "OpenScale – Yönetim" }, true},
		{"kaynak dışı adres", func(o *Options) { o.URL = "http://127.0.0.1:9090/" }, false},
		{"https adres", func(o *Options) { o.URL = "https://127.0.0.1:8080/" }, false},
		{"about:blank başlangıç", func(o *Options) { o.URL = "about:blank" }, false},
		{"localhost kaynağı", func(o *Options) { o.AllowedOrigin = "http://localhost:8080"; o.URL = "http://localhost:8080/" }, false},
		{"dış kaynak", func(o *Options) { o.AllowedOrigin = ""; o.URL = "http://192.168.1.2:8080/" }, false},
		{"boş adres", func(o *Options) { o.URL = "" }, false},
		{"uzun adres", func(o *Options) { o.URL = "http://127.0.0.1:8080/" + strings.Repeat("a", maxURLBytes) }, false},
		{"başlıkta satır sonu", func(o *Options) { o.Title = "a\nb" }, false},
		{"başlıkta bozuk UTF-8", func(o *Options) { o.Title = "a\xffb" }, false},
		{"uzun başlık", func(o *Options) { o.Title = strings.Repeat("ş", maxTitleRunes+1) }, false},
		{"küçük genişlik", func(o *Options) { o.Width = 50 }, false},
		{"negatif yükseklik", func(o *Options) { o.Height = -1 }, false},
		{"dev genişlik", func(o *Options) { o.Width = maxDimension + 1 }, false},
		{"en küçükten küçük", func(o *Options) { o.Width, o.MinWidth = 700, 800 }, false},
		{"bozuk ICO", func(o *Options) { o.IconICO = []byte("not an icon") }, false},
		{"PNG değil", func(o *Options) { o.IconPNG = makeICO(32) }, false},
		{"dev simge", func(o *Options) { o.IconPNG = append(append([]byte{}, testPNG...), make([]byte, maxIconBytes)...) }, false},
		{"göreli veri klasörü", func(o *Options) { o.DataDir = "veri" }, false},
		{"temiz olmayan veri klasörü", func(o *Options) {
			o.DataDir = abs + string(filepath.Separator) + ".." + string(filepath.Separator) + "x"
		}, false},
	} {
		o := ok
		tc.mod(&o)
		_, err := o.normalize()
		if (err == nil) != tc.ok {
			t.Errorf("%s: hata = %v, başarı bekleniyor = %v", tc.name, err, tc.ok)
		}
	}
}

func TestOpenRejectsBeforeWindow(t *testing.T) {
	// Invalid options and a finished context return before any window
	// or runtime is touched, on every system.
	if err := Open(context.Background(), Options{URL: "https://example.com/"}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("geçersiz seçenek hatası bekleniyordu: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Open(ctx, Options{URL: "http://127.0.0.1:8080/"}); !errors.Is(err, context.Canceled) {
		t.Errorf("Open(iptal) = %v", err)
	}
}

func TestErrUnsupportedIsUnavailable(t *testing.T) {
	if !errors.Is(ErrUnsupported, ErrUnavailable) {
		t.Error("ErrUnsupported, ErrUnavailable ile eşleşmeli")
	}
}

func TestParseICO(t *testing.T) {
	images, err := parseICO(makeICO(16, 32, 48, 256))
	if err != nil || len(images) != 4 || images[3].width != 256 {
		t.Fatalf("parseICO = %v, %v", images, err)
	}
	for _, tc := range []struct{ size, want int }{{16, 16}, {20, 32}, {32, 32}, {33, 48}, {300, 256}} {
		im, ok := pickICO(images, tc.size)
		if !ok || im.width != tc.want {
			t.Errorf("pickICO(%d) = %d, %d bekleniyordu", tc.size, im.width, tc.want)
		}
	}
	good := makeICO(32)
	for name, b := range map[string][]byte{
		"boş":           nil,
		"kısa":          good[:5],
		"tür 2 (imleç)": append([]byte{0, 0, 2, 0}, good[4:]...),
		"sıfır görüntü": {0, 0, 1, 0, 0, 0},
		"kesik dizin":   good[:6+8],
		"taşan veri":    good[:len(good)-1],
		"ofset dizinde": func() []byte {
			b := append([]byte{}, good...)
			binary.LittleEndian.PutUint32(b[6+12:], 2)
			return b
		}(),
		"bilinmeyen biçim": func() []byte {
			b := append([]byte{}, good...)
			copy(b[22:], "GIF89a")
			return b
		}(),
	} {
		if _, err := parseICO(b); err == nil {
			t.Errorf("%s: hata bekleniyordu", name)
		}
	}
}
