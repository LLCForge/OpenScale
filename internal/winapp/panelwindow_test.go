package winapp

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/webview"
)

func TestPanelWindowOptions(t *testing.T) {
	o, err := PanelWindowOptions("http://127.0.0.1:41000/login#t=abc", "")
	if err != nil {
		t.Fatal(err)
	}
	if o.URL != "http://127.0.0.1:41000/login#t=abc" || o.Title == "" {
		t.Fatalf("options = %+v", o)
	}
	img, err := png.Decode(bytes.NewReader(o.IconPNG))
	if err != nil || img.Bounds().Dx() != 256 {
		t.Fatalf("icon png: %v", err)
	}
	// A real .ico with several sizes, so the title bar gets a small image
	// drawn for its size instead of a scaled-down 256 px one.
	if len(o.IconICO) < 6 || o.IconICO[2] != 1 || int(o.IconICO[4])|int(o.IconICO[5])<<8 < 3 {
		t.Fatal("ico container wrong")
	}
	for _, bad := range []string{"https://example.com/", "http://10.0.0.1:80/", "javascript:alert(1)"} {
		if _, err := PanelWindowOptions(bad, ""); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if o, _ := PanelWindowOptions("http://127.0.0.1:1/", "Ağ Yardımcısı"); o.Title != "Ağ Yardımcısı" {
		t.Fatal(o.Title)
	}
	// A title that is not a valid neutral name is not used.
	if o, _ := PanelWindowOptions("http://127.0.0.1:1/", "OpenScale VPN <b>"); o.Title == "OpenScale VPN <b>" {
		t.Fatal("unchecked title used")
	}
}

func TestOpenPanelWindowDisabled(t *testing.T) {
	t.Setenv(PanelWindowEnv, "browser")
	if err := OpenPanelWindow(context.Background(), "http://127.0.0.1:1/", ""); !errors.Is(err, webview.ErrUnavailable) {
		t.Fatalf("disabled window = %v", err)
	}
}

func TestDiscreetSetting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	d, err := LoadDiscreet(dir)
	if err != nil || d.Enabled {
		t.Fatalf("default = %+v, %v", d, err)
	}
	if err := SaveDiscreet(dir, Discreet{Enabled: true, Name: "Yazıcı Yardımcısı"}); err != nil {
		t.Fatal(err)
	}
	d, err = LoadDiscreet(dir)
	if err != nil || !d.Enabled || d.NeutralName() != "Yazıcı Yardımcısı" {
		t.Fatalf("loaded = %+v, %v", d, err)
	}
	for _, bad := range []string{"", " x", "OpenScale Aracı", "my vpn", "a/b", strings.Repeat("a", 41), "Tünel"} {
		if err := SaveDiscreet(dir, Discreet{Enabled: true, Name: bad}); bad != "" && err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	got := d.Neutralize("OpenScale: bağlı (VPN, WireGuard tüneli)")
	for _, w := range revealingWords {
		if strings.Contains(strings.ToLower(got), w) {
			t.Fatalf("%q still reveals %q", got, w)
		}
	}
	if (Discreet{}).Neutralize("OpenScale") != "OpenScale" {
		t.Fatal("off mode changed text")
	}
	disp, desc := d.ServiceIdentity()
	if disp != "Yazıcı Yardımcısı" || desc != DefaultNeutralDescription {
		t.Fatal(disp, desc)
	}
	if disp, _ := (Discreet{}).ServiceIdentity(); disp != ServiceDisplayName {
		t.Fatal(disp)
	}
}

func TestIsOpenScaleProgram(t *testing.T) {
	for p, want := range map[string]bool{
		filepath.Join("a", "OpenScale.EXE"):     true,
		filepath.Join("a", "openscale"):         true,
		filepath.Join("a", "winapp.test"):       false,
		filepath.Join("a", "openscale.exe.bak"): false,
	} {
		if isOpenScaleProgram(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}

// The window shows the logo pack's mark, not a drawn stand-in.
func TestPanelWindowUsesLogoPackIcon(t *testing.T) {
	o, err := PanelWindowOptions("http://127.0.0.1:8484/", "OpenScale")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.IconICO, appIconICO) || !bytes.Equal(o.IconPNG, appIconPNG) {
		t.Fatal("panel window does not use the embedded logo icon")
	}
	pack, err := os.ReadFile(filepath.Join("..", "..", "logos", "app-icon.ico"))
	if err != nil {
		t.Skip("logo pack not in this checkout")
	}
	if !bytes.Equal(pack, appIconICO) {
		t.Fatal("assets/app-icon.ico differs from logos/app-icon.ico; copy it again")
	}
}
