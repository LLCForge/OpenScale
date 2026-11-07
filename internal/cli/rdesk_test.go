package cli

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/openscale/openscale/internal/rdesk"
)

func TestRemoteDesktopUsage(t *testing.T) {
	h := newHarness(t)
	h.run(exitUsage, "rdesk")
	h.run(exitUsage, "rdesk", "laptop")
	h.run(exitUsage, "rdesk", "laptop", "--snapshot", "ekran.jpg")
	h.run(exitUsage, "rdesk", "laptop", "--snapshot", "ekran.png", "--monitor", "99")
	h.run(exitUsage, "rdesk", "laptop", "--snapshot", "ekran.png", "--timeout", "1s")
	existing := filepath.Join(t.TempDir(), "var.png")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "rdesk", "laptop", "--snapshot", existing)
}

func TestParseMonitorFlag(t *testing.T) {
	cases := map[string]int{"primary": rdesk.MonitorPrimary, "": rdesk.MonitorPrimary, "all": rdesk.MonitorAll, "Hepsi": rdesk.MonitorAll, "0": 0, "3": 3}
	for in, want := range cases {
		if got, err := parseMonitorFlag(in); err != nil || got != want {
			t.Errorf("%q -> %d %v", in, got, err)
		}
	}
	for _, in := range []string{"-1", "16", "ikinci"} {
		if _, err := parseMonitorFlag(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestWritePNGExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ekran.png")
	img := image.NewRGBA(image.Rect(0, 0, 3, 2))
	img.Pix[0], img.Pix[3] = 200, 255
	if err := writePNGExclusive(path, img); err != nil {
		t.Fatal(err)
	}
	if err := writePNGExclusive(path, img); err == nil {
		t.Fatal("an existing file must not be overwritten")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := png.Decode(f)
	if err != nil || got.Bounds() != img.Rect {
		t.Fatalf("decode: %v", err)
	}
	if r, _, _, _ := got.At(0, 0).RGBA(); r>>8 != 200 {
		t.Fatal("pixel")
	}
}
