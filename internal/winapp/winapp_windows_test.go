//go:build windows

package winapp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestJoinArgsRoundTrip(t *testing.T) {
	cases := [][]string{
		nil,
		{"tray"},
		{"service", "install", "--dir", `C:\Program Files\OpenScale`},
		{"", "a b", `a"b`, `trailing\`, `C:\path with space\`, `\\server\share`, "çğışöü İ"},
		{`"quoted"`, `back\\"slash`, "tab\there"},
	}
	for _, args := range cases {
		line := joinArgs(args)
		got, err := windows.DecomposeCommandLine("prog.exe " + line)
		if err != nil {
			t.Fatalf("DecomposeCommandLine(%q): %v", line, err)
		}
		if !slices.Equal(got[1:], args) && !(len(args) == 0 && len(got) == 1) {
			t.Errorf("round trip %q -> %q -> %q", args, line, got[1:])
		}
	}
}

func TestServiceBinaryPath(t *testing.T) {
	got := serviceBinaryPath(`C:\Program Files\OpenScale\openscale.exe`)
	want := `"C:\Program Files\OpenScale\openscale.exe" service run`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDirs(t *testing.T) {
	for _, d := range []string{InstallDir(), DataDir()} {
		if !filepath.IsAbs(d) || !strings.HasSuffix(d, `\OpenScale`) {
			t.Errorf("unexpected dir %q", d)
		}
	}
	if _, err := validateProgramPath(filepath.Join(InstallDir(), installedExeName)); err != nil {
		t.Errorf("installed exe path rejected: %v", err)
	}
}

func TestStructSizes(t *testing.T) {
	var nid notifyIconData
	var hdr bitmapV5Header
	if hs := unsafe.Sizeof(hdr); hs != 124 {
		t.Errorf("BITMAPV5HEADER size = %d, want 124", hs)
	}
	want := map[string]uintptr{"amd64": 976, "arm64": 976, "386": 956, "arm": 956}
	if w, ok := want[runtime.GOARCH]; ok && unsafe.Sizeof(nid) != w {
		t.Errorf("NOTIFYICONDATAW size = %d, want %d", unsafe.Sizeof(nid), w)
	}
}

// Creating an HICON touches no system state (no tray, service or rule).
func TestIconFromPNG(t *testing.T) {
	src := image.NewNRGBA(image.Rect(0, 0, 48, 48))
	for y := range 48 {
		for x := range 48 {
			src.SetNRGBA(x, y, color.NRGBA{R: 31, G: 122, B: 114, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, src); err != nil {
		t.Fatal(err)
	}
	h, err := IconFromPNG(buf.Bytes(), 0)
	if err != nil {
		t.Fatalf("IconFromPNG: %v", err)
	}
	destroyIcon(h)

	h, err = createIconFromBGRA(renderDefaultIcon(32), 32)
	if err != nil {
		t.Fatalf("default icon: %v", err)
	}
	destroyIcon(h)

	if _, err := IconFromPNG([]byte("nope"), 16); err == nil {
		t.Error("invalid PNG accepted")
	}
	if _, err := createIconFromBGRA(make([]byte, 10), 32); err == nil {
		t.Error("short pixel buffer accepted")
	}
}

func TestOpenURLRejectsRemote(t *testing.T) {
	// Only rejected inputs are exercised: nothing is launched.
	for _, u := range []string{"https://example.com/", "file:///C:/Windows/notepad.exe", "http://localhost/"} {
		if err := OpenURL(u); err == nil {
			t.Errorf("OpenURL(%q) accepted", u)
		}
	}
}

func TestEnsureFirewallRulesRejectsBadInput(t *testing.T) {
	// Validation (or the elevation check) fails before netsh is run.
	if err := EnsureFirewallRules(`relative\openscale.exe`, "100.80.0.0/16"); err == nil {
		t.Error("relative path accepted")
	}
	if err := EnsureFirewallRules(`C:\Program Files\OpenScale\openscale.exe`, "0.0.0.0/0"); err == nil {
		t.Error("/0 accepted")
	}
}
