// Package webview shows the OpenScale management panel in a native desktop
// window (ADR-0170) instead of a browser tab.
//
// The window embeds the system web engine without any added library:
//
//   - Windows: Microsoft Edge WebView2, bound in pure Go through
//     golang.org/x/sys/windows (no cgo). The runtime is found in the
//     registry and its EmbeddedBrowserWebView.dll is loaded directly.
//   - macOS: WKWebView through cgo and Objective-C (darwin && cgo).
//   - Linux: WebKitGTK (webkit2gtk-4.1, or 4.0 with the webkit2gtk_40
//     build tag) and GTK 3 through cgo (linux && cgo).
//
// Every platform applies the same rules: only the AllowedOrigin
// (http://127.0.0.1:<port>) is shown; an https link the user clicks opens
// in the system browser, anything else leaving the origin is blocked; new
// windows, downloads, permission requests (camera, microphone, location,
// notifications, clipboard read), HTTP authentication prompts and
// certificate errors are refused; developer tools, the context menu and
// form autofill or password saving are off.
//
// When the window cannot be shown (no cgo, no runtime, unsupported system)
// Open returns an error that matches ErrUnavailable and the caller falls
// back to a browser app window.
package webview

import (
	"context"
	"errors"
	"fmt"
)

// ErrUnavailable means no native window can be shown on this computer: the
// web engine is missing or too old, or this build has no binding for the
// system. The caller should fall back to the browser.
var ErrUnavailable = errors.New("yerel pencere kullanılamıyor")

// ErrUnsupported means this build has no window binding at all (another
// operating system, or macOS and Linux built without cgo). It matches
// ErrUnavailable with errors.Is.
var ErrUnsupported = fmt.Errorf("%w: bu derlemede yerel pencere desteği yok", ErrUnavailable)

// Options describe the window.
type Options struct {
	// URL is the first page; it must be inside AllowedOrigin.
	URL string
	// Title is the window title; empty means "OpenScale".
	Title string
	// Width and Height are the initial size in device-independent
	// pixels; zero means 1200x800.
	Width, Height int
	// MinWidth and MinHeight bound resizing; zero means 640x480.
	MinWidth, MinHeight int
	// IconICO is a Windows .ico file (optional).
	IconICO []byte
	// IconPNG is a PNG image used on macOS and Linux (optional).
	IconPNG []byte
	// AllowedOrigin is the only origin the window shows, written as
	// http://127.0.0.1:<port> (or http://[::1]:<port>). Empty means the
	// origin of URL, which must then itself be such a loopback origin.
	AllowedOrigin string
	// DataDir overrides the per-user web engine data folder. Empty uses
	// the platform default (Windows: %LOCALAPPDATA%\OpenScale\WebView2).
	DataDir string
	// ForwardPath, when set, lets another program of this user ask the
	// open window to load an address of AllowedOrigin whose path is
	// exactly ForwardPath (Windows: ForwardToOpenWindow). The tray uses it
	// to hand a fresh sign-in ticket to the window it brings to the front.
	ForwardPath string
}

// Size defaults and limits, in device-independent pixels.
const (
	DefaultWidth     = 1200
	DefaultHeight    = 800
	DefaultMinWidth  = 640
	DefaultMinHeight = 480
	minDimension     = 200
	maxDimension     = 16384
	maxTitleRunes    = 200
	maxIconBytes     = 1 << 20
	maxURLBytes      = 8 << 10
	defaultTitle     = "OpenScale"
)

// Open shows the window and blocks until the user closes it or ctx is
// done. It returns nil when the user closed the window, ctx.Err() when
// ctx ended it, an error matching ErrUnavailable when no window could be
// created, and another error when the options are invalid.
//
// On macOS Open must run on the main goroutine of the program (the
// package locks it to the main thread in init); on Windows and Linux any
// goroutine may call it.
func Open(ctx context.Context, opts Options) error {
	cfg, err := opts.normalize()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return open(ctx, cfg)
}

// config is validated Options.
type config struct {
	url       string
	title     string
	width     int
	height    int
	minWidth  int
	minHeight int
	iconICO   []byte
	iconPNG   []byte
	origin    origin
	dataDir   string
	// forwardPath: see Options.ForwardPath ("" refuses every request).
	forwardPath string

	// hidden and hooks are set only by tests.
	hidden bool
	hooks  *testHooks
}

// testHooks observe the window in tests. Every call happens on the UI
// thread of the window.
type testHooks struct {
	// ready is called once the page is loading; navigate loads a URL
	// through the same checks as a link the user did not click.
	ready func(navigate func(string))
	// event reports what the window did: kind is one of "nav-allow",
	// "nav-block", "nav-external", "frame-block", "newwindow-block",
	// "newwindow-external", "permission-deny", "download-cancel",
	// "auth-cancel", "resource-block", "nav-completed", "nav-failed".
	event func(kind, uri string)
}

func (c *config) emit(kind, uri string) {
	if c.hooks != nil && c.hooks.event != nil {
		c.hooks.event(kind, uri)
	}
}

// normalize validates opts and fills defaults.
func (o Options) normalize() (config, error) {
	var c config
	org, err := resolveOrigin(o.AllowedOrigin, o.URL)
	if err != nil {
		return c, err
	}
	if len(o.URL) > maxURLBytes {
		return c, errors.New("webview: adres çok uzun")
	}
	if org.check(o.URL) != actionAllow || o.URL == "about:blank" {
		return c, fmt.Errorf("webview: başlangıç adresi izinli kaynağın (%s) dışında", org)
	}
	title, err := cleanTitle(o.Title)
	if err != nil {
		return c, err
	}
	c = config{
		url:       o.URL,
		title:     title,
		width:     orDefault(o.Width, DefaultWidth),
		height:    orDefault(o.Height, DefaultHeight),
		minWidth:  orDefault(o.MinWidth, DefaultMinWidth),
		minHeight: orDefault(o.MinHeight, DefaultMinHeight),
		origin:    org,
		dataDir:   o.DataDir,
	}
	for _, d := range []struct {
		name string
		v    int
	}{{"Width", c.width}, {"Height", c.height}, {"MinWidth", c.minWidth}, {"MinHeight", c.minHeight}} {
		if d.v < minDimension || d.v > maxDimension {
			return config{}, fmt.Errorf("webview: %s %d, %d ile %d arasında olmalı", d.name, d.v, minDimension, maxDimension)
		}
	}
	if c.width < c.minWidth || c.height < c.minHeight {
		return config{}, errors.New("webview: başlangıç boyutu en küçük boyuttan küçük")
	}
	if len(o.IconICO) > 0 {
		if len(o.IconICO) > maxIconBytes {
			return config{}, errors.New("webview: ICO simgesi çok büyük")
		}
		if _, err := parseICO(o.IconICO); err != nil {
			return config{}, err
		}
		c.iconICO = o.IconICO
	}
	if len(o.IconPNG) > 0 {
		if len(o.IconPNG) > maxIconBytes {
			return config{}, errors.New("webview: PNG simgesi çok büyük")
		}
		if !isPNG(o.IconPNG) {
			return config{}, errors.New("webview: IconPNG bir PNG dosyası değil")
		}
		c.iconPNG = o.IconPNG
	}
	if c.dataDir != "" {
		if err := checkDataDir(c.dataDir); err != nil {
			return config{}, err
		}
	}
	if o.ForwardPath != "" {
		if err := validForwardPath(o.ForwardPath); err != nil {
			return config{}, err
		}
		c.forwardPath = o.ForwardPath
	}
	return c, nil
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// cleanTitle rejects control characters and bounds the length.
func cleanTitle(t string) (string, error) {
	if t == "" {
		return defaultTitle, nil
	}
	n := 0
	for _, r := range t {
		n++
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0xfffd {
			return "", errors.New("webview: başlıkta denetim karakteri veya geçersiz UTF-8 var")
		}
	}
	if n > maxTitleRunes {
		return "", fmt.Errorf("webview: başlık en fazla %d karakter olabilir", maxTitleRunes)
	}
	return t, nil
}

// pngSignature starts every PNG file.
var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

func isPNG(b []byte) bool {
	return len(b) > len(pngSignature)+8 && string(b[:len(pngSignature)]) == string(pngSignature)
}
