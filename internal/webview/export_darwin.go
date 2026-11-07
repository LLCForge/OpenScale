//go:build darwin && cgo && !nowebview

package webview

/*
#include <stdint.h>
*/
import "C"

import "runtime/cgo"

// Callbacks of the macOS window (window_darwin.go). Both run on the main
// thread while the window's handle is valid: the native side cuts every
// link back to Go (detach) before the window reports that it closed, and
// Go deletes the handle only after that report.

// openscaleWebviewTheme checks a message the page posted and returns 1
// with the title bar colours when it is a valid theme message from the
// allowed origin.
//
//export openscaleWebviewTheme
func openscaleWebviewTheme(h C.uintptr_t, msg, pageURL *C.char, dark, r, g, b *C.int) C.int {
	cfg, ok := cgo.Handle(uintptr(h)).Value().(*config)
	if !ok || msg == nil || pageURL == nil || dark == nil || r == nil || g == nil || b == nil {
		return 0
	}
	if cfg.origin.check(C.GoString(pageURL)) != actionAllow {
		return 0
	}
	m, ok := parseThemeMessage(C.GoString(msg))
	if !ok {
		return 0
	}
	if m.dark {
		*dark = 1
	} else {
		*dark = 0
	}
	*r, *g, *b = C.int(m.r), C.int(m.g), C.int(m.b)
	return 1
}

// openscaleWebviewClosed reports that the hosted window closed (failed:
// it could not be created).
//
//export openscaleWebviewClosed
func openscaleWebviewClosed(h C.uintptr_t, failed C.int) {
	hostedClosed(uintptr(h), failed != 0)
}
