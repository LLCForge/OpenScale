//go:build ((darwin && cgo) || (linux && cgo)) && !nowebview

package webview

/*
#include <stdint.h>
*/
import "C"

import "runtime/cgo"

// Decision codes shared with the Objective-C and GTK code.
const (
	decideBlock    = 0
	decideAllow    = 1
	decideExternal = 2
)

// openscaleWebviewDecide is called by the native code on the UI thread
// for every navigation and new-window request. mainFrame is 0 for a frame
// inside the page, which may never leave the origin.
//
//export openscaleWebviewDecide
func openscaleWebviewDecide(h C.uintptr_t, u *C.char, user, mainFrame C.int) C.int {
	cfg, ok := cgo.Handle(uintptr(h)).Value().(*config)
	if !ok || u == nil {
		return decideBlock
	}
	s := C.GoString(u)
	if mainFrame == 0 {
		if cfg.origin.check(s) == actionAllow {
			return decideAllow
		}
		cfg.emit("frame-block", s)
		return decideBlock
	}
	switch cfg.origin.navigate(s, user != 0) {
	case actionAllow:
		cfg.emit("nav-allow", s)
		return decideAllow
	case actionExternal:
		cfg.emit("nav-external", s)
		return decideExternal
	default:
		cfg.emit("nav-block", s)
		return decideBlock
	}
}
