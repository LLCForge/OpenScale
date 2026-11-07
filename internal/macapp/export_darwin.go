//go:build darwin && cgo

package macapp

/*
#include <stdint.h>
#include <string.h>
*/
import "C"

import "unsafe"

// These run on the main thread inside [NSApp run]. They never block: user
// callbacks get their own goroutine, answers go to buffered channels.

//export openscaleMacappClicked
func openscaleMacappClicked(id C.int) {
	if cfg := handlers.Load(); cfg != nil && cfg.OnClick != nil {
		go cfg.OnClick(int(id))
	}
}

//export openscaleMacappReopen
func openscaleMacappReopen(unused C.int) {
	if cfg := handlers.Load(); cfg != nil && cfg.OnReopen != nil {
		go cfg.OnReopen()
	}
}

//export openscaleMacappReady
func openscaleMacappReady(unused C.int) {
	if cfg := handlers.Load(); cfg != nil && cfg.OnReady != nil {
		go cfg.OnReady()
	}
}

// openscaleMacappReply delivers a dialog answer. text, when not NULL, is a
// C buffer the native side wipes and frees right after this returns, so
// it is copied here.
//
//export openscaleMacappReply
func openscaleMacappReply(req C.uint64_t, ok C.int, text *C.char) {
	var r reply
	r.ok = ok != 0
	if text != nil {
		n := C.strlen(text)
		if n > 0 && n <= 4096 {
			r.text = C.GoBytes(unsafe.Pointer(text), C.int(n))
		} else {
			r.text = []byte{}
		}
	}
	deliver(uint64(req), r)
}
