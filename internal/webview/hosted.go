package webview

import "sync/atomic"

// hostedRunLoop: on macOS another part of this program (the menu bar
// app, internal/macapp) owns the AppKit run loop. Open then shows the
// window inside that run loop from any goroutine, closing the window
// does not end the program, and a second "open the panel" is forwarded
// to the open window (ADR-0227). Other systems ignore it.
var hostedRunLoop atomic.Bool

// UseAppRunLoop switches Open to the hosted mode described above. Call
// it before the menu bar app starts its run loop.
func UseAppRunLoop() { hostedRunLoop.Store(true) }
