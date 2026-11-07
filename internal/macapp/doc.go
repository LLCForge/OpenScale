// Package macapp is the macOS menu bar of the OpenScale app (ADR-0227):
// an NSStatusItem with a template icon, its menu, alerts, a passphrase
// prompt, notifications and the clipboard, through cgo and AppKit.
//
// The package exists only in darwin builds with cgo; desktop falls back
// to the browser when it is missing (CGO_ENABLED=0).
//
// Threads. AppKit may be used only on the main thread. The package locks
// the main goroutine to the main thread in init, Run must be called from
// the main goroutine and runs [NSApp run] there until Quit. Every other
// function may be called from any goroutine: it copies its arguments
// into Objective-C objects at once and queues a block on the main run
// loop (CFRunLoopPerformBlock in the common modes, so the block also runs
// while a menu is open or an alert is up). Functions that wait for an
// answer (Confirm, AskSecret) must not be called on the main thread.
//
// Callbacks. Menu clicks and the reopen event reach Go through //export
// functions on the main thread; they start a new goroutine and return at
// once, so the run loop is never blocked by Go work. Dialog answers come
// back the same way and are delivered to a buffered channel.
//
// Memory. The Objective-C code is compiled with ARC (-fobjc-arc): no
// manual retain, release or autorelease. Strings and bytes from Go are
// copied into NSString/NSData before the C function returns. The only C
// buffer handed to Go (a typed passphrase) is allocated with malloc,
// copied by Go, then wiped with memset_s and freed by the C side.
package macapp
