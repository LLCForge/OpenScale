//go:build !windows && !linux && !(darwin && cgo)

package rdesk

// Screen capture and input injection exist only for Windows and Linux
// (X11). macOS needs ScreenCaptureKit or CGDisplayStream and CGEvent, which
// need cgo or a signed helper; that is a separate decision (ADR-0055).

// NewScreenCapturer reports ErrUnsupported on this system.
func NewScreenCapturer() (Capturer, error) { return nil, ErrUnsupported }

// NewInputInjector reports ErrUnsupported on this system.
func NewInputInjector() (Injector, error) { return nil, ErrUnsupported }

// NewSystemClipboard reports ErrUnsupported on this system.
func NewSystemClipboard() (Clipboard, error) { return nil, ErrUnsupported }
