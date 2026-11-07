// Package rdesk is OpenScale's embedded remote desktop core (ADR-0055).
//
// The server listens only on the device's tunnel address. Like the embedded
// SSH server, it takes the client's identity from the tunnel source
// address: a WireGuard peer can only send from the addresses the signed
// network document gives it. Every session asks the caller's Authorize
// callback, which answers from the rdesk rules (watching and controlling
// are separate permissions, and unattended access is a third one). An
// attended session waits for the Consent callback, and every session is
// announced through the mandatory Indicator callback before any pixel
// leaves the device.
//
// The protocol is OpenScale's own framing over a TCP connection inside the
// tunnel; WireGuard already encrypts and authenticates it. Frames are
// lossless: the screen is split into 64x64 tiles, only changed tiles are
// sent, a uniform tile is sent as one color and the rest are compressed
// with compress/flate after a left-neighbour delta filter. Adaptive
// quality lowers the frame rate, then the resolution (box downscaling by
// 2 or 4), and raises the compression level when acknowledgements show
// the link cannot keep up. No external codec is used (ADR-0002).
//
// Screen capture and input injection are platform code: GDI BitBlt and
// SendInput on Windows, the X11 core protocol (GetImage) and the XTEST
// extension spoken in pure Go on Linux; other systems report
// ErrUnsupported.
package rdesk

import (
	"errors"
	"image"
)

// ProtocolVersion is the wire protocol version this package speaks.
const ProtocolVersion = 1

// Mode is what a session may do.
type Mode uint8

// Session modes.
const (
	// ModeView only receives the screen.
	ModeView Mode = 1
	// ModeControl also sends keyboard, mouse and clipboard input.
	ModeControl Mode = 2
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeView || m == ModeControl }

// String returns "view" or "control", the names the trust rules use.
func (m Mode) String() string {
	switch m {
	case ModeView:
		return "view"
	case ModeControl:
		return "control"
	}
	return "unknown"
}

// MonitorAll selects the whole virtual desktop (every monitor together).
const MonitorAll = -1

// Monitor is one display in virtual desktop coordinates.
type Monitor struct {
	Bounds  image.Rectangle
	Primary bool
}

var (
	// ErrUnsupported is returned when the platform cannot capture the
	// screen or inject input.
	ErrUnsupported = errors.New("rdesk: bu sistemde uzak masaüstü desteklenmiyor")
	// ErrScreenUnavailable is returned by a capturer while the screen
	// cannot be read (locked workstation, secure desktop, minimized or
	// disconnected remote session). Servers retry.
	ErrScreenUnavailable = errors.New("rdesk: ekran şu anda okunamıyor")
	// ErrInvalidListenAddr is returned for a missing or wildcard listen
	// address.
	ErrInvalidListenAddr = errors.New("rdesk: dinleme adresi belirli bir tünel adresi olmalı")
)

// Capturer reads the screen. Implementations need not be safe for
// concurrent use; the server uses one per session from one goroutine.
type Capturer interface {
	// Monitors returns the current displays; the first primary one is
	// the default view.
	Monitors() ([]Monitor, error)
	// Capture copies rectangle r of the virtual desktop into dst (which
	// it may reallocate when the size differs) and returns it. Pixels
	// are opaque RGBA.
	Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error)
	Close() error
}

// Injector sends input to the local desktop. Coordinates are virtual
// desktop pixels.
type Injector interface {
	// Pointer moves the pointer to (x, y) and sets the buttons (bit 0
	// left, bit 1 right, bit 2 middle) to the given state.
	Pointer(x, y int, buttons uint8) error
	// Wheel scrolls by whole notches; positive dy scrolls up, positive
	// dx scrolls right.
	Wheel(dx, dy int) error
	// Key presses or releases a key named by its USB HID usage
	// (keyboard page 0x07).
	Key(usage uint16, down bool) error
	// Text types the given text as characters.
	Text(s string) error
	Close() error
}

// Clipboard reads and writes the local text clipboard.
type Clipboard interface {
	// Sequence changes whenever the clipboard content changes.
	Sequence() (uint64, error)
	ReadText() (string, error)
	WriteText(s string) error
	Close() error
}

// Pointer button bits.
const (
	ButtonLeft   uint8 = 1 << 0
	ButtonRight  uint8 = 1 << 1
	ButtonMiddle uint8 = 1 << 2
)
