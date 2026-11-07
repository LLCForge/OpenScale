package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Post-quantum PSK exchange (ADR-0033): binary datagrams between two
// devices, inside their own WireGuard tunnel, from PQPort to PQPort. They
// never reach the OS; the format lives in internal/node.
const PQPort = 4043

// TCP fallback transport (ADR-0032). When UDP to the coordinator is
// blocked, a device carries its WireGuard datagrams to the coordinator over
// one TCP connection. WireGuard already encrypts and authenticates every
// datagram, so the stream adds no cryptography (no TLS, R-20).
//
// Stream: each side first sends TCPMagic, then frames: a 2-byte big-endian
// length followed by exactly one WireGuard message. Every frame must look
// like a WireGuard message (ValidWireGuardMessage) and be at most
// TCPMaxFrame bytes; anything else closes the connection.
const (
	// TCPMagic opens the stream in both directions.
	TCPMagic = "OSWGTCP1"
	// DefaultTCPPort is the coordinator's default TCP fallback port: 443 is
	// open on almost every network that blocks UDP.
	DefaultTCPPort = 443
	// TCPMaxFrame bounds one frame. The largest legitimate datagram on the
	// coordinator leg is a relayed packet (RelayMaxPayload plus IP, UDP and
	// WireGuard overhead).
	TCPMaxFrame = 4096
	tcpFrameHdr = 2
)

// UDP echo (ADR-0032): while a device uses TCP it asks, from its WireGuard
// socket, whether UDP to the coordinator works again. The coordinator
// answers a request with a reply of the same size carrying the same nonce,
// so the echo cannot amplify traffic. Neither message is a WireGuard
// message (those start with a type byte 1-4 followed by three zeros).
const (
	UDPEchoRequest = "OSUDPQ"
	UDPEchoReply   = "OSUDPR"
	UDPEchoNonce   = 16
	UDPEchoLen     = len(UDPEchoRequest) + UDPEchoNonce
)

// WireGuard message types and sizes (whitepaper section 5.4).
const (
	wgInitiation    = 1
	wgResponse      = 2
	wgCookieReply   = 3
	wgTransport     = 4
	wgInitiationLen = 148
	wgResponseLen   = 92
	wgCookieLen     = 64
	wgTransportMin  = 32
)

// ValidWireGuardMessage reports whether b has the shape of a WireGuard
// message: a known type with three zero bytes and the size that type has.
// It does not check any cryptography; WireGuard does that.
func ValidWireGuardMessage(b []byte) bool {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	switch b[0] {
	case wgInitiation:
		return len(b) == wgInitiationLen
	case wgResponse:
		return len(b) == wgResponseLen
	case wgCookieReply:
		return len(b) == wgCookieLen
	case wgTransport:
		// Padding is not always a multiple of 16: WireGuard pads up to the
		// interface MTU at most.
		return len(b) >= wgTransportMin && len(b) <= TCPMaxFrame
	}
	return false
}

// IsWireGuardInitiation reports whether b is a handshake initiation.
func IsWireGuardInitiation(b []byte) bool {
	return len(b) == wgInitiationLen && b[0] == wgInitiation && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// ErrBadFrame is returned for a frame that is too large, empty or not a
// WireGuard message.
var ErrBadFrame = errors.New("invalid TCP transport frame")

// AppendFrame appends msg as one frame to dst.
func AppendFrame(dst, msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > TCPMaxFrame {
		return dst, ErrBadFrame
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(msg))) //nolint:gosec // bounded by TCPMaxFrame
	return append(dst, msg...), nil
}

// ReadFrame reads one frame into buf (at least TCPMaxFrame bytes) and
// returns the message. It never allocates and never reads past the frame.
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	if len(buf) < TCPMaxFrame {
		return nil, errors.New("frame buffer too small")
	}
	var hdr [tcpFrameHdr]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > TCPMaxFrame {
		return nil, ErrBadFrame
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if !ValidWireGuardMessage(buf[:n]) {
		return nil, ErrBadFrame
	}
	return buf[:n], nil
}

// ReadMagic reads and checks the stream preamble.
func ReadMagic(r io.Reader) error {
	var got [len(TCPMagic)]byte
	if _, err := io.ReadFull(r, got[:]); err != nil {
		return err
	}
	if !bytes.Equal(got[:], []byte(TCPMagic)) {
		return fmt.Errorf("peer is not an OpenScale TCP transport")
	}
	return nil
}

// IsUDPEcho reports whether b is a UDP echo message with the given prefix.
func IsUDPEcho(b []byte, prefix string) bool {
	return len(b) == UDPEchoLen && string(b[:len(prefix)]) == prefix
}
