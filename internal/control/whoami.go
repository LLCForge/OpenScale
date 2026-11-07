package control

import (
	"bytes"
	"net/netip"
)

// Who-am-I echo (#77, ADR-0023 sızıntı testi). A device asks the
// coordinator's public WireGuard UDP port which source address it sees.
// The leak test sends it from an ordinary socket, which follows the exit
// node routes: through a working exit node the coordinator sees the exit
// node's address, and the device's own address means a leak. No third
// party is ever asked. The reply has exactly the request's size, so the
// echo cannot amplify traffic; neither message looks like WireGuard.
const (
	WhoAmIRequest = "OSWHOQ"
	WhoAmIReply   = "OSWHOR"
	WhoAmINonce   = 16
	// whoAmIAddr holds the address (16 bytes, IPv4 mapped) and the port.
	whoAmIAddr = 18
	WhoAmILen  = len(WhoAmIRequest) + WhoAmINonce + whoAmIAddr
)

// IsWhoAmI reports whether b is a who-am-I message with the given prefix.
func IsWhoAmI(b []byte, prefix string) bool {
	return len(b) == WhoAmILen && string(b[:len(prefix)]) == prefix
}

// NewWhoAmIRequest returns a request carrying nonce, padded to WhoAmILen.
func NewWhoAmIRequest(nonce [WhoAmINonce]byte) []byte {
	b := make([]byte, WhoAmILen)
	copy(b, WhoAmIRequest)
	copy(b[len(WhoAmIRequest):], nonce[:])
	return b
}

// WhoAmIAnswer returns the reply to req for a sender seen at from.
func WhoAmIAnswer(req []byte, from netip.AddrPort) []byte {
	b := make([]byte, WhoAmILen)
	copy(b, WhoAmIReply)
	off := len(WhoAmIReply)
	copy(b[off:off+WhoAmINonce], req[len(WhoAmIRequest):len(WhoAmIRequest)+WhoAmINonce])
	off += WhoAmINonce
	a := from.Addr().As16()
	copy(b[off:off+16], a[:])
	b[off+16], b[off+17] = byte(from.Port()>>8), byte(from.Port())
	return b
}

// ParseWhoAmIReply returns the address in a reply that carries nonce.
func ParseWhoAmIReply(b []byte, nonce [WhoAmINonce]byte) (netip.AddrPort, bool) {
	if !IsWhoAmI(b, WhoAmIReply) {
		return netip.AddrPort{}, false
	}
	off := len(WhoAmIReply)
	if !bytes.Equal(b[off:off+WhoAmINonce], nonce[:]) {
		return netip.AddrPort{}, false
	}
	off += WhoAmINonce
	addr := netip.AddrFrom16([16]byte(b[off : off+16])).Unmap()
	port := uint16(b[off+16])<<8 | uint16(b[off+17])
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, port), true
}
