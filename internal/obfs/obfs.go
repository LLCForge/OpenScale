// Package obfs disguises the device's WireGuard traffic on the wire
// (ADR-0186, #612, #615, #616) and carries the coordinator TCP transport
// behind a real TLS handshake (#613).
//
// WireGuard already encrypts and authenticates every datagram; nothing in
// this package adds secrecy or authenticity. Its only job is to make the
// datagrams harder to classify: a deep packet inspection box recognises
// WireGuard by the message type in the first byte, the three zero bytes
// after it and the fixed handshake sizes (148, 92 and 64 bytes).
//
// Datagram format ("QUIC-like", version 1):
//
//	byte 0       0x40 | random 6 bits   (QUIC short header form, fixed bit set)
//	bytes 1..12  random nonce            (looks like a connection ID and packet number)
//	rest         ChaCha20-Poly1305(key, nonce, ad = byte 0,
//	             plaintext = uint16 length | WireGuard datagram | zero padding)
//
// The key is derived from the network identifier in the signed document,
// so every member and the coordinator share it without a new document
// field. The coordinator (and anyone who has the document) can remove the
// disguise; that is accepted: the disguise targets classifiers, not
// parties that already see the document. Byte 0 of a disguised datagram
// always has bit 0x40 set, so it never looks like a plain WireGuard
// message (types 1 to 4): both kinds can arrive on the same socket.
package obfs

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Format constants.
const (
	headerLen = 1 + chacha20poly1305.NonceSize
	tagLen    = chacha20poly1305.Overhead
	lenField  = 2
	// Overhead is the most a disguised datagram adds before padding.
	Overhead = headerLen + tagLen + lenField
	// MaxPayload is the largest WireGuard datagram that can be wrapped.
	MaxPayload = 65535 - Overhead - 28
	// quicFixedBit is set in every disguised datagram.
	quicFixedBit = 0x40
	keyInfo      = "openscale obfs v1"
)

// ErrNotObfuscated means a datagram is not a valid disguised datagram for
// this key (a plain WireGuard message, noise or another network).
var ErrNotObfuscated = errors.New("obfs: datagram is not disguised with this key")

// Key is the shared disguise key.
type Key [chacha20poly1305.KeySize]byte

// DeriveKey derives the disguise key of a network from its identifier.
func DeriveKey(networkID string) (Key, error) {
	var k Key
	if networkID == "" {
		return k, errors.New("obfs: ağ kimliği boş")
	}
	r := hkdf.New(sha256.New, []byte(networkID), []byte("openscale-obfs-salt"), []byte(keyInfo))
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return Key{}, err
	}
	return k, nil
}

// Sealer wraps and unwraps datagrams with one key. It is safe for
// concurrent use.
type Sealer struct {
	aead cipher.AEAD
	// rand fills nonces and the random header bits; tests may replace it.
	rand io.Reader
	pad  Padding
}

// NewSealer returns a Sealer for key with the given padding.
func NewSealer(key Key, pad Padding) (*Sealer, error) {
	if err := pad.Validate(); err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: a, rand: rand.Reader, pad: pad}, nil
}

// Wrap appends the disguised form of payload to dst and returns it.
func (s *Sealer) Wrap(dst, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("obfs: datagram too large (%d bytes)", len(payload))
	}
	total := s.pad.size(len(payload) + Overhead)
	plainLen := total - headerLen - tagLen
	var hdr [headerLen]byte
	if _, err := io.ReadFull(s.rand, hdr[:]); err != nil {
		return nil, err
	}
	hdr[0] = quicFixedBit | hdr[0]&0x3f
	start := len(dst)
	dst = append(dst, hdr[:]...)
	body := len(dst)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	dst = append(dst, payload...)
	for len(dst)-body < plainLen {
		dst = append(dst, 0)
	}
	// Room for the tag, so Seal works in place.
	dst = slices.Grow(dst, tagLen)
	nonce := dst[start+1 : start+headerLen]
	ad := dst[start : start+1]
	plain := dst[body:]
	out := s.aead.Seal(plain[:0], nonce, plain, ad)
	return dst[:body+len(out)], nil
}

// Unwrap opens a disguised datagram in place and returns the WireGuard
// datagram inside (a sub-slice of pkt). Any failure returns
// ErrNotObfuscated.
func (s *Sealer) Unwrap(pkt []byte) ([]byte, error) {
	if len(pkt) < Overhead || pkt[0]&0xc0 != quicFixedBit {
		return nil, ErrNotObfuscated
	}
	nonce := pkt[1:headerLen]
	plain, err := s.aead.Open(pkt[headerLen:headerLen], nonce, pkt[headerLen:], pkt[:1])
	if err != nil || len(plain) < lenField {
		return nil, ErrNotObfuscated
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n > len(plain)-lenField {
		return nil, ErrNotObfuscated
	}
	return plain[lenField : lenField+n], nil
}

// LooksLikeWireGuard reports whether b has the shape of a plain WireGuard
// message: type 1 to 4 followed by three zero bytes.
func LooksLikeWireGuard(b []byte) bool {
	return len(b) >= 4 && b[0] >= 1 && b[0] <= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0
}
