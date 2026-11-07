package p2psend

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"golang.org/x/crypto/curve25519"
)

// Onion routing through trusted member devices (ADR-0204).
//
// The sender wraps the route in layers, innermost first. Each layer is
// sealed to one relay's WireGuard key with a fresh ephemeral key and
// tells that relay only where to connect next and what to send there
// first. A relay peels its layer, dials the next hop, forwards the inner
// bytes and then copies the rest of the stream both ways. The rest is the
// end-to-end encrypted file stream, which no relay can read.
//
// With two or more relays no single relay knows both the sender and the
// receiver: the first sees the sender and the second relay, the last sees
// the previous relay and the receiver. A single relay would see both, so
// onion mode requires at least MinHops relays.
//
//	layer = preamble('R') | ephemeral (32) | u16 length | sealed
//	sealed plaintext = u8 len | next "addr:port" | inner bytes

// Hop limits.
const (
	MinHops = 2
	MaxHops = 3
	// maxLayer bounds a sealed layer; three nested layers fit easily.
	maxLayer = 2048
)

// Hop is one relay on an onion route.
type Hop struct {
	Key  Key
	Addr netip.AddrPort
}

// ErrRoute is returned for an unusable onion route.
var ErrRoute = errors.New("geçersiz soğan yönlendirme yolu")

func onionKey(shared []byte, e, relay Key) (*[32]byte, error) {
	salt := append(append(make([]byte, 0, 64), e[:]...), relay[:]...)
	out, err := hkdf.Key(sha256.New, shared, salt, infoOnion, 32)
	if err != nil {
		return nil, err
	}
	var k [32]byte
	copy(k[:], out)
	clear(out)
	return &k, nil
}

// sealLayer seals (next, inner) to relay.
func sealLayer(relay Key, next netip.AddrPort, inner []byte, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	nextText := next.String()
	if !next.IsValid() || len(nextText) > 255 {
		return nil, ErrRoute
	}
	var ePriv [32]byte
	defer clear(ePriv[:])
	if _, err := io.ReadFull(random, ePriv[:]); err != nil {
		return nil, err
	}
	ePubB, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var e Key
	copy(e[:], ePubB)
	shared, err := x25519(ePriv[:], relay)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	k, err := onionKey(shared, e, relay)
	if err != nil {
		return nil, err
	}
	defer clear(k[:])
	plain := make([]byte, 0, 1+len(nextText)+len(inner))
	plain = append(plain, byte(len(nextText)))
	plain = append(plain, nextText...)
	plain = append(plain, inner...)
	ct, err := seal(k, domainOnion, 0, plain, []byte(magic))
	if err != nil {
		return nil, err
	}
	if len(ct) > maxLayer {
		return nil, fmt.Errorf("%w: katman çok büyük", ErrRoute)
	}
	var b bytes.Buffer
	writePreamble(&b, kindRelay)
	b.Write(e[:])
	_ = binary.Write(&b, binary.BigEndian, uint16(len(ct)))
	b.Write(ct)
	return b.Bytes(), nil
}

// BuildOnion returns the bytes to send to the first relay of hops so the
// stream reaches dest. The route must have MinHops to MaxHops relays, no
// repeated relay and must not include the destination.
func BuildOnion(hops []Hop, dest netip.AddrPort, destKey Key, random io.Reader) ([]byte, error) {
	if len(hops) < MinHops || len(hops) > MaxHops {
		return nil, fmt.Errorf("%w: %d ile %d arası ara cihaz gerekir", ErrRoute, MinHops, MaxHops)
	}
	seen := map[Key]bool{destKey: true}
	for _, h := range hops {
		if h.Key.IsZero() || seen[h.Key] || !h.Addr.IsValid() {
			return nil, fmt.Errorf("%w: ara cihazlar farklı olmalı ve alıcıyı içermemeli", ErrRoute)
		}
		seen[h.Key] = true
	}
	var inner []byte
	next := dest
	for i := len(hops) - 1; i >= 0; i-- {
		layer, err := sealLayer(hops[i].Key, next, inner, random)
		if err != nil {
			return nil, err
		}
		inner, next = layer, hops[i].Addr
	}
	return inner, nil
}

// peeled is a relay's view of its layer.
type peeled struct {
	ephemeral Key
	next      netip.AddrPort
	inner     []byte
}

// readLayer reads the rest of an 'R' layer after the preamble.
func readLayer(r io.Reader) (Key, []byte, error) {
	var e Key
	if _, err := io.ReadFull(r, e[:]); err != nil {
		return e, nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return e, nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 16+2 || n > maxLayer {
		return e, nil, ErrProtocol
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(r, ct); err != nil {
		return e, nil, err
	}
	return e, ct, nil
}

// peelLayer decrypts a layer with the relay's identity.
func peelLayer(id Identity, e Key, ct []byte) (peeled, error) {
	shared, err := x25519(id.Private[:], e)
	if err != nil {
		return peeled{}, err
	}
	defer clear(shared)
	k, err := onionKey(shared, e, id.Public)
	if err != nil {
		return peeled{}, err
	}
	defer clear(k[:])
	p, err := open(k, domainOnion, 0, ct, []byte(magic))
	if err != nil {
		return peeled{}, err
	}
	return parseLayerPlain(e, p)
}

func parseLayerPlain(e Key, p []byte) (peeled, error) {
	if len(p) < 1 {
		return peeled{}, ErrProtocol
	}
	n := int(p[0])
	if n == 0 || len(p) < 1+n {
		return peeled{}, ErrProtocol
	}
	next, err := netip.ParseAddrPort(string(p[1 : 1+n]))
	if err != nil || next.Port() == 0 || !next.Addr().IsValid() || next.Addr().IsUnspecified() {
		return peeled{}, fmt.Errorf("%w: sonraki adres", ErrProtocol)
	}
	inner := p[1+n:]
	if len(inner) > 0 {
		// The inner bytes must themselves be a relay layer.
		r := bytes.NewReader(inner)
		k, err := readPreamble(r)
		if err != nil || k != kindRelay {
			return peeled{}, fmt.Errorf("%w: iç katman", ErrProtocol)
		}
		if _, _, err := readLayer(r); err != nil || r.Len() != 0 {
			return peeled{}, fmt.Errorf("%w: iç katman", ErrProtocol)
		}
	}
	return peeled{ephemeral: e, next: next, inner: inner}, nil
}

// ParseLayer parses a full 'R' layer including the preamble and decrypts
// it with id. It is exported for fuzzing.
func ParseLayer(id Identity, b []byte) (netip.AddrPort, error) {
	r := bytes.NewReader(b)
	k, err := readPreamble(r)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if k != kindRelay {
		return netip.AddrPort{}, ErrProtocol
	}
	e, ct, err := readLayer(r)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := peelLayer(id, e, ct)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return p.next, nil
}
