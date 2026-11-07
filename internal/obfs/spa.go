package obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Single packet authorization knock (#614, ADR-0181). The primitives live
// here so that devices (internal/node) and the coordinator share one
// definition without the device code importing the coordinator.
//
// Knock (61 bytes): "OSK1" | version 1 | unix seconds (8, big endian) |
// random nonce (16) | HMAC-SHA256(key, first 29 bytes).

const (
	// SPAMagic opens every knock.
	SPAMagic   = "OSK1"
	spaVersion = 1
	// SPAKnockSize is the knock's length.
	SPAKnockSize = 4 + 1 + 8 + 16 + sha256.Size
)

// SPAKey derives the knock key of a coordinator from its WireGuard public
// key and the network id (both in the signed document).
func SPAKey(coordinatorWG [32]byte, networkID string) [32]byte {
	ikm := append(append([]byte{}, coordinatorWG[:]...), networkID...)
	r := hkdf.New(sha256.New, ikm, []byte("openscale/spa/v1"), []byte("knock"))
	var k [32]byte
	_, _ = io.ReadFull(r, k[:])
	return k
}

// SPAKnock builds a knock.
func SPAKnock(key [32]byte, now time.Time, random io.Reader) ([]byte, error) {
	out := make([]byte, SPAKnockSize)
	copy(out, SPAMagic)
	out[4] = spaVersion
	binary.BigEndian.PutUint64(out[5:13], uint64(now.Unix())) //nolint:gosec // times after 1970
	if _, err := io.ReadFull(random, out[13:29]); err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key[:])
	m.Write(out[:29])
	copy(out[29:], m.Sum(nil))
	return out, nil
}

// IsSPAKnock reports whether data looks like a knock (shape only).
func IsSPAKnock(data []byte) bool {
	return len(data) == SPAKnockSize && string(data[:4]) == SPAMagic && data[4] == spaVersion
}

// DemuxKnock is Demux for the coordinator's TLS camouflage when a device
// may open with an SPA knock (#614): a stream that starts with SPAMagic
// or with magic passes (the bytes read are replayed); anything else gets
// the decoy web answer. magic must be at least len(SPAMagic) long.
func DemuxKnock(c net.Conn, magic string, timeout time.Duration) (net.Conn, bool) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	head := make([]byte, len(SPAMagic))
	if _, err := io.ReadFull(c, head); err != nil {
		_ = c.Close()
		return nil, false
	}
	if string(head) == SPAMagic {
		_ = c.SetReadDeadline(time.Time{})
		return &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(head), c)}, true
	}
	return Demux(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(head), c)}, magic, timeout)
}
