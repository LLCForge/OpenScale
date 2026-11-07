// Package trust implements OpenScale's trust core: the owner's root key,
// the root-signed network document, and offline device enrollment
// (see docs/adr/0003-guven-modeli.md).
package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// KeySize is the size of every public key handled by this package
// (Ed25519 public keys and X25519/WireGuard keys).
const KeySize = 32

// Key is a 32-byte public key encoded as standard base64 in JSON, the same
// text format WireGuard tools use.
type Key [KeySize]byte

var errInvalidKey = errors.New("key must be 32 bytes of standard base64")

var keyEncoding = base64.StdEncoding.Strict()

// IsZero reports whether k is all zeros.
func (k Key) IsZero() bool { return k == Key{} }

// String returns the base64 form.
func (k Key) String() string { return keyEncoding.EncodeToString(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler and rejects
// non-canonical base64.
func (k *Key) UnmarshalText(text []byte) error {
	parsed, err := ParseKey(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// ParseKey decodes a base64 key.
func ParseKey(s string) (Key, error) {
	if len(s) != keyEncoding.EncodedLen(KeySize) {
		return Key{}, errInvalidKey
	}
	buf := make([]byte, keyEncoding.DecodedLen(len(s)))
	n, err := keyEncoding.Decode(buf, []byte(s))
	if err != nil || n != KeySize {
		return Key{}, errInvalidKey
	}
	var k Key
	copy(k[:], buf[:n])
	return k, nil
}

// keyFromSlice copies a 32-byte slice into a Key.
func keyFromSlice(b []byte) (Key, error) {
	if len(b) != KeySize {
		return Key{}, errInvalidKey
	}
	var k Key
	copy(k[:], b)
	return k, nil
}

// fingerprint returns a short, human-comparable digest such as
// "ABCD-EFGH-IJKL-MNOP" (80 bits). Each part is length-prefixed so
// different splits of the same bytes cannot collide.
func fingerprint(parts ...[]byte) string {
	h := sha256.New()
	h.Write([]byte("openscale/fingerprint/v1"))
	var lenBuf [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p))) //nolint:gosec // parts are small keys and ids
		h.Write(lenBuf[:])
		h.Write(p)
	}
	sum := h.Sum(nil)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	return enc[0:4] + "-" + enc[4:8] + "-" + enc[8:12] + "-" + enc[12:16]
}

// NormalizeFingerprint uppercases and strips separators so a fingerprint
// typed by a person can be compared with a generated one.
func NormalizeFingerprint(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// newRandomID returns a 128-bit random identifier as 32 lowercase hex chars.
func newRandomID(random io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return "", fmt.Errorf("read random id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func isValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// decodeStrict decodes exactly one JSON value into v, rejecting unknown
// fields and trailing data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}
