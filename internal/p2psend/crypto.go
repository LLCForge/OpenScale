// Package p2psend sends files between OpenScale devices with application
// level end-to-end encryption on top of the tunnel (ADR-0204).
//
// The file is encrypted to the receiver's WireGuard key as listed in the
// signed network document, so a coordinator, a relay, an exit node or a
// trusted intermediate device carrying the bytes never sees the file, its
// name or its exact size. The sender authenticates with its own
// WireGuard key from the same document:
//
//	dh1 = X25519(ephemeral, receiver)       forward secrecy for the sender side
//	dh2 = X25519(sender static, receiver)   sender authentication
//	keys = HKDF-SHA256(dh1 || dh2, salt = e || S || R, info)
//
// Three keys are derived: one for the sealed header (name, size, digest),
// one for file chunks and one for the receiver's replies. Every chunk is a
// fixed size ChaCha20-Poly1305 record with its index as nonce, so chunks
// cannot be reordered, dropped or moved between transfers, and the last
// chunk is padded so the record count reveals the size only to 64 KiB.
//
// Direct delivery over the tunnel is tried first. Optionally the stream
// goes through two or three trusted member devices with layered (onion)
// routing headers: every relay learns only the previous and the next hop
// (onion.go).
package p2psend

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of X25519 keys.
const KeySize = 32

// Key is an X25519 public key (a WireGuard public key).
type Key [KeySize]byte

// IsZero reports whether k is all zeros.
func (k Key) IsZero() bool { return k == Key{} }

// Identity is this device's static X25519 key pair (its WireGuard key).
type Identity struct {
	Private [KeySize]byte
	Public  Key
}

// NewIdentity derives the public key from a private key.
func NewIdentity(private [KeySize]byte) (Identity, error) {
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	id.Private = private
	copy(id.Public[:], pub)
	return id, nil
}

// GenerateIdentity creates a random identity (tests and one-off use).
func GenerateIdentity(random io.Reader) (Identity, error) {
	if random == nil {
		random = rand.Reader
	}
	var priv [KeySize]byte
	if _, err := io.ReadFull(random, priv[:]); err != nil {
		return Identity{}, err
	}
	return NewIdentity(priv)
}

// Wipe clears the private key.
func (id *Identity) Wipe() { clear(id.Private[:]) }

const (
	infoSession = "openscale/p2psend/v1/session"
	infoOnion   = "openscale/p2psend/v1/onion"
)

// ErrHandshake hides why a session could not be opened.
var ErrHandshake = errors.New("uçtan uca anahtar anlaşması başarısız")

// sessionKeys are the per-transfer keys.
type sessionKeys struct {
	header [32]byte
	data   [32]byte
	reply  [32]byte
}

func (k *sessionKeys) wipe() {
	clear(k.header[:])
	clear(k.data[:])
	clear(k.reply[:])
}

// deriveSession computes the session keys from the two shared secrets and
// the three public keys.
func deriveSession(dh1, dh2 []byte, e, s, r Key) (sessionKeys, error) {
	secret := make([]byte, 0, 64)
	secret = append(secret, dh1...)
	secret = append(secret, dh2...)
	defer clear(secret)
	salt := make([]byte, 0, 96)
	salt = append(salt, e[:]...)
	salt = append(salt, s[:]...)
	salt = append(salt, r[:]...)
	out, err := hkdf.Key(sha256.New, secret, salt, infoSession, 96)
	if err != nil {
		return sessionKeys{}, err
	}
	defer clear(out)
	var k sessionKeys
	copy(k.header[:], out[0:32])
	copy(k.data[:], out[32:64])
	copy(k.reply[:], out[64:96])
	return k, nil
}

// x25519 refuses low-order points (all-zero output).
func x25519(priv []byte, pub Key) ([]byte, error) {
	out, err := curve25519.X25519(priv, pub[:])
	if err != nil {
		return nil, ErrHandshake
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(out, zero[:]) == 1 {
		return nil, ErrHandshake
	}
	return out, nil
}

// senderSession runs the sender side: it returns the ephemeral public key
// and the session keys for receiver r.
func senderSession(id Identity, r Key, random io.Reader) (Key, sessionKeys, error) {
	if random == nil {
		random = rand.Reader
	}
	var ePriv [32]byte
	defer clear(ePriv[:])
	if _, err := io.ReadFull(random, ePriv[:]); err != nil {
		return Key{}, sessionKeys{}, err
	}
	ePubB, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, sessionKeys{}, err
	}
	var e Key
	copy(e[:], ePubB)
	dh1, err := x25519(ePriv[:], r)
	if err != nil {
		return Key{}, sessionKeys{}, err
	}
	defer clear(dh1)
	dh2, err := x25519(id.Private[:], r)
	if err != nil {
		return Key{}, sessionKeys{}, err
	}
	defer clear(dh2)
	k, err := deriveSession(dh1, dh2, e, id.Public, r)
	return e, k, err
}

// receiverSession derives the same keys on the receiving device.
func receiverSession(id Identity, e, s Key) (sessionKeys, error) {
	dh1, err := x25519(id.Private[:], e)
	if err != nil {
		return sessionKeys{}, err
	}
	defer clear(dh1)
	dh2, err := x25519(id.Private[:], s)
	if err != nil {
		return sessionKeys{}, err
	}
	defer clear(dh2)
	return deriveSession(dh1, dh2, e, s, id.Public)
}

// nonceFor builds a 12-byte nonce: a 4-byte domain and an 8-byte counter.
func nonceFor(domain uint32, counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(n[0:4], domain)
	binary.BigEndian.PutUint64(n[4:12], counter)
	return n
}

const (
	domainHeader uint32 = 1
	domainData   uint32 = 2
	domainReply  uint32 = 3
	domainOnion  uint32 = 4
)

func seal(key *[32]byte, domain uint32, counter uint64, plain, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonceFor(domain, counter), plain, ad), nil
}

func open(key *[32]byte, domain uint32, counter uint64, ct, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	p, err := aead.Open(nil, nonceFor(domain, counter), ct, ad)
	if err != nil {
		return nil, fmt.Errorf("%w: kimlik doğrulama etiketi uyuşmuyor", ErrCorrupt)
	}
	return p, nil
}

// ErrCorrupt is returned when a record fails authentication.
var ErrCorrupt = errors.New("şifreli kayıt doğrulanamadı")
