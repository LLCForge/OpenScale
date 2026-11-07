// Package bundlecrypt encrypts a diagnostics bundle to the X25519 public
// key of the person who will help (#512, ADR-0166). A plain zip that
// lands in the wrong mailbox or chat can be read by anyone; a sealed
// bundle only by the holder of the matching private key.
//
// Format (all integers big endian):
//
//	"OSB1" | ephemeral X25519 public key (32) | recipient public key (32) | ciphertext
//
// The key is HKDF-SHA256 over the X25519 shared secret with the two
// public keys as salt; the content is sealed once with ChaCha20-Poly1305
// under that single-use key and a zero nonce, the 68 byte header being
// the additional data. Only the standard library and golang.org/x/crypto
// are used (ADR-0002).
package bundlecrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Magic starts every sealed bundle.
const Magic = "OSB1"

// KeySize is the size of a public or private key.
const KeySize = 32

// headerSize is the magic and both public keys.
const headerSize = len(Magic) + 2*KeySize

// MaxPlaintext bounds what is sealed in one piece.
const MaxPlaintext = 64 << 20

// PublicPrefix marks a recipient key in text so it is not mistaken for
// another base64 value.
const PublicPrefix = "osbk1:"

const info = "openscale diagnostics bundle v1"

// Errors.
var (
	ErrNotSealed   = errors.New("dosya şifreli bir OpenScale teşhis paketi değil")
	ErrWrongKey    = errors.New("paket başka bir alıcı anahtarına şifrelenmiş")
	ErrDamaged     = errors.New("şifreli paket bozuk veya değiştirilmiş")
	ErrBadKey      = errors.New("alıcı anahtarı geçersiz; 'osbk1:' ile başlayan anahtarı eksiksiz yapıştırın")
	ErrTooLarge    = errors.New("paket şifrelemek için çok büyük")
	ErrBadKeyFile  = errors.New("alıcı anahtar dosyası geçersiz")
	errLowOrderKey = errors.New("zayıf anahtar")
)

// KeyPair is a recipient's key pair.
type KeyPair struct {
	Private *ecdh.PrivateKey
}

// Generate makes a key pair from rand.
func Generate(rand io.Reader) (*KeyPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Private: k}, nil
}

// PublicText is the public key to hand to the person sealing a bundle.
func (k *KeyPair) PublicText() string { return FormatPublic(k.Private.PublicKey()) }

// FormatPublic writes a public key as text.
func FormatPublic(p *ecdh.PublicKey) string {
	return PublicPrefix + base64.RawURLEncoding.EncodeToString(p.Bytes())
}

// ParsePublic reads a public key written by FormatPublic.
func ParsePublic(s string) (*ecdh.PublicKey, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, PublicPrefix)
	if !ok || len(rest) > 64 {
		return nil, ErrBadKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) != KeySize || subtle.ConstantTimeCompare(raw, make([]byte, KeySize)) == 1 {
		return nil, ErrBadKey
	}
	p, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, ErrBadKey
	}
	return p, nil
}

// keyFile is the stored key pair.
type keyFile struct {
	Schema  int    `json:"schema"`
	Private string `json:"private"`
	Public  string `json:"public"`
}

// MarshalKeyFile encodes the key pair for a private file.
func (k *KeyPair) MarshalKeyFile() ([]byte, error) {
	return json.MarshalIndent(keyFile{Schema: 1, Private: base64.StdEncoding.EncodeToString(k.Private.Bytes()), Public: k.PublicText()}, "", "  ")
}

// ParseKeyFile reads a key file and checks that its halves match.
func ParseKeyFile(data []byte) (*KeyPair, error) {
	var f keyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Schema != 1 {
		return nil, ErrBadKeyFile
	}
	raw, err := base64.StdEncoding.DecodeString(f.Private)
	if err != nil || len(raw) != KeySize {
		return nil, ErrBadKeyFile
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	clear(raw)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	k := &KeyPair{Private: priv}
	if f.Public != "" && f.Public != k.PublicText() {
		return nil, ErrBadKeyFile
	}
	return k, nil
}

func deriveKey(shared, eph, recipient []byte) ([]byte, error) {
	if subtle.ConstantTimeCompare(shared, make([]byte, len(shared))) == 1 {
		return nil, errLowOrderKey
	}
	salt := append(append([]byte(nil), eph...), recipient...)
	return hkdf.Key(sha256.New, shared, salt, info, chacha20poly1305.KeySize)
}

// Seal encrypts plaintext to recipient.
func Seal(rand io.Reader, recipient *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintext {
		return nil, ErrTooLarge
	}
	eph, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, ErrBadKey
	}
	header := make([]byte, 0, headerSize)
	header = append(header, Magic...)
	header = append(header, eph.PublicKey().Bytes()...)
	header = append(header, recipient.Bytes()...)
	key, err := deriveKey(shared, eph.PublicKey().Bytes(), recipient.Bytes())
	clear(shared)
	if err != nil {
		return nil, ErrBadKey
	}
	aead, err := chacha20poly1305.New(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	out := make([]byte, 0, headerSize+len(plaintext)+aead.Overhead())
	out = append(out, header...)
	return aead.Seal(out, nonce, plaintext, header), nil
}

// IsSealed reports whether data starts like a sealed bundle.
func IsSealed(data []byte) bool { return bytes.HasPrefix(data, []byte(Magic)) }

// Open decrypts a sealed bundle with the recipient's key pair.
func Open(k *KeyPair, sealed []byte) ([]byte, error) {
	if len(sealed) < headerSize+chacha20poly1305.Overhead || !IsSealed(sealed) {
		return nil, ErrNotSealed
	}
	header := sealed[:headerSize]
	ephRaw := header[len(Magic) : len(Magic)+KeySize]
	recRaw := header[len(Magic)+KeySize:]
	if subtle.ConstantTimeCompare(recRaw, k.Private.PublicKey().Bytes()) != 1 {
		return nil, ErrWrongKey
	}
	eph, err := ecdh.X25519().NewPublicKey(ephRaw)
	if err != nil {
		return nil, ErrDamaged
	}
	shared, err := k.Private.ECDH(eph)
	if err != nil {
		return nil, ErrDamaged
	}
	key, err := deriveKey(shared, ephRaw, recRaw)
	clear(shared)
	if err != nil {
		return nil, ErrDamaged
	}
	aead, err := chacha20poly1305.New(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), sealed[headerSize:], header)
	if err != nil {
		return nil, ErrDamaged
	}
	return plain, nil
}

// Fingerprint is a short, human comparable form of a public key.
func Fingerprint(p *ecdh.PublicKey) string {
	sum := sha256.Sum256(p.Bytes())
	return fmt.Sprintf("%X-%X-%X-%X", sum[0:2], sum[2:4], sum[4:6], sum[6:8])
}
