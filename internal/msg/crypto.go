// Package msg is OpenScale's embedded end-to-end encrypted messaging
// between devices (ADR-0109, #242).
//
// A message is sealed for one recipient with keys derived from the two
// devices' WireGuard X25519 keys, which the signed network document
// already binds to device names:
//
//	dh1 = X25519(ephemeral, recipient static)
//	dh2 = X25519(sender static, recipient static)
//	key = HKDF-SHA256(dh1 || dh2, salt = ephemeral public,
//	                  info = label || sender public || recipient public)
//	box = AES-256-GCM(key, nonce = 0, plaintext, aad = header)
//
// dh2 authenticates the sender to the recipient (only the holder of the
// sender's static key or the recipient can compute it); the fresh
// ephemeral key gives every message its own key, so the all-zero nonce is
// never reused, and a later theft of the sender's static key alone does
// not open past messages. The header (id, names, time, ephemeral key) is
// authenticated as additional data.
//
// Messages travel only inside the tunnel, directly between the two
// devices; nothing is relayed through or stored at the coordinator.
// Storage exists only on the two devices (store.go).
package msg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	// Version is the envelope format version.
	Version = 1
	// MaxText bounds a message's UTF-8 text.
	MaxText = 4000
	// Port is the TCP port of the message listener on each device's
	// tunnel address, next to the other tunnel services (4022, 4044-4047).
	Port uint16 = 4048

	keyLabel = "openscale-msg-v1 key"
	aadLabel = "openscale-msg-v1"
	idBytes  = 16
	keySize  = 32
	gcmTag   = 16
	maxName  = 63
)

var (
	// ErrDecrypt means the envelope did not open with the expected keys:
	// it was forged, altered or sealed for another device.
	ErrDecrypt = errors.New("mesaj açılamadı: anahtar uyuşmuyor veya içerik değiştirilmiş")
	// ErrBadEnvelope means the envelope is malformed.
	ErrBadEnvelope = errors.New("geçersiz mesaj zarfı")
)

// Envelope is a sealed message on the wire.
type Envelope struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Time      int64  `json:"t"`
	Ephemeral []byte `json:"e"`
	Box       []byte `json:"c"`
}

// ValidName reports whether s can be a device name in an envelope:
// lowercase DNS label characters, at most 63 bytes.
func ValidName(s string) bool {
	if s == "" || len(s) > maxName || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validID(s string) bool {
	if len(s) != idBytes*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Validate checks the envelope's shape, not its authenticity.
func (e Envelope) Validate() error {
	switch {
	case e.V != Version:
		return fmt.Errorf("%w: sürüm %d desteklenmiyor", ErrBadEnvelope, e.V)
	case !validID(e.ID):
		return fmt.Errorf("%w: kimlik", ErrBadEnvelope)
	case !ValidName(e.From) || !ValidName(e.To) || e.From == e.To:
		return fmt.Errorf("%w: cihaz adı", ErrBadEnvelope)
	case e.Time <= 0:
		return fmt.Errorf("%w: zaman", ErrBadEnvelope)
	case len(e.Ephemeral) != keySize:
		return fmt.Errorf("%w: geçici anahtar", ErrBadEnvelope)
	case len(e.Box) < gcmTag+1 || len(e.Box) > MaxText+gcmTag:
		return fmt.Errorf("%w: boyut", ErrBadEnvelope)
	}
	return nil
}

func (e Envelope) aad() []byte {
	b := make([]byte, 0, 160)
	b = append(b, aadLabel...)
	for _, f := range []string{e.ID, e.From, e.To, strconv.FormatInt(e.Time, 10), hex.EncodeToString(e.Ephemeral)} {
		b = append(b, 0)
		b = append(b, f...)
	}
	return b
}

// CheckText validates a message text before sealing.
func CheckText(text string) error {
	switch {
	case text == "":
		return errors.New("mesaj boş")
	case len(text) > MaxText:
		return fmt.Errorf("mesaj en fazla %d bayt olabilir", MaxText)
	case !utf8.ValidString(text):
		return errors.New("mesaj geçerli UTF-8 değil")
	}
	return nil
}

func deriveKey(dh1, dh2, ephPub, senderPub, recipientPub []byte) (cipher.AEAD, error) {
	ikm := make([]byte, 0, len(dh1)+len(dh2))
	ikm = append(append(ikm, dh1...), dh2...)
	info := make([]byte, 0, len(keyLabel)+2*keySize)
	info = append(append(append(info, keyLabel...), senderPub...), recipientPub...)
	key, err := hkdf.Key(sha256.New, ikm, ephPub, string(info), keySize)
	clear(ikm)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts text from the device holding senderPriv (its WireGuard
// private key) to the device whose WireGuard public key is recipientPub.
func Seal(random io.Reader, senderPriv, recipientPub []byte, from, to string, now time.Time, text string) (Envelope, error) {
	if err := CheckText(text); err != nil {
		return Envelope{}, err
	}
	curve := ecdh.X25519()
	s, err := curve.NewPrivateKey(senderPriv)
	if err != nil {
		return Envelope{}, fmt.Errorf("gönderen anahtarı: %w", err)
	}
	r, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return Envelope{}, fmt.Errorf("alıcı anahtarı: %w", err)
	}
	eph, err := curve.GenerateKey(random)
	if err != nil {
		return Envelope{}, err
	}
	id := make([]byte, idBytes)
	if _, err := io.ReadFull(random, id); err != nil {
		return Envelope{}, err
	}
	env := Envelope{V: Version, ID: hex.EncodeToString(id), From: from, To: to, Time: now.Unix(), Ephemeral: eph.PublicKey().Bytes()}
	dh1, err := eph.ECDH(r)
	if err != nil {
		return Envelope{}, fmt.Errorf("alıcı anahtarı: %w", err)
	}
	defer clear(dh1)
	dh2, err := s.ECDH(r)
	if err != nil {
		return Envelope{}, fmt.Errorf("alıcı anahtarı: %w", err)
	}
	defer clear(dh2)
	aead, err := deriveKey(dh1, dh2, env.Ephemeral, s.PublicKey().Bytes(), r.Bytes())
	if err != nil {
		return Envelope{}, err
	}
	env.Box = aead.Seal(nil, make([]byte, aead.NonceSize()), []byte(text), env.aad())
	if err := env.Validate(); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// Open authenticates and decrypts env with the recipient's WireGuard
// private key and the sender's WireGuard public key taken from the signed
// document (never from the envelope).
func Open(recipientPriv, senderPub []byte, env Envelope) (string, error) {
	if err := env.Validate(); err != nil {
		return "", err
	}
	curve := ecdh.X25519()
	r, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return "", fmt.Errorf("alıcı anahtarı: %w", err)
	}
	s, err := curve.NewPublicKey(senderPub)
	if err != nil {
		return "", fmt.Errorf("gönderen anahtarı: %w", err)
	}
	e, err := curve.NewPublicKey(env.Ephemeral)
	if err != nil {
		return "", ErrDecrypt
	}
	dh1, err := r.ECDH(e)
	if err != nil {
		return "", ErrDecrypt
	}
	defer clear(dh1)
	dh2, err := r.ECDH(s)
	if err != nil {
		return "", ErrDecrypt
	}
	defer clear(dh2)
	aead, err := deriveKey(dh1, dh2, env.Ephemeral, s.Bytes(), r.PublicKey().Bytes())
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, make([]byte, aead.NonceSize()), env.Box, env.aad())
	if err != nil {
		return "", ErrDecrypt
	}
	if err := CheckText(string(pt)); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadEnvelope, err)
	}
	return string(pt), nil
}
