package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	rootKeyFormat = "openscale-root-key-v1"
	saltSize      = 16

	// MinPassphraseLength is the minimum number of characters (runes).
	MinPassphraseLength = 12
	maxPassphraseBytes  = 1024

	// MaxSealedKeySize bounds the sealed root key file.
	MaxSealedKeySize = 4096
)

// Argon2Params configures Argon2id for the root key passphrase.
type Argon2Params struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultArgon2 follows RFC 9106's second recommended option.
var DefaultArgon2 = Argon2Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// Bounds reject both weak parameters and a crafted file that would make
// opening the key exhaust memory or CPU.
const (
	minArgonTime    = 1
	maxArgonTime    = 10
	minArgonMemory  = 64 * 1024
	maxArgonMemory  = 1024 * 1024
	minArgonThreads = 1
	maxArgonThreads = 16
)

// ErrWrongPassphrase is returned when the passphrase does not decrypt the key.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted root key")

// ErrWeakPassphrase is returned for passphrases shorter than the minimum.
var ErrWeakPassphrase = fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLength)

// SealedRootKey is the on-disk, passphrase-encrypted root key.
type SealedRootKey struct {
	Format     string       `json:"format"`
	PublicKey  Key          `json:"public_key"`
	KDF        Argon2Params `json:"kdf"`
	Salt       []byte       `json:"salt"`
	Nonce      []byte       `json:"nonce"`
	Ciphertext []byte       `json:"ciphertext"`
}

// GenerateRootKey creates a new root key pair.
func GenerateRootKey(random io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := checkRandomSource(random); err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("generate root key: %w", err)
	}
	return pub, priv, nil
}

// SealRootKey encrypts priv with a key derived from passphrase.
func SealRootKey(priv ed25519.PrivateKey, passphrase []byte, params Argon2Params, random io.Reader) (*SealedRootKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid root private key")
	}
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	pub, err := keyFromSlice(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}

	s := &SealedRootKey{
		Format:    rootKeyFormat,
		PublicKey: pub,
		KDF:       params,
		Salt:      make([]byte, saltSize),
		Nonce:     make([]byte, chacha20poly1305.NonceSizeX),
	}
	if _, err := io.ReadFull(random, s.Salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	if _, err := io.ReadFull(random, s.Nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	aead, kek, err := s.aead(passphrase)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)

	seed := priv.Seed()
	defer wipe(seed)
	s.Ciphertext = aead.Seal(nil, s.Nonce, seed, s.additionalData())
	return s, nil
}

// Open decrypts the root key. The decrypted key is checked against the
// stored public key so a tampered file cannot yield a different key.
func (s *SealedRootKey) Open(passphrase []byte) (ed25519.PrivateKey, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if len(passphrase) == 0 || len(passphrase) > maxPassphraseBytes {
		return nil, ErrWrongPassphrase
	}
	aead, kek, err := s.aead(passphrase)
	if err != nil {
		return nil, err
	}
	lockMemory(kek)
	defer WipeKey(kek)

	seed, err := aead.Open(nil, s.Nonce, s.Ciphertext, s.additionalData())
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	lockMemory(seed)
	defer WipeKey(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrWrongPassphrase
	}
	priv := ed25519.NewKeyFromSeed(seed)
	// The caller releases the lock with WipeKey (#8, ADR-0060).
	lockMemory(priv)
	if subtle.ConstantTimeCompare(priv.Public().(ed25519.PublicKey), s.PublicKey[:]) != 1 {
		WipeKey(priv)
		return nil, ErrWrongPassphrase
	}
	return priv, nil
}

// RootPublicKey returns the public key without requiring the passphrase.
func (s *SealedRootKey) RootPublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(append([]byte(nil), s.PublicKey[:]...))
}

// Fingerprint returns a short digest of the root public key for display.
func (s *SealedRootKey) Fingerprint() string {
	return RootFingerprint(s.RootPublicKey())
}

// RootFingerprint returns a short digest of a root public key.
func RootFingerprint(pub ed25519.PublicKey) string {
	return fingerprint([]byte("root"), pub)
}

// MarshalSealedRootKey encodes the sealed key as JSON.
func MarshalSealedRootKey(s *SealedRootKey) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sealed root key: %w", err)
	}
	return append(data, '\n'), nil
}

// UnmarshalSealedRootKey strictly decodes and validates a sealed key.
func UnmarshalSealedRootKey(data []byte) (*SealedRootKey, error) {
	if len(data) > MaxSealedKeySize {
		return nil, errors.New("sealed root key is too large")
	}
	var s SealedRootKey
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("decode sealed root key: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// CheckPassphrase enforces the passphrase policy.
func CheckPassphrase(passphrase []byte) error {
	if len(passphrase) > maxPassphraseBytes {
		return errors.New("passphrase is too long")
	}
	if !utf8.Valid(passphrase) || utf8.RuneCount(passphrase) < MinPassphraseLength {
		return ErrWeakPassphrase
	}
	// A long passphrase made of very few distinct characters ("aaaaaaaaaaaa",
	// "121212121212") has almost no entropy.
	distinct := make(map[rune]struct{}, 16)
	for _, r := range string(passphrase) {
		distinct[r] = struct{}{}
	}
	if len(distinct) < minDistinctRunes {
		return ErrWeakPassphrase
	}
	// Common words, keyboard runs and repetition (#12, ADR-0060).
	if EstimatePassphraseBits(passphrase) < MinPassphraseBits {
		return ErrGuessablePassphrase
	}
	return nil
}

const minDistinctRunes = 6

func (s *SealedRootKey) validate() error {
	switch {
	case s.Format != rootKeyFormat:
		return fmt.Errorf("unsupported root key format %q", s.Format)
	case s.PublicKey.IsZero():
		return errors.New("root public key is missing")
	case len(s.Salt) != saltSize:
		return errors.New("invalid salt size")
	case len(s.Nonce) != chacha20poly1305.NonceSizeX:
		return errors.New("invalid nonce size")
	case len(s.Ciphertext) != ed25519.SeedSize+chacha20poly1305.Overhead:
		return errors.New("invalid ciphertext size")
	}
	return s.KDF.validate()
}

func (p Argon2Params) validate() error {
	if p.Time < minArgonTime || p.Time > maxArgonTime ||
		p.MemoryKiB < minArgonMemory || p.MemoryKiB > maxArgonMemory ||
		p.Threads < minArgonThreads || p.Threads > maxArgonThreads {
		return errors.New("argon2id parameters are outside the allowed range")
	}
	return nil
}

func (s *SealedRootKey) aead(passphrase []byte) (cipherAEAD, []byte, error) {
	kek := argon2.IDKey(passphrase, s.Salt, s.KDF.Time, s.KDF.MemoryKiB, s.KDF.Threads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		wipe(kek)
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}
	return aead, kek, nil
}

// additionalData binds the format, public key, KDF parameters and salt to
// the ciphertext, so changing any of them (for example lowering the Argon2
// cost) makes decryption fail.
func (s *SealedRootKey) additionalData() []byte {
	ad := make([]byte, 0, len(rootKeyFormat)+KeySize+9+saltSize)
	ad = append(ad, rootKeyFormat...)
	ad = append(ad, s.PublicKey[:]...)
	ad = binary.BigEndian.AppendUint32(ad, s.KDF.Time)
	ad = binary.BigEndian.AppendUint32(ad, s.KDF.MemoryKiB)
	ad = append(ad, s.KDF.Threads)
	ad = append(ad, s.Salt...)
	return ad
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// wipe zeroes key material on a best-effort basis; the Go runtime may still
// hold copies.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewRandom exposes the system CSPRNG for callers that need to pass it.
func NewRandom() io.Reader { return rand.Reader }
