package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// PublicKeyPrefix starts the text form of a release public key.
const PublicKeyPrefix = "osrelkey1:"

// PublicKey is an Ed25519 public key. Its text (and JSON) form is
// PublicKeyPrefix followed by unpadded base64url.
type PublicKey [ed25519.PublicKeySize]byte

// PublicKeyFrom copies an ed25519 public key.
func PublicKeyFrom(pub ed25519.PublicKey) (PublicKey, error) {
	var k PublicKey
	if len(pub) != ed25519.PublicKeySize {
		return k, errors.New("invalid ed25519 public key size")
	}
	copy(k[:], pub)
	if k.IsZero() {
		return k, errors.New("public key is all zeros")
	}
	return k, nil
}

// ParsePublicKey parses the text form, surrounding whitespace allowed.
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	err := k.UnmarshalText([]byte(strings.TrimSpace(s)))
	return k, err
}

// IsZero reports whether the key is unset.
func (k PublicKey) IsZero() bool { return k == PublicKey{} }

// Equal compares two keys in constant time.
func (k PublicKey) Equal(o PublicKey) bool { return subtle.ConstantTimeCompare(k[:], o[:]) == 1 }

// String returns the text form.
func (k PublicKey) String() string {
	return PublicKeyPrefix + base64.RawURLEncoding.EncodeToString(k[:])
}

// MarshalText implements encoding.TextMarshaler.
func (k PublicKey) MarshalText() ([]byte, error) {
	if k.IsZero() {
		return nil, errors.New("public key is missing")
	}
	return []byte(k.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *PublicKey) UnmarshalText(text []byte) error {
	s := string(text)
	if !strings.HasPrefix(s, PublicKeyPrefix) || len(s) > 128 {
		return errors.New("release public key must start with " + PublicKeyPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, PublicKeyPrefix))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("invalid release public key encoding")
	}
	var tmp PublicKey
	copy(tmp[:], raw)
	if tmp.IsZero() {
		return errors.New("public key is all zeros")
	}
	*k = tmp
	return nil
}

// Fingerprint returns the SHA-256 of the key with a domain prefix, as 16
// groups of four hex digits, for comparison over a separate channel.
func (k PublicKey) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte("openscale-release-key\x00"))
	h.Write(k[:])
	sum := hex.EncodeToString(h.Sum(nil))
	groups := make([]string, 0, len(sum)/4)
	for i := 0; i < len(sum); i += 4 {
		groups = append(groups, sum[i:i+4])
	}
	return strings.Join(groups, " ")
}

// NormalizeFingerprint removes spaces, colons and dashes and lowercases.
func NormalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", ":", "", "-", "").Replace(strings.TrimSpace(s)))
}

// Key roles stored in sealed key files.
const (
	RoleRoot    = "root"
	RoleSigning = "signing"
)

const (
	sealedKeyFormat = "openscale-release-key-v1"
	saltSize        = 16
	// MaxSealedKeySize bounds a sealed key file.
	MaxSealedKeySize = 4096
	// MinPassphraseLength is the minimum number of characters (runes).
	MinPassphraseLength = 12
	maxPassphraseBytes  = 1024
	minDistinctRunes    = 6
)

// KDFParams configures Argon2id for a sealed key.
type KDFParams struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultKDF follows RFC 9106's second recommended option.
var DefaultKDF = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// ErrWrongPassphrase is returned when a passphrase does not open a key.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted key file")

// ErrWeakPassphrase is returned for passphrases below the policy.
var ErrWeakPassphrase = fmt.Errorf("passphrase must be at least %d characters with %d distinct characters", MinPassphraseLength, minDistinctRunes)

// SealedKey is a passphrase-encrypted release private key (root or signing).
type SealedKey struct {
	Format     string    `json:"format"`
	Role       string    `json:"role"`
	PublicKey  PublicKey `json:"public_key"`
	KDF        KDFParams `json:"kdf"`
	Salt       []byte    `json:"salt"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
}

// GenerateKey creates a new Ed25519 key pair.
func GenerateKey(random io.Reader) (PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return PublicKey{}, nil, fmt.Errorf("generate key: %w", err)
	}
	k, err := PublicKeyFrom(pub)
	if err != nil {
		return PublicKey{}, nil, err
	}
	return k, priv, nil
}

// CheckPassphrase enforces the passphrase policy.
func CheckPassphrase(passphrase []byte) error {
	if len(passphrase) > maxPassphraseBytes {
		return errors.New("passphrase is too long")
	}
	if !utf8.Valid(passphrase) || utf8.RuneCount(passphrase) < MinPassphraseLength {
		return ErrWeakPassphrase
	}
	distinct := make(map[rune]struct{}, 16)
	for _, r := range string(passphrase) {
		distinct[r] = struct{}{}
	}
	if len(distinct) < minDistinctRunes {
		return ErrWeakPassphrase
	}
	return nil
}

// SealKey encrypts priv for role with a key derived from passphrase.
func SealKey(priv ed25519.PrivateKey, role string, passphrase []byte, params KDFParams, random io.Reader) (*SealedKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	if role != RoleRoot && role != RoleSigning && role != RoleWitness {
		return nil, fmt.Errorf("unknown key role %q", role)
	}
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	pub, err := PublicKeyFrom(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	s := &SealedKey{
		Format:    sealedKeyFormat,
		Role:      role,
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

// Open decrypts the key and checks it against the stored public key, so a
// tampered file cannot yield a different key.
func (s *SealedKey) Open(passphrase []byte) (ed25519.PrivateKey, error) {
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
	defer wipe(kek)
	seed, err := aead.Open(nil, s.Nonce, s.Ciphertext, s.additionalData())
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrWrongPassphrase
	}
	defer wipe(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	if subtle.ConstantTimeCompare(priv.Public().(ed25519.PublicKey), s.PublicKey[:]) != 1 {
		wipe(priv)
		return nil, ErrWrongPassphrase
	}
	return priv, nil
}

// MarshalSealedKey encodes a sealed key as JSON.
func MarshalSealedKey(s *SealedKey) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return marshalIndent(s)
}

// UnmarshalSealedKey strictly decodes and validates a sealed key.
func UnmarshalSealedKey(data []byte) (*SealedKey, error) {
	if len(data) > MaxSealedKeySize {
		return nil, errors.New("sealed key file is too large")
	}
	var s SealedKey
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("decode sealed key: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *SealedKey) validate() error {
	switch {
	case s.Format != sealedKeyFormat:
		return fmt.Errorf("unsupported key format %q", s.Format)
	case s.Role != RoleRoot && s.Role != RoleSigning && s.Role != RoleWitness:
		return fmt.Errorf("unknown key role %q", s.Role)
	case s.PublicKey.IsZero():
		return errors.New("public key is missing")
	case len(s.Salt) != saltSize:
		return errors.New("invalid salt size")
	case len(s.Nonce) != chacha20poly1305.NonceSizeX:
		return errors.New("invalid nonce size")
	case len(s.Ciphertext) != ed25519.SeedSize+chacha20poly1305.Overhead:
		return errors.New("invalid ciphertext size")
	}
	return s.KDF.validate()
}

// Bounds reject weak parameters and crafted files that would exhaust memory.
func (p KDFParams) validate() error {
	if p.Time < 1 || p.Time > 10 || p.MemoryKiB < 64*1024 || p.MemoryKiB > 1024*1024 || p.Threads < 1 || p.Threads > 16 {
		return errors.New("argon2id parameters are outside the allowed range")
	}
	return nil
}

type aeadCipher interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func (s *SealedKey) aead(passphrase []byte) (aeadCipher, []byte, error) {
	kek := argon2.IDKey(passphrase, s.Salt, s.KDF.Time, s.KDF.MemoryKiB, s.KDF.Threads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		wipe(kek)
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}
	return aead, kek, nil
}

// additionalData binds format, role, public key, KDF parameters and salt to
// the ciphertext: changing any of them (for example turning a signing key
// file into a root key file, or lowering the Argon2 cost) breaks decryption.
func (s *SealedKey) additionalData() []byte {
	ad := make([]byte, 0, 64+len(s.Role)+saltSize)
	ad = append(ad, sealedKeyFormat...)
	ad = append(ad, 0)
	ad = append(ad, s.Role...)
	ad = append(ad, 0)
	ad = append(ad, s.PublicKey[:]...)
	ad = binary.BigEndian.AppendUint32(ad, s.KDF.Time)
	ad = binary.BigEndian.AppendUint32(ad, s.KDF.MemoryKiB)
	ad = append(ad, s.KDF.Threads)
	ad = append(ad, s.Salt...)
	return ad
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
