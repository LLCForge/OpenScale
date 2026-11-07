package trust

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Passphrase-sealed secrets (ADR-0172, ADR-0175): administrator key files,
// the portable administrator blob kept on the coordinator, and the
// pre-signed emergency documents. Same construction as the root key
// (ADR-0003): Argon2id and XChaCha20-Poly1305, with the format, a label,
// the KDF parameters and the salt bound as additional data, so a blob of
// one kind is never opened as another and the KDF cost cannot be lowered.

// MaxSealedSecretSize bounds an encoded sealed secret.
const MaxSealedSecretSize = MaxEnvelopeSize + 64<<10

const (
	maxSealedLabel  = 256
	maxSealedSecret = MaxEnvelopeSize
)

// SealedSecret is a passphrase-encrypted secret.
type SealedSecret struct {
	Format     string       `json:"format"`
	Label      string       `json:"label,omitempty"`
	KDF        Argon2Params `json:"kdf"`
	Salt       []byte       `json:"salt"`
	Nonce      []byte       `json:"nonce"`
	Ciphertext []byte       `json:"ciphertext"`
}

// SealSecret encrypts secret under passphrase. format names the kind of
// secret ("openscale-...-v1"); label is bound as additional data.
func SealSecret(format, label string, secret, passphrase []byte, params Argon2Params, random io.Reader) (*SealedSecret, error) {
	if !strings.HasPrefix(format, "openscale-") || len(format) > 64 || len(label) > maxSealedLabel {
		return nil, errors.New("invalid sealed secret format or label")
	}
	if len(secret) == 0 || len(secret) > maxSealedSecret {
		return nil, errors.New("secret is empty or too large")
	}
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	s := &SealedSecret{Format: format, Label: label, KDF: params, Salt: make([]byte, saltSize), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
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
	defer WipeKey(kek)
	s.Ciphertext = aead.Seal(nil, s.Nonce, secret, s.additionalData())
	return s, nil
}

// Open decrypts the secret; format must match the sealed one. The caller
// wipes the result with WipeKey.
func (s *SealedSecret) Open(format string, passphrase []byte) ([]byte, error) {
	if err := s.validate(format); err != nil {
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
	plain, err := aead.Open(nil, s.Nonce, s.Ciphertext, s.additionalData())
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	lockMemory(plain)
	return plain, nil
}

func (s *SealedSecret) validate(format string) error {
	switch {
	case s.Format != format:
		return fmt.Errorf("unexpected sealed secret format %q", s.Format)
	case len(s.Label) > maxSealedLabel:
		return errors.New("sealed secret label is too long")
	case len(s.Salt) != saltSize:
		return errors.New("invalid salt size")
	case len(s.Nonce) != chacha20poly1305.NonceSizeX:
		return errors.New("invalid nonce size")
	case len(s.Ciphertext) <= chacha20poly1305.Overhead || len(s.Ciphertext) > maxSealedSecret+chacha20poly1305.Overhead:
		return errors.New("invalid ciphertext size")
	}
	return s.KDF.validate()
}

func (s *SealedSecret) aead(passphrase []byte) (cipherAEAD, []byte, error) {
	kek := argon2.IDKey(passphrase, s.Salt, s.KDF.Time, s.KDF.MemoryKiB, s.KDF.Threads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		wipe(kek)
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}
	return aead, kek, nil
}

func (s *SealedSecret) additionalData() []byte {
	ad := make([]byte, 0, 2*len(s.Format)+len(s.Label)+16+saltSize)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(s.Format))) //nolint:gosec // bounded above
	ad = append(ad, s.Format...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(s.Label))) //nolint:gosec // bounded above
	ad = append(ad, s.Label...)
	ad = binary.BigEndian.AppendUint32(ad, s.KDF.Time)
	ad = binary.BigEndian.AppendUint32(ad, s.KDF.MemoryKiB)
	ad = append(ad, s.KDF.Threads)
	ad = append(ad, s.Salt...)
	return ad
}

// MarshalSealedSecret encodes s as JSON.
func MarshalSealedSecret(s *SealedSecret) ([]byte, error) {
	data, err := jsonIndent(s)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSealedSecretSize {
		return nil, errors.New("sealed secret is too large")
	}
	return data, nil
}

// UnmarshalSealedSecret strictly decodes a sealed secret of format.
func UnmarshalSealedSecret(data []byte, format string) (*SealedSecret, error) {
	if len(data) > MaxSealedSecretSize {
		return nil, errors.New("sealed secret is too large")
	}
	var s SealedSecret
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("decode sealed secret: %w", err)
	}
	if err := s.validate(format); err != nil {
		return nil, err
	}
	return &s, nil
}

func jsonIndent(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return append(data, '\n'), nil
}
