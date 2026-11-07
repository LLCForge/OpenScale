package trust

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Members-only document part (#629, ADR-0178; used by members_only.go,
// which wires it into the document). The coordinator works with
// keys and endpoints only, while device names, tags and rules travel
// encrypted end to end to the members.
//
// SealPrivatePart encrypts a payload once under a random content key and
// wraps that key for every recipient device with X25519 (an ephemeral key
// against the device's WireGuard public key), HKDF-SHA256 and
// ChaCha20-Poly1305. The network id and document version are bound as
// additional data, so a part cannot be moved to another network or
// version. Only members hold the WireGuard private keys; the coordinator
// sees the recipients' device ids, the sizes and nothing else.

// Private part limits.
const (
	MaxPrivateRecipients = MaxDevices
	maxPrivatePlaintext  = MaxDocumentSize
	privatePartFormat    = "openscale-private-part-v1"
)

// ErrPrivatePart is returned when a private part cannot be opened.
var ErrPrivatePart = errors.New("cannot open the members-only document part")

// PrivateRecipient is a member that can open a private part.
type PrivateRecipient struct {
	DeviceID     string `json:"device_id"`
	WireGuardKey Key    `json:"-"`
	// Wrapped is the content key sealed for this device.
	Wrapped []byte `json:"wrapped"`
}

// PrivatePart is the encrypted members-only part of a document.
type PrivatePart struct {
	Format     string             `json:"format"`
	Ephemeral  Key                `json:"ephemeral"`
	Recipients []PrivateRecipient `json:"recipients"`
	Nonce      []byte             `json:"nonce"`
	Ciphertext []byte             `json:"ciphertext"`
}

func privateAD(networkID string, version uint64) []byte {
	ad := []byte(privatePartFormat + "\x00" + networkID + "\x00")
	return binary.BigEndian.AppendUint64(ad, version)
}

func wrapKey(shared []byte, eph, recipient Key, networkID string, version uint64) ([]byte, error) {
	salt := slices.Concat(eph[:], recipient[:])
	r := hkdf.New(sha256.New, shared, salt, slices.Concat([]byte("openscale/private-part/v1/wrap\x00"), privateAD(networkID, version)))
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

// SealPrivatePart encrypts plaintext for the given devices (device id and
// WireGuard public key each).
func SealPrivatePart(plaintext []byte, recipients []PrivateRecipient, networkID string, version uint64, random io.Reader) (*PrivatePart, error) {
	if len(plaintext) > maxPrivatePlaintext {
		return nil, ErrTooLarge
	}
	if len(recipients) == 0 || len(recipients) > MaxPrivateRecipients {
		return nil, fmt.Errorf("1-%d recipients are allowed", MaxPrivateRecipients)
	}
	var ephPriv [32]byte
	if _, err := io.ReadFull(random, ephPriv[:]); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	defer wipe(ephPriv[:])
	ephPubBytes, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var eph Key
	copy(eph[:], ephPubBytes)
	content := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(random, content); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	defer wipe(content)
	part := &PrivatePart{Format: privatePartFormat, Ephemeral: eph, Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	seen := make(map[string]bool, len(recipients))
	for _, r := range recipients {
		if !isValidID(r.DeviceID) || seen[r.DeviceID] || r.WireGuardKey.IsZero() {
			return nil, errors.New("recipients need distinct device ids and keys")
		}
		seen[r.DeviceID] = true
		shared, err := curve25519.X25519(ephPriv[:], r.WireGuardKey[:])
		if err != nil {
			return nil, fmt.Errorf("recipient %s: %w", r.DeviceID, err)
		}
		k, err := wrapKey(shared, eph, r.WireGuardKey, networkID, version)
		wipe(shared)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(k)
		wipe(k)
		if err != nil {
			return nil, err
		}
		// The wrapping key is unique per (ephemeral, recipient), so a zero
		// nonce is never reused under one key.
		nonce := make([]byte, chacha20poly1305.NonceSize)
		part.Recipients = append(part.Recipients, PrivateRecipient{DeviceID: r.DeviceID,
			Wrapped: aead.Seal(nil, nonce, content, []byte(r.DeviceID))})
	}
	slices.SortFunc(part.Recipients, func(a, b PrivateRecipient) int {
		if a.DeviceID < b.DeviceID {
			return -1
		}
		if a.DeviceID > b.DeviceID {
			return 1
		}
		return 0
	})
	if _, err := io.ReadFull(random, part.Nonce); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	aead, err := chacha20poly1305.NewX(content)
	if err != nil {
		return nil, err
	}
	part.Ciphertext = aead.Seal(nil, part.Nonce, plaintext, privateAD(networkID, version))
	return part, nil
}

// OpenPrivatePart decrypts the part with this device's id and WireGuard
// private key.
func OpenPrivatePart(part *PrivatePart, deviceID string, wgPriv []byte, networkID string, version uint64) ([]byte, error) {
	if part == nil || part.Format != privatePartFormat || len(part.Nonce) != chacha20poly1305.NonceSizeX || len(wgPriv) != 32 {
		return nil, ErrPrivatePart
	}
	idx := slices.IndexFunc(part.Recipients, func(r PrivateRecipient) bool { return r.DeviceID == deviceID })
	if idx < 0 {
		return nil, ErrPrivatePart
	}
	pubBytes, err := curve25519.X25519(wgPriv, curve25519.Basepoint)
	if err != nil {
		return nil, ErrPrivatePart
	}
	var pub Key
	copy(pub[:], pubBytes)
	shared, err := curve25519.X25519(wgPriv, part.Ephemeral[:])
	if err != nil {
		return nil, ErrPrivatePart
	}
	k, err := wrapKey(shared, part.Ephemeral, pub, networkID, version)
	wipe(shared)
	if err != nil {
		return nil, ErrPrivatePart
	}
	aead, err := chacha20poly1305.New(k)
	wipe(k)
	if err != nil {
		return nil, ErrPrivatePart
	}
	content, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), part.Recipients[idx].Wrapped, []byte(deviceID))
	if err != nil {
		return nil, ErrPrivatePart
	}
	defer wipe(content)
	x, err := chacha20poly1305.NewX(content)
	if err != nil {
		return nil, ErrPrivatePart
	}
	plain, err := x.Open(nil, part.Nonce, part.Ciphertext, privateAD(networkID, version))
	if err != nil {
		return nil, ErrPrivatePart
	}
	return plain, nil
}
