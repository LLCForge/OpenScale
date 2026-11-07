package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Device key rotation (ADR-0020, F-103).

// Signature contexts of a key rotation request. The old key proves the
// request comes from the current member; the new key proves possession of
// the key being installed.
const (
	KeyRotationContext       = "openscale/key-rotation/v1"
	KeyRotationNewKeyContext = "openscale/key-rotation-new-key/v1"
)

// Key rotation limits.
const (
	KeyRotationMaxAge  = EnrollmentMaxAge
	MaxRetiredKeys     = 4096
	rotationPrefix     = "osrot1."
	maxRotationPayload = 1024
	maxRotationChars   = 4096
)

// Key rotation errors.
var (
	ErrRotationStale   = errors.New("key rotation request does not match the device's current keys; it was already applied or the keys changed")
	ErrRotationExpired = errors.New("key rotation request is too old or dated in the future")
	ErrKeyInUse        = errors.New("key is already used in this network")
)

// RetiredKey records keys replaced by a rotation. They can never be used
// again by any device, invite or coordinator.
type RetiredKey struct {
	DeviceID     string    `json:"device_id"`
	SigningKey   Key       `json:"signing_key"`
	WireGuardKey Key       `json:"wireguard_key"`
	RetiredAt    time.Time `json:"retired_at"`
}

// KeyRotationRequest is the signed payload of a rotation. It is bound to
// the network, the device and the device's current keys; once applied, the
// old keys are retired and the same request no longer verifies.
type KeyRotationRequest struct {
	NetworkID       string    `json:"network_id"`
	DeviceID        string    `json:"device_id"`
	OldSigningKey   Key       `json:"old_signing_key"`
	OldWireGuardKey Key       `json:"old_wireguard_key"`
	NewSigningKey   Key       `json:"new_signing_key"`
	NewWireGuardKey Key       `json:"new_wireguard_key"`
	Nonce           string    `json:"nonce"`
	CreatedAt       time.Time `json:"created_at"`
}

// SignedKeyRotation carries the payload bytes and both signatures over
// them. DeviceID is repeated outside the payload so the old signature can
// be checked against the document before the payload is parsed.
type SignedKeyRotation struct {
	DeviceID     string `json:"device_id"`
	Payload      []byte `json:"payload"`
	OldSignature []byte `json:"old_signature"`
	NewSignature []byte `json:"new_signature"`
}

// NewKeyRotation generates new keys for the same device id and a request
// signed with the current (old) and the new signing key. The device must
// keep both key sets until it sees the new document.
func (s *DeviceSecrets) NewKeyRotation(random io.Reader, networkID string, now time.Time) (*DeviceSecrets, SignedKeyRotation, *KeyRotationRequest, error) {
	if err := s.validate(); err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	if !isValidID(networkID) {
		return nil, SignedKeyRotation{}, nil, errors.New("network id must be 32 lowercase hex characters")
	}
	next, err := GenerateDeviceSecrets(random, now)
	if err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	next.DeviceID = s.DeviceID
	oldSigning, oldWG, err := s.PublicKeys()
	if err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	newSigning, newWG, err := next.PublicKeys()
	if err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	nonce, err := newRandomID(random)
	if err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	req := &KeyRotationRequest{
		NetworkID:       networkID,
		DeviceID:        s.DeviceID,
		OldSigningKey:   oldSigning,
		OldWireGuardKey: oldWG,
		NewSigningKey:   newSigning,
		NewWireGuardKey: newWG,
		Nonce:           nonce,
		CreatedAt:       roundTimestamp(now),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, SignedKeyRotation{}, nil, fmt.Errorf("encode key rotation: %w", err)
	}
	oldSig, err := s.SigningKey().Sign(nil, payload, &ed25519.Options{Context: KeyRotationContext})
	if err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	newSig, err := next.SigningKey().Sign(nil, payload, &ed25519.Options{Context: KeyRotationNewKeyContext})
	if err != nil {
		return nil, SignedKeyRotation{}, nil, err
	}
	sr := SignedKeyRotation{DeviceID: s.DeviceID, Payload: payload, OldSignature: oldSig, NewSignature: newSig}
	return next, sr, req, nil
}

// OpenKeyRotation verifies a rotation request against doc: the old
// signature with the device's current key from doc (before the payload is
// parsed), the binding to the network and to the current keys, the age,
// the new-key signature and that the new keys are unused.
func OpenKeyRotation(doc *Document, sr SignedKeyRotation, now time.Time) (*KeyRotationRequest, error) {
	if len(sr.Payload) == 0 || len(sr.Payload) > maxRotationPayload {
		return nil, errors.New("key rotation request has an invalid size")
	}
	if !isValidID(sr.DeviceID) {
		return nil, errors.New("key rotation request has an invalid device id")
	}
	idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.ID == sr.DeviceID })
	if idx < 0 {
		return nil, ErrUnknownDevice
	}
	dev := doc.Devices[idx]
	if len(sr.OldSignature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(dev.SigningKey[:], sr.Payload, sr.OldSignature, &ed25519.Options{Context: KeyRotationContext}) != nil {
		return nil, ErrBadSignature
	}
	var req KeyRotationRequest
	if err := decodeStrict(sr.Payload, &req); err != nil {
		return nil, fmt.Errorf("decode key rotation: %w", err)
	}
	switch {
	case req.NetworkID != doc.NetworkID:
		return nil, ErrWrongNetwork
	case req.DeviceID != sr.DeviceID:
		return nil, errors.New("key rotation request names another device")
	case req.OldSigningKey != dev.SigningKey || req.OldWireGuardKey != dev.WireGuardKey:
		return nil, ErrRotationStale
	case !isValidID(req.Nonce):
		return nil, errors.New("key rotation request has an invalid nonce")
	case req.CreatedAt.IsZero() || now.Before(req.CreatedAt.Add(-clockSkew)) || now.Sub(req.CreatedAt) > KeyRotationMaxAge:
		return nil, ErrRotationExpired
	case req.NewSigningKey.IsZero() || req.NewWireGuardKey.IsZero() || req.NewSigningKey == req.NewWireGuardKey:
		return nil, errors.New("key rotation request has invalid new keys")
	}
	if len(sr.NewSignature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(req.NewSigningKey[:], sr.Payload, sr.NewSignature, &ed25519.Options{Context: KeyRotationNewKeyContext}) != nil {
		return nil, ErrBadSignature
	}
	for _, k := range []Key{req.NewSigningKey, req.NewWireGuardKey} {
		if err := doc.checkKeyFree(k); err != nil {
			return nil, err
		}
	}
	return &req, nil
}

// ApplyKeyRotation verifies sr against the document and, if it is valid,
// installs the new keys and retires the old ones in this version. There is
// no way to apply a request that was not verified against this document.
func (doc *Document) ApplyKeyRotation(sr SignedKeyRotation, now time.Time) (Device, error) {
	req, err := OpenKeyRotation(doc, sr, now)
	if err != nil {
		return Device{}, err
	}
	now = now.UTC().Truncate(time.Second)
	var out Device
	err = doc.transact(func() error {
		idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.ID == req.DeviceID })
		if idx < 0 {
			return ErrUnknownDevice
		}
		d := &doc.Devices[idx]
		doc.RetiredKeys = append(doc.RetiredKeys, RetiredKey{
			DeviceID:     d.ID,
			SigningKey:   d.SigningKey,
			WireGuardKey: d.WireGuardKey,
			RetiredAt:    now,
		})
		d.SigningKey, d.WireGuardKey = req.NewSigningKey, req.NewWireGuardKey
		out = *d
		return nil
	})
	if err != nil {
		return Device{}, err
	}
	return out, nil
}

// Fingerprint is shown on the device and confirmed by the owner before the
// rotation is signed. It covers the device id and the new keys.
func (r *KeyRotationRequest) Fingerprint() string {
	id, _ := hex.DecodeString(r.DeviceID)
	return fingerprint([]byte("device-rotation"), id, r.NewSigningKey[:], r.NewWireGuardKey[:])
}

// EncodeKeyRotation returns the single-line form of a signed rotation.
func EncodeKeyRotation(sr SignedKeyRotation) (string, error) {
	if len(sr.Payload) == 0 || len(sr.Payload) > maxRotationPayload {
		return "", errors.New("key rotation request has an invalid size")
	}
	data, err := json.Marshal(sr)
	if err != nil {
		return "", fmt.Errorf("encode key rotation: %w", err)
	}
	return rotationPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeKeyRotation parses a line produced by EncodeKeyRotation. The result
// is untrusted until OpenKeyRotation succeeds.
func DecodeKeyRotation(line string) (SignedKeyRotation, error) {
	line = strings.Join(strings.Fields(line), "")
	if len(line) > maxRotationChars || !strings.HasPrefix(line, rotationPrefix) {
		return SignedKeyRotation{}, errors.New("not an OpenScale key rotation request")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, rotationPrefix))
	if err != nil {
		return SignedKeyRotation{}, errors.New("key rotation request is damaged")
	}
	var sr SignedKeyRotation
	if err := decodeStrict(data, &sr); err != nil {
		return SignedKeyRotation{}, errors.New("key rotation request is damaged")
	}
	if len(sr.Payload) == 0 || len(sr.Payload) > maxRotationPayload {
		return SignedKeyRotation{}, errors.New("key rotation request has an invalid size")
	}
	return sr, nil
}

// checkKeyFree reports an error if k is used anywhere in the document or
// was ever revoked or retired.
func (doc *Document) checkKeyFree(k Key) error {
	for _, r := range doc.Revoked {
		if r.SigningKey == k || r.WireGuardKey == k {
			return ErrRevokedKey
		}
	}
	if doc.keyRetired(k) {
		return ErrRevokedKey
	}
	for _, d := range doc.Devices {
		if d.SigningKey == k || d.WireGuardKey == k {
			return ErrKeyInUse
		}
	}
	for _, inv := range doc.Invites {
		if inv.SigningKey == k || inv.WireGuardKey == k {
			return ErrKeyInUse
		}
	}
	if doc.Coordinator != nil && doc.Coordinator.WireGuardKey == k {
		return ErrKeyInUse
	}
	return nil
}

// keyRetired reports whether k was replaced by a rotation.
func (doc *Document) keyRetired(k Key) bool {
	for _, r := range doc.RetiredKeys {
		if r.SigningKey == k || r.WireGuardKey == k {
			return true
		}
	}
	return false
}

func (doc *Document) validateRetired() error {
	if len(doc.RetiredKeys) > MaxRetiredKeys {
		return fmt.Errorf("at most %d retired keys are allowed", MaxRetiredKeys)
	}
	retired := make(map[Key]bool, 2*len(doc.RetiredKeys))
	for i, r := range doc.RetiredKeys {
		if !isValidID(r.DeviceID) || r.SigningKey.IsZero() || r.WireGuardKey.IsZero() ||
			r.SigningKey == r.WireGuardKey || r.RetiredAt.IsZero() {
			return fmt.Errorf("retired key %d is incomplete", i)
		}
		if retired[r.SigningKey] || retired[r.WireGuardKey] {
			return fmt.Errorf("retired key %d is listed twice", i)
		}
		retired[r.SigningKey], retired[r.WireGuardKey] = true, true
	}
	if len(retired) == 0 {
		return nil
	}
	for _, d := range doc.Devices {
		if retired[d.SigningKey] || retired[d.WireGuardKey] {
			return fmt.Errorf("device %s uses a retired key", d.Name)
		}
	}
	for i, inv := range doc.Invites {
		if retired[inv.SigningKey] || retired[inv.WireGuardKey] {
			return fmt.Errorf("invite %d uses a retired key", i)
		}
	}
	if doc.Coordinator != nil && retired[doc.Coordinator.WireGuardKey] {
		return errors.New("coordinator uses a retired key")
	}
	return nil
}
