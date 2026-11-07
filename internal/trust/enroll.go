package trust

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// EnrollmentContext is the signature context of enrollment requests.
const EnrollmentContext = "openscale/enrollment-request/v1"

const (
	deviceKeyFormat = "openscale-device-key-v1"

	// MaxDeviceKeySize bounds the device key file.
	MaxDeviceKeySize = 4096

	// EnrollmentMaxAge limits how long an enrollment request stays usable.
	EnrollmentMaxAge = 24 * time.Hour

	enrollmentPrefix   = "osreq1."
	maxEnrollmentChars = 4096
	maxHostnameLen     = 63
)

// ErrEnrollmentExpired is returned for stale or future-dated requests.
var ErrEnrollmentExpired = errors.New("enrollment request is too old or dated in the future")

// DeviceSecrets is the device's private key material. It never leaves the
// device.
type DeviceSecrets struct {
	Format           string    `json:"format"`
	DeviceID         string    `json:"device_id"`
	SigningSeed      []byte    `json:"signing_seed"`
	WireGuardPrivate []byte    `json:"wireguard_private"`
	CreatedAt        time.Time `json:"created_at"`
}

// EnrollmentRequest is the public half a new device hands to the owner.
type EnrollmentRequest struct {
	DeviceID     string    `json:"device_id"`
	SigningKey   Key       `json:"signing_key"`
	WireGuardKey Key       `json:"wireguard_key"`
	Hostname     string    `json:"hostname"`
	CreatedAt    time.Time `json:"created_at"`
	// TPMEvidence is the device's TPM statement (#611, w3_join_policy.go).
	TPMEvidence json.RawMessage `json:"tpm_evidence,omitempty"`
}

// GenerateDeviceSecrets creates a device identity: a random ID, an Ed25519
// signing key and a clamped X25519 WireGuard key.
func GenerateDeviceSecrets(random io.Reader, now time.Time) (*DeviceSecrets, error) {
	if err := checkRandomSource(random); err != nil {
		return nil, err
	}
	id, err := newRandomID(random)
	if err != nil {
		return nil, err
	}
	_, signing, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	wg := make([]byte, 32)
	if _, err := io.ReadFull(random, wg); err != nil {
		return nil, fmt.Errorf("generate wireguard key: %w", err)
	}
	clampX25519(wg)
	s := &DeviceSecrets{
		Format:           deviceKeyFormat,
		DeviceID:         id,
		SigningSeed:      signing.Seed(),
		WireGuardPrivate: wg,
		CreatedAt:        roundTimestamp(now),
	}
	return s, s.validate()
}

// SigningKey returns the Ed25519 private key.
func (s *DeviceSecrets) SigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(s.SigningSeed)
}

// PublicKeys returns the device's public signing and WireGuard keys.
func (s *DeviceSecrets) PublicKeys() (Key, Key, error) {
	signing, err := keyFromSlice(s.SigningKey().Public().(ed25519.PublicKey))
	if err != nil {
		return Key{}, Key{}, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(s.WireGuardPrivate)
	if err != nil {
		return Key{}, Key{}, fmt.Errorf("load wireguard key: %w", err)
	}
	wg, err := keyFromSlice(priv.PublicKey().Bytes())
	if err != nil {
		return Key{}, Key{}, err
	}
	return signing, wg, nil
}

// NewEnrollmentRequest builds and signs a request with the device signing
// key, proving the device holds it.
func (s *DeviceSecrets) NewEnrollmentRequest(hostname string, now time.Time) (Envelope, *EnrollmentRequest, error) {
	return s.newEnrollmentRequest(hostname, now, nil)
}

func (s *DeviceSecrets) newEnrollmentRequest(hostname string, now time.Time, evidence json.RawMessage) (Envelope, *EnrollmentRequest, error) {
	signing, wg, err := s.PublicKeys()
	if err != nil {
		return Envelope{}, nil, err
	}
	req := &EnrollmentRequest{
		DeviceID:     s.DeviceID,
		SigningKey:   signing,
		WireGuardKey: wg,
		Hostname:     SanitizeHostname(hostname),
		CreatedAt:    roundTimestamp(now),
		TPMEvidence:  evidence,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encode enrollment request: %w", err)
	}
	env, err := Sign(s.SigningKey(), EnrollmentContext, payload)
	if err != nil {
		return Envelope{}, nil, err
	}
	return env, req, nil
}

// OpenEnrollmentRequest verifies a self-signed request. It proves the sender
// holds the signing key; it does not prove who the sender is, which is why
// the owner must compare fingerprints on both screens.
func OpenEnrollmentRequest(env Envelope, now time.Time) (*EnrollmentRequest, error) {
	if len(env.Payload) > maxEnrollmentChars {
		return nil, errors.New("enrollment request is too large")
	}
	var req EnrollmentRequest
	if err := decodeStrict(env.Payload, &req); err != nil {
		return nil, fmt.Errorf("decode enrollment request: %w", err)
	}
	if err := req.check(now); err != nil {
		return nil, err
	}
	if _, err := env.Verify(ed25519.PublicKey(req.SigningKey[:]), EnrollmentContext); err != nil {
		return nil, err
	}
	return &req, nil
}

// check validates the request fields and its age.
func (r *EnrollmentRequest) check(now time.Time) error {
	if !isValidID(r.DeviceID) || r.SigningKey.IsZero() || r.WireGuardKey.IsZero() || r.SigningKey == r.WireGuardKey {
		return errors.New("enrollment request has an invalid id or key")
	}
	if len(r.Hostname) > maxHostnameLen || (r.Hostname != "" && !isValidLabel(r.Hostname)) {
		return errors.New("enrollment request has an invalid hostname")
	}
	if err := validTPMEvidence(r.TPMEvidence); err != nil { // #611
		return err
	}
	if r.CreatedAt.IsZero() || now.Before(r.CreatedAt.Add(-clockSkew)) || now.Sub(r.CreatedAt) > EnrollmentMaxAge {
		return ErrEnrollmentExpired
	}
	return nil
}

// Fingerprint is shown on both the new device and the owner's device.
func (r *EnrollmentRequest) Fingerprint() string {
	id, _ := hex.DecodeString(r.DeviceID)
	return fingerprint([]byte("device"), id, r.SigningKey[:], r.WireGuardKey[:])
}

// EncodeEnrollment turns an envelope into a single copy-pasteable line.
func EncodeEnrollment(env Envelope) (string, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("encode enrollment request: %w", err)
	}
	return enrollmentPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeEnrollment parses a line produced by EncodeEnrollment.
func DecodeEnrollment(s string) (Envelope, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxEnrollmentChars*2 || !strings.HasPrefix(s, enrollmentPrefix) {
		return Envelope{}, errors.New("not an OpenScale enrollment request")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, enrollmentPrefix))
	if err != nil {
		return Envelope{}, errors.New("enrollment request is not valid base64")
	}
	return UnmarshalEnvelope(data)
}

// MarshalDeviceSecrets encodes the device key file.
func MarshalDeviceSecrets(s *DeviceSecrets) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode device key: %w", err)
	}
	return append(data, '\n'), nil
}

// UnmarshalDeviceSecrets strictly decodes and validates the device key file.
func UnmarshalDeviceSecrets(data []byte) (*DeviceSecrets, error) {
	if len(data) > MaxDeviceKeySize {
		return nil, errors.New("device key file is too large")
	}
	var s DeviceSecrets
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("decode device key: %w", err)
	}
	if err := s.validate(); err != nil {
		return &s, err
	}
	s.lockSecrets()
	return &s, nil
}

// SanitizeHostname lowercases a hostname and reduces it to a DNS label, or
// returns "" if nothing usable remains.
func SanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			b.WriteByte('-')
		}
		if b.Len() >= maxHostnameLen {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if !isValidLabel(out) {
		return ""
	}
	return out
}

func (s *DeviceSecrets) validate() error {
	switch {
	case s.Format != deviceKeyFormat:
		return fmt.Errorf("unsupported device key format %q", s.Format)
	case !isValidID(s.DeviceID):
		return errors.New("device key has an invalid device id")
	case len(s.SigningSeed) != ed25519.SeedSize:
		return errors.New("device key has an invalid signing key")
	case len(s.WireGuardPrivate) != 32:
		return errors.New("device key has an invalid wireguard key")
	}
	return nil
}

// clampX25519 applies the standard Curve25519 scalar clamping, matching
// keys produced by `wg genkey`.
func clampX25519(k []byte) {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}
