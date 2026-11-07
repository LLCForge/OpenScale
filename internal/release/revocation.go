package release

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

const (
	revocationsFormat = "openscale-release-revocations-v1"
	// MaxRevokedKeys bounds the revocation list.
	MaxRevokedKeys = 1024
)

// RevokedKey is a signing key that must no longer be trusted. Every release
// it signed is rejected, whatever its date: a leaked key can backdate.
type RevokedKey struct {
	SigningKey PublicKey `json:"signing_key"`
	Reason     string    `json:"reason,omitempty"`
}

// Revocations is a root-signed list of revoked signing keys. Sequence grows
// with every new list so an installer can refuse an older list; the updater
// does so against the newest list it stored (updater/revocations.go).
type Revocations struct {
	Format   string       `json:"format"`
	RootKey  PublicKey    `json:"root_key"`
	Sequence uint64       `json:"sequence"`
	Issued   time.Time    `json:"issued"`
	Revoked  []RevokedKey `json:"revoked"`

	signed []byte // the verified signed form (VerifyRevocations)
}

// Signed returns the signed list this value was verified from, or nil for a
// list that did not come from VerifyRevocations.
func (r *Revocations) Signed() []byte { return slices.Clone(r.signed) }

// IsRevoked reports whether key is on the list.
func (r *Revocations) IsRevoked(key PublicKey) bool {
	for _, k := range r.Revoked {
		if k.SigningKey.Equal(key) {
			return true
		}
	}
	return false
}

// SignRevocations signs a revocation list with the root key. RootKey and
// Format are filled in from the key.
func SignRevocations(rootPriv ed25519.PrivateKey, r Revocations) ([]byte, error) {
	if len(rootPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid root private key")
	}
	root, err := PublicKeyFrom(rootPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	r.Format = revocationsFormat
	r.RootKey = root
	r.Issued = r.Issued.UTC().Truncate(time.Second)
	if r.Revoked == nil {
		r.Revoked = []RevokedKey{}
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	payload, err := marshalIndent(r)
	if err != nil {
		return nil, fmt.Errorf("encode revocations: %w", err)
	}
	env, err := sign(rootPriv, ContextRevocations, payload)
	if err != nil {
		return nil, err
	}
	return marshalIndent(env)
}

// VerifyRevocations checks a signed revocation list against the root key.
func VerifyRevocations(root PublicKey, data []byte) (*Revocations, error) {
	if len(data) > MaxRevocationsSize {
		return nil, errors.New("revocation list is too large")
	}
	var env Envelope
	if err := decodeStrict(data, &env); err != nil {
		return nil, fmt.Errorf("decode revocation list: %w", err)
	}
	payload, err := env.verify(root, ContextRevocations)
	if err != nil {
		return nil, fmt.Errorf("revocation list: %w", err)
	}
	var r Revocations
	if err := decodeStrict(payload, &r); err != nil {
		return nil, fmt.Errorf("decode revocation list: %w", err)
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	if !r.RootKey.Equal(root) {
		return nil, errors.New("revocation list names a different root key")
	}
	r.signed = slices.Clone(data)
	return &r, nil
}

func (r *Revocations) validate() error {
	switch {
	case r.Format != revocationsFormat:
		return fmt.Errorf("unsupported revocation list format %q", r.Format)
	case r.RootKey.IsZero():
		return errors.New("revocation list root key is missing")
	case r.Issued.IsZero():
		return errors.New("revocation list has no issue time")
	case len(r.Revoked) > MaxRevokedKeys:
		return fmt.Errorf("revocation list exceeds %d keys", MaxRevokedKeys)
	}
	for i, k := range r.Revoked {
		if k.SigningKey.IsZero() {
			return fmt.Errorf("revoked key %d is missing", i)
		}
		if k.SigningKey.Equal(r.RootKey) {
			return errors.New("the root key cannot revoke itself; replace it instead")
		}
		if len(k.Reason) > maxCommentLength || !utf8.ValidString(k.Reason) || hasControl(k.Reason) {
			return fmt.Errorf("revoked key %d: reason is too long or not printable", i)
		}
	}
	return nil
}
