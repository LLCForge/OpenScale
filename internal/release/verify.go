package release

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// DefaultClockSkew is how far in the future a manifest's creation time may
// be relative to the verifier's clock.
const DefaultClockSkew = 5 * time.Minute

// ErrRevoked is returned when the signing key is on the revocation list.
var ErrRevoked = errors.New("release signing key has been revoked")

// ErrCertificateExpired is returned when the manifest was not signed inside
// the certificate's validity period, or RequireValidNow is set and the
// certificate is no longer valid.
var ErrCertificateExpired = errors.New("release signing certificate is not valid at that time")

// SignManifest signs m with the signing key certified by certEnv and returns
// the encoded SignedRelease. root is the release root public key; the
// certificate is verified against it so a release can never be signed with
// a key the verifiers will reject.
func SignManifest(signingPriv ed25519.PrivateKey, certEnv Envelope, root PublicKey, m Manifest, now time.Time) ([]byte, error) {
	if len(signingPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing private key")
	}
	cert, err := VerifyCertificate(root, certEnv)
	if err != nil {
		return nil, err
	}
	pub, err := PublicKeyFrom(signingPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if !pub.Equal(cert.SigningKey) {
		return nil, errors.New("the certificate is for a different signing key")
	}
	now = now.UTC().Truncate(time.Second)
	if !cert.ValidAt(now) {
		return nil, fmt.Errorf("%w (valid %s - %s)", ErrCertificateExpired, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	m.Created = now
	if err := m.validate(); err != nil {
		return nil, err
	}
	payload, err := marshalIndent(m)
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	env, err := sign(signingPriv, ContextManifest, payload)
	if err != nil {
		return nil, err
	}
	out, err := marshalIndent(SignedRelease{Format: signedReleaseFormat, Certificate: certEnv, Manifest: env})
	if err != nil {
		return nil, fmt.Errorf("encode signed release: %w", err)
	}
	if len(out) > MaxSignedReleaseSize {
		return nil, errors.New("signed release is too large")
	}
	return out, nil
}

// VerifyOptions controls Verify.
type VerifyOptions struct {
	// Now is the verifier's clock. Required.
	Now time.Time
	// Revocations, if not nil, must come from VerifyRevocations with the
	// same root key. Installers must always pass the newest list they know
	// (updater.Verify does); nil only means no list exists for this root.
	Revocations *Revocations
	// RequireValidNow additionally requires the certificate to be valid at
	// Now, not only when the manifest was signed.
	RequireValidNow bool
	// ClockSkew overrides DefaultClockSkew when positive.
	ClockSkew time.Duration
}

// Verified is a release whose signature chain has been checked.
type Verified struct {
	Manifest    Manifest
	Certificate Certificate
}

// Verify checks a signed release against the release root public key:
// root -> certificate -> signing key -> manifest. The manifest must have
// been signed inside the certificate's validity period and not after
// opts.Now (plus clock skew), and the signing key must not be revoked.
func Verify(root PublicKey, data []byte, opts VerifyOptions) (*Verified, error) {
	if root.IsZero() {
		return nil, errors.New("release root public key is missing")
	}
	if opts.Now.IsZero() {
		return nil, errors.New("verification time is missing")
	}
	if len(data) > MaxSignedReleaseSize {
		return nil, errors.New("signed release is too large")
	}
	var sr SignedRelease
	if err := decodeStrict(data, &sr); err != nil {
		return nil, fmt.Errorf("decode signed release: %w", err)
	}
	if sr.Format != signedReleaseFormat {
		return nil, fmt.Errorf("unsupported signed release format %q", sr.Format)
	}
	cert, err := VerifyCertificate(root, sr.Certificate)
	if err != nil {
		return nil, err
	}
	if opts.Revocations != nil {
		if !opts.Revocations.RootKey.Equal(root) {
			return nil, errors.New("revocation list belongs to a different root key")
		}
		if opts.Revocations.IsRevoked(cert.SigningKey) {
			return nil, ErrRevoked
		}
	}
	payload, err := sr.Manifest.verify(cert.SigningKey, ContextManifest)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var m Manifest
	if err := decodeStrict(payload, &m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if m.Created.After(opts.Now.Add(skew)) {
		return nil, errors.New("manifest creation time is in the future")
	}
	if !cert.ValidAt(m.Created) {
		return nil, fmt.Errorf("%w: manifest signed %s", ErrCertificateExpired, m.Created.Format(time.RFC3339))
	}
	if opts.RequireValidNow && !cert.ValidAt(opts.Now) {
		return nil, ErrCertificateExpired
	}
	return &Verified{Manifest: m, Certificate: *cert}, nil
}
