package release

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	certificateFormat = "openscale-release-certificate-v1"

	// PurposeManifest is the only purpose a signing key can be certified for.
	PurposeManifest = "release-manifest"

	// DefaultCertificateValidity is the validity of a new signing key.
	DefaultCertificateValidity = 90 * 24 * time.Hour
	// MaxCertificateValidity keeps signing keys short-lived.
	MaxCertificateValidity = 180 * 24 * time.Hour

	maxCommentLength = 200
)

// Certificate is signed by the release root key and authorizes SigningKey
// to sign release manifests between NotBefore and NotAfter.
type Certificate struct {
	Format     string    `json:"format"`
	RootKey    PublicKey `json:"root_key"`
	SigningKey PublicKey `json:"signing_key"`
	Purpose    string    `json:"purpose"`
	Serial     uint64    `json:"serial"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Comment    string    `json:"comment,omitempty"`
}

// CertificateRequest holds the fields chosen by the issuer.
type CertificateRequest struct {
	SigningKey PublicKey
	Serial     uint64
	NotBefore  time.Time
	Validity   time.Duration
	Comment    string
}

// IssueCertificate signs a certificate for req.SigningKey with the root key.
func IssueCertificate(rootPriv ed25519.PrivateKey, req CertificateRequest) (Envelope, *Certificate, error) {
	if len(rootPriv) != ed25519.PrivateKeySize {
		return Envelope{}, nil, errors.New("invalid root private key")
	}
	root, err := PublicKeyFrom(rootPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return Envelope{}, nil, err
	}
	nb := req.NotBefore.UTC().Truncate(time.Second)
	c := &Certificate{
		Format:     certificateFormat,
		RootKey:    root,
		SigningKey: req.SigningKey,
		Purpose:    PurposeManifest,
		Serial:     req.Serial,
		NotBefore:  nb,
		NotAfter:   nb.Add(req.Validity),
		Comment:    req.Comment,
	}
	if err := c.validate(); err != nil {
		return Envelope{}, nil, err
	}
	payload, err := marshalIndent(c)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encode certificate: %w", err)
	}
	env, err := sign(rootPriv, ContextCertificate, payload)
	if err != nil {
		return Envelope{}, nil, err
	}
	return env, c, nil
}

// VerifyCertificate checks env against the release root key and returns the
// certificate. It does not check the validity period; see ValidAt.
func VerifyCertificate(root PublicKey, env Envelope) (*Certificate, error) {
	payload, err := env.verify(root, ContextCertificate)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	var c Certificate
	if err := decodeStrict(payload, &c); err != nil {
		return nil, fmt.Errorf("decode certificate: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if !c.RootKey.Equal(root) {
		return nil, errors.New("certificate names a different root key")
	}
	return &c, nil
}

// ValidAt reports whether t is inside [NotBefore, NotAfter].
func (c *Certificate) ValidAt(t time.Time) bool {
	return !t.Before(c.NotBefore) && !t.After(c.NotAfter)
}

func (c *Certificate) validate() error {
	switch {
	case c.Format != certificateFormat:
		return fmt.Errorf("unsupported certificate format %q", c.Format)
	case c.RootKey.IsZero() || c.SigningKey.IsZero():
		return errors.New("certificate key is missing")
	case c.RootKey.Equal(c.SigningKey):
		return errors.New("the root key must not be its own signing key")
	case c.Purpose != PurposeManifest:
		return fmt.Errorf("unsupported certificate purpose %q", c.Purpose)
	case c.NotBefore.IsZero() || !c.NotAfter.After(c.NotBefore):
		return errors.New("certificate validity period is empty")
	case c.NotAfter.Sub(c.NotBefore) > MaxCertificateValidity:
		return fmt.Errorf("certificate validity exceeds %d days", int(MaxCertificateValidity/(24*time.Hour)))
	case len(c.Comment) > maxCommentLength || !utf8.ValidString(c.Comment) || hasControl(c.Comment):
		return errors.New("certificate comment is too long or not printable")
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
