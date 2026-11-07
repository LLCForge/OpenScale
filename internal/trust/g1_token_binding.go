package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Token binding (#601, ADR-0173). A grant may record which physical token
// holds the administrator key: its kind, serial number and, for PIV, the
// token's attestation certificate for the slot together with the token's
// attestation (F9) certificate that signed it. A key generated inside a
// YubiKey's PIV applet cannot be exported, so a valid attestation proves
// that every signature by this key comes from that one token; a cloned or
// imported key has no such certificate. The root signs the binding as part
// of the grant after checking the chain up to the Yubico root certificate
// the owner supplied; members re-check the leaf against the key and the
// intermediate (no vendor certificate is embedded in OpenScale).
//
// OpenPGP cards offer no comparable attestation through internal/piv, so an
// "openpgp" binding records the serial only. That is an inventory record,
// not a proof: the ADR says so.

// Token kinds of a binding.
const (
	TokenKindPIV     = "piv"
	TokenKindOpenPGP = "openpgp"
)

// maxAttestationCert bounds each certificate of a binding.
const maxAttestationCert = 4096

// oidYubicoSerial is the Yubico attestation extension holding the serial.
var oidYubicoSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}

// ErrTokenBinding is returned for an invalid token binding.
var ErrTokenBinding = errors.New("invalid token binding")

// TokenBinding ties a key to one hardware token.
type TokenBinding struct {
	Kind   string `json:"kind"`
	Serial uint32 `json:"serial"`
	// Attestation is the DER certificate the token issued for the key's
	// slot (PIV ATTEST); Intermediate is the token's DER attestation
	// certificate (slot F9) that signed it.
	Attestation  []byte `json:"attestation,omitempty"`
	Intermediate []byte `json:"intermediate,omitempty"`
}

// Validate checks the binding and that its attestation names key.
func (b *TokenBinding) Validate(key Key) error {
	if b == nil {
		return nil
	}
	if b.Serial == 0 {
		return fmt.Errorf("%w: serial is missing", ErrTokenBinding)
	}
	switch b.Kind {
	case TokenKindOpenPGP:
		if len(b.Attestation) > 0 || len(b.Intermediate) > 0 {
			return fmt.Errorf("%w: openpgp bindings carry no attestation", ErrTokenBinding)
		}
		return nil
	case TokenKindPIV:
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrTokenBinding, b.Kind)
	}
	if len(b.Attestation) == 0 || len(b.Intermediate) == 0 {
		return fmt.Errorf("%w: a piv binding needs the attestation and intermediate certificates", ErrTokenBinding)
	}
	if len(b.Attestation) > maxAttestationCert || len(b.Intermediate) > maxAttestationCert {
		return fmt.Errorf("%w: certificate is too large", ErrTokenBinding)
	}
	leaf, err := x509.ParseCertificate(b.Attestation)
	if err != nil {
		return fmt.Errorf("%w: attestation: %v", ErrTokenBinding, err)
	}
	inter, err := x509.ParseCertificate(b.Intermediate)
	if err != nil {
		return fmt.Errorf("%w: intermediate: %v", ErrTokenBinding, err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key[:]) {
		return fmt.Errorf("%w: the attestation names another key", ErrTokenBinding)
	}
	// The F9 certificate need not be marked as a CA; only its signature
	// over the leaf matters here.
	if err := inter.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return fmt.Errorf("%w: attestation is not signed by the intermediate: %v", ErrTokenBinding, err)
	}
	serial, found, err := attestationSerial(leaf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenBinding, err)
	}
	if found && serial != b.Serial {
		return fmt.Errorf("%w: serial %d does not match the attestation (%d)", ErrTokenBinding, b.Serial, serial)
	}
	return nil
}

// CheckChain checks that the intermediate is signed by the vendor root
// certificate (DER), as the owner does once before signing a grant.
func (b *TokenBinding) CheckChain(rootDER []byte) error {
	if b == nil || b.Kind != TokenKindPIV {
		return fmt.Errorf("%w: only piv bindings have a chain", ErrTokenBinding)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return fmt.Errorf("%w: root: %v", ErrTokenBinding, err)
	}
	inter, err := x509.ParseCertificate(b.Intermediate)
	if err != nil {
		return fmt.Errorf("%w: intermediate: %v", ErrTokenBinding, err)
	}
	if err := root.CheckSignature(inter.SignatureAlgorithm, inter.RawTBSCertificate, inter.Signature); err != nil {
		return fmt.Errorf("%w: intermediate is not signed by the root: %v", ErrTokenBinding, err)
	}
	return nil
}

// AttestationSerial returns the serial number in a Yubico attestation
// certificate (DER), if present.
func AttestationSerial(der []byte) (uint32, bool, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, false, err
	}
	return attestationSerial(c)
}

func attestationSerial(c *x509.Certificate) (uint32, bool, error) {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidYubicoSerial) {
			continue
		}
		var n int64
		rest, err := asn1.Unmarshal(ext.Value, &n)
		if err != nil || len(rest) != 0 || n <= 0 || n > 0xFFFFFFFF {
			return 0, false, errors.New("malformed serial extension")
		}
		return uint32(n), true, nil
	}
	return 0, false, nil
}
