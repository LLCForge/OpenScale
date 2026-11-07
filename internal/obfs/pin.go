package obfs

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SPKI pins (#613, #624): the SHA-256 of a certificate's
// SubjectPublicKeyInfo, written "sha256/<base64>" as in RFC 7469, or as 64
// hex digits.

// Pin is one SPKI SHA-256 pin.
type Pin [sha256.Size]byte

// MaxPins bounds a pin list.
const MaxPins = 8

// ErrPinMismatch means no certificate matched a pin.
var ErrPinMismatch = errors.New("sertifika sabitlenmiş anahtarla eşleşmedi")

// ParsePin reads "sha256/<base64>" or 64 hex digits.
func ParsePin(s string) (Pin, error) {
	var p Pin
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "sha256/"); ok {
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil || len(raw) != len(p) {
			return Pin{}, fmt.Errorf("SPKI sabitlemesi %q geçersiz: sha256/ ardından 32 baytlık base64 olmalı", s)
		}
		copy(p[:], raw)
		return p, nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(p) {
		return Pin{}, fmt.Errorf("SPKI sabitlemesi %q geçersiz: sha256/<base64> veya 64 onaltılık hane olmalı", s)
	}
	copy(p[:], raw)
	return p, nil
}

// ParsePins reads a list of pins.
func ParsePins(list []string) ([]Pin, error) {
	if len(list) > MaxPins {
		return nil, fmt.Errorf("en fazla %d SPKI sabitlemesi verilebilir", MaxPins)
	}
	out := make([]Pin, 0, len(list))
	for _, s := range list {
		p, err := ParsePin(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// String formats the pin as "sha256/<base64>".
func (p Pin) String() string { return "sha256/" + base64.StdEncoding.EncodeToString(p[:]) }

// SPKIPin returns the pin of a certificate.
func SPKIPin(c *x509.Certificate) Pin { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

func matches(pins []Pin, c *x509.Certificate) bool {
	got := SPKIPin(c)
	ok := 0
	for _, p := range pins {
		ok |= subtle.ConstantTimeCompare(p[:], got[:])
	}
	return ok == 1
}

// RequirePins adds a pin check to cfg on top of normal certificate
// verification: one certificate of a verified chain must match a pin.
// cfg must not skip verification.
func RequirePins(cfg *tls.Config, pins []Pin) error {
	if len(pins) == 0 {
		return nil
	}
	if cfg.InsecureSkipVerify {
		return errors.New("obfs: pins need verification on")
	}
	pins = append([]Pin(nil), pins...)
	prev := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if prev != nil {
			if err := prev(cs); err != nil {
				return err
			}
		}
		for _, chain := range cs.VerifiedChains {
			for _, c := range chain {
				if matches(pins, c) {
					return nil
				}
			}
		}
		return ErrPinMismatch
	}
	return nil
}

// PinOnlyConfig returns client settings that trust exactly the pinned
// keys, for a self-signed server certificate: the leaf's key must match a
// pin and the leaf must be within its validity period. No CA is consulted.
func PinOnlyConfig(serverName string, pins []Pin, now func() time.Time) (*tls.Config, error) {
	if len(pins) == 0 {
		return nil, errors.New("obfs: at least one pin is needed")
	}
	if now == nil {
		now = time.Now
	}
	pins = append([]Pin(nil), pins...)
	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		// The chain is checked below against the pins instead of CAs.
		InsecureSkipVerify: true, //nolint:gosec // pinned below (VerifyPeerCertificate)
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPinMismatch
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			t := now()
			if t.Before(leaf.NotBefore) || t.After(leaf.NotAfter) {
				return errors.New("sabitlenmiş sertifikanın süresi geçerli değil")
			}
			if !matches(pins, leaf) {
				return ErrPinMismatch
			}
			return nil
		},
	}, nil
}
