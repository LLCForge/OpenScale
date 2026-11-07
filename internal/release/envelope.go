// Package release implements OpenScale release signing (ADR-0022): an
// offline Ed25519 release root key certifies short-lived signing keys, and a
// signing key signs the release manifest (version, build, size and SHA-256 of
// every artifact). Verifiers take the release root public key as a parameter;
// programs embed it at build time.
//
// Every signed object is an Envelope: the exact payload bytes are signed with
// Ed25519ctx (RFC 8032) under a per-object context, verified before they are
// parsed, and never re-encoded.
package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Signature contexts. A signature made for one kind of object can never be
// replayed as another, and none of them can be confused with the network
// document contexts of internal/trust.
const (
	ContextCertificate = "openscale/release-signing-certificate/v1"
	ContextManifest    = "openscale/release-manifest/v1"
	ContextRevocations = "openscale/release-revocations/v1"
)

// Size limits for untrusted input.
const (
	maxEnvelopePayload = 512 << 10
	// MaxSignedReleaseSize bounds a signed release file.
	MaxSignedReleaseSize = 2 << 20
	// MaxRevocationsSize bounds a signed revocation list.
	MaxRevocationsSize = 1 << 20
)

// ErrBadSignature is returned when a signature does not verify.
var ErrBadSignature = errors.New("release signature verification failed")

// ErrWrongContext is returned when an envelope was signed for another purpose.
var ErrWrongContext = errors.New("release envelope context mismatch")

// Envelope carries a payload and an Ed25519ctx signature over its exact bytes.
type Envelope struct {
	Context   string `json:"context"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func sign(priv ed25519.PrivateKey, context string, payload []byte) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid ed25519 private key")
	}
	if len(payload) > maxEnvelopePayload {
		return Envelope{}, errors.New("payload is too large")
	}
	sig, err := priv.Sign(nil, payload, &ed25519.Options{Context: context})
	if err != nil {
		return Envelope{}, fmt.Errorf("sign: %w", err)
	}
	return Envelope{
		Context:   context,
		Payload:   append([]byte(nil), payload...),
		Signature: sig,
	}, nil
}

// verify checks the signature with pub under context and returns the payload.
func (e Envelope) verify(pub PublicKey, context string) ([]byte, error) {
	if pub.IsZero() {
		return nil, errors.New("public key is missing")
	}
	if e.Context != context {
		return nil, ErrWrongContext
	}
	if len(e.Payload) == 0 || len(e.Payload) > maxEnvelopePayload {
		return nil, errors.New("envelope payload is empty or too large")
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	if err := ed25519.VerifyWithOptions(ed25519.PublicKey(pub[:]), e.Payload, e.Signature, &ed25519.Options{Context: context}); err != nil {
		return nil, ErrBadSignature
	}
	return e.Payload, nil
}

// decodeStrict decodes exactly one JSON value, rejecting unknown fields and
// trailing data, so two different files can never verify as the same object.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// MarshalEnvelope encodes an envelope (for example a certificate file).
func MarshalEnvelope(e Envelope) ([]byte, error) {
	return marshalIndent(e)
}

// UnmarshalEnvelope strictly decodes an envelope. It is untrusted until it
// is verified (VerifyCertificate, SignManifest).
func UnmarshalEnvelope(data []byte) (Envelope, error) {
	var e Envelope
	if len(data) > MaxSignedReleaseSize {
		return e, errors.New("envelope is too large")
	}
	if err := decodeStrict(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	return e, nil
}

func marshalIndent(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
