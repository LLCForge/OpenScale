package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxEnvelopeSize bounds an encoded envelope (payload plus base64 overhead).
const MaxEnvelopeSize = 2 << 20

// ErrBadSignature is returned when an envelope signature does not verify.
var ErrBadSignature = errors.New("signature verification failed")

// ErrWrongContext is returned when an envelope was signed for another
// purpose, for example an enrollment request presented as a document.
var ErrWrongContext = errors.New("envelope context mismatch")

// Envelope carries a payload and an Ed25519ctx signature over its exact
// bytes. The payload is verified before it is parsed, so no canonical
// re-encoding is ever needed.
type Envelope struct {
	Context   string `json:"context"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
	// Algorithm names the signature algorithm (#14, ADR-0061). Empty means
	// Ed25519ctx; Sign leaves it empty so versions without the field still
	// read new envelopes.
	Algorithm string `json:"algorithm,omitempty"`
	// Cosignatures are approvals of a network document (#5, ADR-0121),
	// outside the root signature's scope. Omitted when empty.
	Cosignatures []Cosignature `json:"cosignatures,omitempty"`
	// Admin carries a delegated administrator's grant and base document;
	// Signature is then the administrator's (ADR-0172). SensitiveApprovals
	// approve access to sensitive devices (ADR-0174). Both omitted when
	// empty; envelopes without them encode exactly as before.
	Admin              *AdminProof   `json:"admin,omitempty"`
	SensitiveApprovals []Cosignature `json:"sensitive_approvals,omitempty"`
}

// Sign signs payload with priv under context. The context gives domain
// separation (RFC 8032 Ed25519ctx): a signature for one kind of object can
// never be replayed as another.
func Sign(priv ed25519.PrivateKey, context string, payload []byte) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid ed25519 private key")
	}
	if err := checkContext(context); err != nil {
		return Envelope{}, err
	}
	sig, err := priv.Sign(nil, payload, &ed25519.Options{Context: context})
	if err != nil {
		return Envelope{}, fmt.Errorf("sign envelope: %w", err)
	}
	return Envelope{
		Context:   context,
		Payload:   append([]byte(nil), payload...),
		Signature: sig,
	}, nil
}

// Verify checks the signature with pub and context and returns the payload.
func (e Envelope) Verify(pub ed25519.PublicKey, context string) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key")
	}
	if err := checkAlgorithm(e.Algorithm); err != nil {
		return nil, err
	}
	if e.Context != context {
		return nil, ErrWrongContext
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	if err := ed25519.VerifyWithOptions(pub, e.Payload, e.Signature, &ed25519.Options{Context: context}); err != nil {
		return nil, ErrBadSignature
	}
	return e.Payload, nil
}

// MarshalEnvelope encodes an envelope as JSON.
func MarshalEnvelope(e Envelope) ([]byte, error) {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	if len(data) > MaxEnvelopeSize {
		return nil, errors.New("envelope is too large")
	}
	return append(data, '\n'), nil
}

// UnmarshalEnvelope strictly decodes an envelope. The result is untrusted
// until Verify succeeds.
func UnmarshalEnvelope(data []byte) (Envelope, error) {
	if len(data) > MaxEnvelopeSize {
		return Envelope{}, errors.New("envelope is too large")
	}
	var e Envelope
	if err := decodeStrict(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	// Digest signatures (ADR-0123) are decoded; only the document verifier
	// accepts them.
	if err := checkDecodeAlgorithm(e.Algorithm); err != nil {
		return Envelope{}, err
	}
	if err := checkCosignatures(e.Cosignatures); err != nil { // ADR-0121
		return Envelope{}, err
	}
	if err := checkG1Envelope(e); err != nil { // ADR-0172, ADR-0174
		return Envelope{}, err
	}
	return e, nil
}

func checkContext(context string) error {
	if context == "" || len(context) > 255 {
		return errors.New("signature context must be 1-255 bytes")
	}
	return nil
}
