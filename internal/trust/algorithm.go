package trust

import "errors"

// Cryptographic agility (#14, ADR-0061). Every envelope may name its
// signature algorithm. Before the field existed every envelope was
// Ed25519ctx, so a missing field means Ed25519ctx and old documents stay
// valid. Any other value is rejected while decoding and again in Verify:
// an envelope never selects an algorithm the verifier did not expect.

// AlgEd25519 identifies Ed25519ctx (RFC 8032) signatures.
const AlgEd25519 = "ed25519"

// ErrUnsupportedAlgorithm is returned for an envelope that names a
// signature algorithm this version does not implement.
var ErrUnsupportedAlgorithm = errors.New("unsupported signature algorithm")

// SupportedAlgorithms lists the signature algorithms this version accepts.
func SupportedAlgorithms() []string { return []string{AlgEd25519} }

// checkAlgorithm accepts only algorithms this version implements.
func checkAlgorithm(alg string) error {
	switch alg {
	case "", AlgEd25519:
		return nil
	}
	return ErrUnsupportedAlgorithm
}

// EffectiveAlgorithm returns the algorithm an envelope is verified with.
func (e Envelope) EffectiveAlgorithm() string {
	if e.Algorithm == "" {
		return AlgEd25519
	}
	return e.Algorithm
}
