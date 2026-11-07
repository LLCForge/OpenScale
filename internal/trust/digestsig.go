package trust

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
)

// Digest signatures for keys held in hardware (#3, ADR-0123). A YubiKey's
// PIV applet (firmware 5.7+) signs with pure Ed25519 only: it implements
// neither Ed25519ctx nor Ed25519ph, and a 1 MiB document does not fit
// through its APDU buffer. Such a key therefore signs a short,
// domain-separated message instead of the payload:
//
//	"openscale/digest-signature/v1" 0x00 || len(context) || context || SHA-512(payload)
//
// The prefix keeps these messages apart from every other pure Ed25519 use of
// the same key, and the context keeps the usual separation between kinds of
// signed objects. Ed25519ctx signatures (RFC 8032 dom2 prefix) and these
// messages can never be confused with each other.
//
// Only root-signed documents (verifyRootSignature) and document approvals
// (multisig.go) accept this algorithm; Envelope.Verify, used for every other
// object, keeps accepting Ed25519ctx only.

// AlgEd25519Digest identifies a pure Ed25519 signature over the digest
// message above.
const AlgEd25519Digest = "ed25519-digest-v1"

// AlgHybridEd25519MLDSA65 is reserved for the hybrid Ed25519 + ML-DSA-65
// signature of #15 (ADR-0122). It is not implemented: no envelope with this
// value is accepted until a standard-library ML-DSA exists.
const AlgHybridEd25519MLDSA65 = "ed25519+ml-dsa-65"

const digestSignaturePrefix = "openscale/digest-signature/v1\x00"

// DigestSigner signs with an Ed25519 key that never leaves its device, such
// as a PIV slot on a hardware token. SignMessage returns a pure Ed25519
// signature over msg.
type DigestSigner interface {
	PublicKey() ed25519.PublicKey
	SignMessage(msg []byte) ([]byte, error)
}

// DigestMessage returns the message a DigestSigner signs for payload under
// context.
func DigestMessage(context string, payload []byte) ([]byte, error) {
	if err := checkContext(context); err != nil {
		return nil, err
	}
	sum := sha512.Sum512(payload)
	msg := make([]byte, 0, len(digestSignaturePrefix)+1+len(context)+len(sum))
	msg = append(msg, digestSignaturePrefix...)
	msg = append(msg, byte(len(context)))
	msg = append(msg, context...)
	msg = append(msg, sum[:]...)
	return msg, nil
}

// SignWithDigest signs payload under context with a hardware-held key. The
// signature is verified before it is returned, so a faulty token or a token
// holding a different key is caught here and not by every device.
func SignWithDigest(signer DigestSigner, context string, payload []byte) (Envelope, error) {
	if signer == nil {
		return Envelope{}, errors.New("no signer")
	}
	pub := signer.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		return Envelope{}, errors.New("invalid ed25519 public key")
	}
	msg, err := DigestMessage(context, payload)
	if err != nil {
		return Envelope{}, err
	}
	sig, err := signer.SignMessage(msg)
	if err != nil {
		return Envelope{}, fmt.Errorf("sign envelope: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return Envelope{}, errors.New("signer returned a signature that does not verify")
	}
	return Envelope{
		Context:   context,
		Payload:   append([]byte(nil), payload...),
		Signature: sig,
		Algorithm: AlgEd25519Digest,
	}, nil
}

// SignDocumentWith validates doc and signs it with a hardware-held root key.
// The payload is produced exactly as SignDocument produces it.
func SignDocumentWith(doc *Document, signer DigestSigner) (Envelope, error) {
	payload, err := DocumentPayload(doc)
	if err != nil {
		return Envelope{}, err
	}
	return SignWithDigest(signer, DocumentContext, payload)
}

// verifyDigest checks an AlgEd25519Digest signature.
func verifyDigest(pub ed25519.PublicKey, context string, payload, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key")
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	msg, err := DigestMessage(context, payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// verifyRootSignature is Envelope.Verify for root-signed documents: it also
// accepts a digest signature, so the root key may live on a PIV token.
// Both algorithms are Ed25519 with the same pinned key; neither is weaker.
func (e Envelope) verifyRootSignature(pub ed25519.PublicKey, context string) ([]byte, error) {
	if e.Algorithm != AlgEd25519Digest {
		return e.Verify(pub, context)
	}
	if e.Context != context {
		return nil, ErrWrongContext
	}
	if err := verifyDigest(pub, context, e.Payload, e.Signature); err != nil {
		return nil, err
	}
	return e.Payload, nil
}

// checkDecodeAlgorithm accepts the algorithms an envelope may carry on the
// wire. Which of them a verifier accepts is decided by the verifier.
func checkDecodeAlgorithm(alg string) error {
	if alg == AlgEd25519Digest {
		return nil
	}
	return checkAlgorithm(alg)
}

// DocumentAlgorithms lists the root signature algorithms accepted on
// network documents.
func DocumentAlgorithms() []string { return []string{AlgEd25519, AlgEd25519Digest} }
