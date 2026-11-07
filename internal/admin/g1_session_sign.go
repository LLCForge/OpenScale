package admin

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Signing for a session held by another process (ADR-0223). The tray opens
// the token session in the user's process (the PIN never reaches the
// service); the panel in the service builds the plan and sends the exact
// payload it wants signed. The session signs only a network document for
// its own network, under the context of its role, so a caller of the local
// channel cannot use the token to sign anything else.

// ErrSignRequest is returned for a payload the session refuses to sign.
var ErrSignRequest = errors.New("the token session refuses this signing request")

// SignedPayload is the answer to SignPayload.
type SignedPayload struct {
	Signature []byte
	// Version and NetworkID come from the signed document, for the log
	// and the user's confirmation.
	Version   uint64
	NetworkID string
}

// DescribePayload checks payload as SignPayload would and returns the
// document's version, so the tray can ask the user before the token is
// touched. It does not use the token.
func (s *TokenSession) DescribePayload(context string, payload []byte, networkID string) (uint64, error) {
	s.mu.Lock()
	role := s.role
	s.mu.Unlock()
	doc, err := checkSignPayload(role, context, payload, networkID)
	if err != nil {
		return 0, err
	}
	return doc.Version, nil
}

// SignPayload signs payload (a network document) under context with the
// session's token and returns a signature that verifies under the token's
// key. networkID must be the network the session was opened for.
func (s *TokenSession) SignPayload(context string, payload []byte, networkID string) (SignedPayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := checkSignPayload(s.role, context, payload, networkID)
	if err != nil {
		return SignedPayload{}, err
	}
	signer, err := s.use(s.role)
	if err != nil {
		return SignedPayload{}, err
	}
	msg, err := trust.DigestMessage(context, payload)
	if err != nil {
		return SignedPayload{}, err
	}
	sig, err := signer.SignMessage(msg)
	if err != nil {
		return SignedPayload{}, fmt.Errorf("token signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(signer.PublicKey(), msg, sig) {
		return SignedPayload{}, errors.New("the token returned a signature that does not verify")
	}
	return SignedPayload{Signature: sig, Version: doc.Version, NetworkID: doc.NetworkID}, nil
}

// checkSignPayload accepts only a valid network document of networkID,
// under the context that belongs to role.
func checkSignPayload(role, context string, payload []byte, networkID string) (*trust.Document, error) {
	want := ""
	switch role {
	case SessionRoot:
		want = trust.DocumentContext
	case SessionAdmin:
		want = trust.AdminDocumentContext
	}
	if want == "" || context != want {
		return nil, fmt.Errorf("%w: context %q", ErrSignRequest, context)
	}
	if len(payload) == 0 || len(payload) > trust.MaxDocumentSize {
		return nil, fmt.Errorf("%w: payload size", ErrSignRequest)
	}
	var doc trust.Document
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("%w: not a network document", ErrSignRequest)
	}
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignRequest, err)
	}
	if networkID == "" || doc.NetworkID != networkID {
		return nil, fmt.Errorf("%w: another network", ErrSignRequest)
	}
	return &doc, nil
}

// PublicKey returns the token's public key (also after the session ended).
func (s *TokenSession) PublicKey() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append(ed25519.PublicKey(nil), s.signer.PublicKey()...)
}

// KeyFingerprint names a token key for display: the first 8 bytes of
// SHA-256 of the public key, in hex. The panel shows it instead of a
// serial number, which the PIV and OpenPGP paths of this package do not
// read.
func KeyFingerprint(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// IdleUntil is when the session ends if it is not used again (never after
// its fixed end).
func (s *TokenSession) IdleUntil() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.lastUse.Add(s.opts.Idle)
	if s.ends.Before(t) {
		t = s.ends
	}
	return t
}

// RootPublicKey returns the network's root public key (public data; the
// panel checks a token signer against it before relaying a signature).
func (n *Network) RootPublicKey() ed25519.PublicKey {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sealed.RootPublicKey()
}
