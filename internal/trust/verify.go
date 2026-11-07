package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// clockSkew tolerates small clock differences between devices.
const clockSkew = 5 * time.Minute

// Errors returned when a document is rejected.
var (
	ErrRollback     = errors.New("document version is older than the last accepted version")
	ErrEquivocation = errors.New("two different documents carry the same version")
	ErrExpired      = errors.New("document has expired")
	ErrNotYetValid  = errors.New("document is not valid yet")
	ErrWrongNetwork = errors.New("document belongs to another network")
	ErrTooLarge     = errors.New("document is too large")
)

// Anchor is what a device pins when it joins: the root key and network ID.
type Anchor struct {
	RootKey   ed25519.PublicKey
	NetworkID string
}

// SignDocument validates doc and signs it with the root key.
func SignDocument(doc *Document, root ed25519.PrivateKey) (Envelope, error) {
	payload, err := DocumentPayload(doc)
	if err != nil {
		return Envelope{}, err
	}
	return Sign(root, DocumentContext, payload)
}

// DocumentPayload validates doc and returns the exact bytes a root key
// signs. SignDocument and SignDocumentWith (hardware key, ADR-0123) share it.
func DocumentPayload(doc *Document) ([]byte, error) {
	normalizeSlices(doc)
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("invalid document: %w", err)
	}
	// Policy tests run before every signature; a failing test refuses it
	// (F-076, ADR-0120).
	if err := doc.CheckPolicyTests(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode document: %w", err)
	}
	if len(payload) > MaxDocumentSize {
		return nil, ErrTooLarge
	}
	return payload, nil
}

// OpenDocument verifies env against anchor and returns the document if it
// is authentic, well-formed, for the pinned network, not older than
// minVersion and valid at now.
func OpenDocument(env Envelope, anchor Anchor, minVersion uint64, now time.Time) (*Document, error) {
	doc, _, err := openDocument(env, anchor, minVersion, now)
	return doc, err
}

// VerifyDocumentSignature checks the signature and structure of a document
// without time or rollback checks. It is meant for the owner's own tooling,
// which must be able to load an expired document in order to renew it.
// Devices must use OpenDocument or State.Accept instead.
func VerifyDocumentSignature(env Envelope, root ed25519.PublicKey) (*Document, error) {
	doc, _, err := verifyDocument(env, root)
	return doc, err
}

func verifyDocument(env Envelope, root ed25519.PublicKey) (*Document, [32]byte, error) {
	doc, digest, _, err := verifyDocumentFull(env, root)
	return doc, digest, err
}

// verifyDocumentFull is verifyDocument that also accepts a delegated
// administrator's signature (ADR-0172) and returns what it verified.
func verifyDocumentFull(env Envelope, root ed25519.PublicKey) (*Document, [32]byte, *AdminVerified, error) {
	if len(env.Payload) > MaxDocumentSize {
		return nil, [32]byte{}, nil, ErrTooLarge
	}
	if env.Admin != nil {
		doc, adm, err := verifyAdminDocument(env, root)
		if err != nil {
			return nil, [32]byte{}, nil, err
		}
		return doc, sha256.Sum256(env.Payload), adm, nil
	}
	doc, digest, err := verifyRootDocument(env, root)
	return doc, digest, nil, err
}

func verifyRootDocument(env Envelope, root ed25519.PublicKey) (*Document, [32]byte, error) {
	if len(env.Payload) > MaxDocumentSize {
		return nil, [32]byte{}, ErrTooLarge
	}
	payload, err := env.verifyRootSignature(root, DocumentContext) // Ed25519ctx or PIV digest (ADR-0123)
	if err != nil {
		return nil, [32]byte{}, err
	}
	var doc Document
	if err := decodeStrict(payload, &doc); err != nil {
		return nil, [32]byte{}, fmt.Errorf("decode document: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, [32]byte{}, fmt.Errorf("invalid document: %w", err)
	}
	return &doc, sha256.Sum256(payload), nil
}

func openDocument(env Envelope, anchor Anchor, minVersion uint64, now time.Time) (*Document, [32]byte, error) {
	doc, digest, _, err := openDocumentFull(env, anchor, minVersion, now)
	return doc, digest, err
}

func openDocumentFull(env Envelope, anchor Anchor, minVersion uint64, now time.Time) (*Document, [32]byte, *AdminVerified, error) {
	doc, digest, adm, err := verifyDocumentFull(env, anchor.RootKey)
	if err != nil {
		return nil, [32]byte{}, nil, err
	}
	if subtle.ConstantTimeCompare([]byte(doc.NetworkID), []byte(anchor.NetworkID)) != 1 {
		return nil, [32]byte{}, nil, ErrWrongNetwork
	}
	if doc.Version < minVersion {
		return nil, [32]byte{}, nil, ErrRollback
	}
	if now.Before(doc.IssuedAt.Add(-clockSkew)) {
		return nil, [32]byte{}, nil, ErrNotYetValid
	}
	if !now.Before(doc.ExpiresAt) {
		return nil, [32]byte{}, nil, ErrExpired
	}
	return doc, digest, adm, nil
}

// State is what a device persists between document updates to defend
// against rollback and equivocation by the coordinator.
type State struct {
	Anchor         Anchor
	HighestVersion uint64
	HighestDigest  [32]byte
	// Root rotation state (ADR-0027, rootrotation.go): the current root
	// epoch, the pinned recovery keys and the roots revoked by transitions.
	Epoch        uint64
	RecoveryKeys []Key
	RevokedRoots []Key
	// Approval is the k-of-n approval policy of the last accepted document
	// (ADR-0121, multisig.go). Never modified in place; replaced on adopt.
	Approval *ApprovalPolicy
	// RootBaseVersion and RootBaseDigest identify the newest root-signed
	// document this member accepted, directly or as the base of an
	// administrator document, and RevokedAdmins its revoked grants
	// (ADR-0172). Sensitive is the pinned sensitive device policy
	// (ADR-0174). Never modified in place.
	RootBaseVersion uint64
	RootBaseDigest  [32]byte
	RevokedAdmins   []string
	Sensitive       *SensitivePolicy
}

// Accept opens env and, if it is acceptable, advances the state. A
// document with the current version is accepted only if it is identical to
// the one already seen.
func (s *State) Accept(env Envelope, now time.Time) (*Document, error) {
	doc, digest, adm, err := openDocumentFull(env, s.Anchor, s.HighestVersion, now)
	if err != nil {
		return nil, err
	}
	// Delegated administrator: base not older than the newest accepted
	// root-signed document, grant not revoked there (ADR-0172).
	if err := s.checkAdmin(adm); err != nil {
		return nil, err
	}
	// Two-person rule for sensitive devices (ADR-0174).
	if err := s.checkSensitive(env, doc); err != nil {
		return nil, err
	}
	// Root epoch and pinned recovery keys (ADR-0027).
	if err := s.checkRoot(doc); err != nil {
		return nil, err
	}
	// k-of-n approvals: pinned policy and the document's own (ADR-0121).
	if err := s.checkApproval(env, doc); err != nil {
		return nil, err
	}
	if doc.Version == s.HighestVersion && s.HighestVersion != 0 && digest != s.HighestDigest {
		return nil, ErrEquivocation
	}
	// Version chain: n+1 must name the n this member holds (ADR-0144).
	if err := s.checkChain(doc); err != nil {
		return nil, err
	}
	s.HighestVersion = doc.Version
	s.HighestDigest = digest
	s.adoptRoot(doc)
	s.adoptApproval(doc)
	s.adoptG1(doc, digest, adm)
	return doc, nil
}

func normalizeSlices(doc *Document) {
	if doc.Devices == nil {
		doc.Devices = []Device{}
	}
	if doc.Revoked == nil {
		doc.Revoked = []Revocation{}
	}
	if doc.Rules == nil {
		doc.Rules = []Rule{}
	}
	for i := range doc.Devices {
		if doc.Devices[i].Roles == nil {
			doc.Devices[i].Roles = []Role{}
		}
	}
	for i := range doc.Rules {
		if doc.Rules[i].Ports == nil {
			doc.Rules[i].Ports = []string{}
		}
	}
	for i := range doc.Groups {
		if doc.Groups[i].Members == nil {
			doc.Groups[i].Members = []string{}
		}
	}
}
