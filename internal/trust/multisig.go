package trust

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
)

// k-of-n document approval (#5, ADR-0121). A network may require that every
// document carries, next to the root signature, independent Ed25519
// signatures of at least Threshold of its approvers (for example a second
// admin device or a hardware token kept elsewhere). This is plain multiple
// signatures, not a threshold signature scheme: each approval is an ordinary
// signature that is checked on its own, so no new cryptography is involved.
//
// Downgrade protection: a member pins the policy of the last document it
// accepted (State.Approval). A later document must satisfy the pinned
// policy, so whoever holds only the root key can neither publish alone nor
// remove or weaken the policy. A document that introduces or changes a
// policy must also satisfy its own policy, which proves the new approvers
// hold their keys before anyone depends on them.

// DocumentApprovalContext is the signature context of approvals. It differs
// from DocumentContext, so a root signature never counts as an approval.
const DocumentApprovalContext = "openscale/document-approval/v1"

// Approval limits.
const (
	// MaxApprovers bounds the approvers of a policy.
	MaxApprovers = 7
	// MaxCosignatures bounds the approvals an envelope may carry.
	MaxCosignatures = 16
)

// Approval errors.
var (
	ErrApprovalMissing = errors.New("document does not carry enough approvals")
	ErrApprovalPolicy  = errors.New("invalid approval policy")
)

// Approver is one key whose signature counts towards a policy.
type Approver struct {
	Name string `json:"name"`
	Key  Key    `json:"key"`
}

// ApprovalPolicy requires Threshold distinct approvers to sign a document.
type ApprovalPolicy struct {
	Threshold int        `json:"threshold"`
	Approvers []Approver `json:"approvers"`
}

// Cosignature is an approver's signature over an envelope's payload. An
// empty Algorithm means Ed25519ctx under DocumentApprovalContext;
// AlgEd25519Digest allows an approver key held on a PIV token.
type Cosignature struct {
	Key       Key    `json:"key"`
	Algorithm string `json:"algorithm,omitempty"`
	Signature []byte `json:"signature"`
}

// Validate checks the policy's structure.
func (p *ApprovalPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if len(p.Approvers) == 0 || len(p.Approvers) > MaxApprovers {
		return fmt.Errorf("%w: 1-%d approvers are allowed", ErrApprovalPolicy, MaxApprovers)
	}
	if p.Threshold < 1 || p.Threshold > len(p.Approvers) {
		return fmt.Errorf("%w: threshold must be between 1 and the number of approvers", ErrApprovalPolicy)
	}
	names := make(map[string]bool, len(p.Approvers))
	keys := make(map[Key]bool, len(p.Approvers))
	for _, a := range p.Approvers {
		if !isValidLabel(a.Name) {
			return fmt.Errorf("%w: approver name %q must be a lowercase DNS label", ErrApprovalPolicy, a.Name)
		}
		if a.Key.IsZero() {
			return fmt.Errorf("%w: approver %q has no key", ErrApprovalPolicy, a.Name)
		}
		if names[a.Name] || keys[a.Key] {
			return fmt.Errorf("%w: duplicate approver %q", ErrApprovalPolicy, a.Name)
		}
		names[a.Name], keys[a.Key] = true, true
	}
	return nil
}

// validateApproval checks the document's approval policy; an approver can
// never be one of the document's recovery keys.
func (doc *Document) validateApproval() error {
	if err := doc.Approval.Validate(); err != nil {
		return err
	}
	if doc.Approval == nil {
		return nil
	}
	for _, a := range doc.Approval.Approvers {
		if slices.Contains(doc.RecoveryKeys, a.Key) {
			return fmt.Errorf("%w: approver %q uses a recovery key", ErrApprovalPolicy, a.Name)
		}
	}
	return nil
}

// Equal reports whether p and q require the same approvals.
func (p *ApprovalPolicy) Equal(q *ApprovalPolicy) bool {
	if p == nil || q == nil {
		return p == q
	}
	if p.Threshold != q.Threshold || len(p.Approvers) != len(q.Approvers) {
		return false
	}
	for _, a := range p.Approvers {
		if !slices.Contains(q.Approvers, a) {
			return false
		}
	}
	return true
}

func (p *ApprovalPolicy) clone() *ApprovalPolicy {
	if p == nil {
		return nil
	}
	return &ApprovalPolicy{Threshold: p.Threshold, Approvers: slices.Clone(p.Approvers)}
}

// Approved returns the names of the policy's approvers whose valid
// approval env carries. Unknown keys and invalid signatures are ignored.
func (p *ApprovalPolicy) Approved(env Envelope) []string {
	if p == nil {
		return nil
	}
	var names []string
	for _, a := range p.Approvers {
		for _, c := range env.Cosignatures {
			if c.Key == a.Key && c.verify(env.Payload) == nil {
				names = append(names, a.Name)
				break
			}
		}
	}
	return names
}

// Check returns ErrApprovalMissing unless env carries valid approvals of at
// least Threshold distinct approvers.
func (p *ApprovalPolicy) Check(env Envelope) error {
	if p == nil {
		return nil
	}
	if have := len(p.Approved(env)); have < p.Threshold {
		return fmt.Errorf("%w (%d of %d)", ErrApprovalMissing, have, p.Threshold)
	}
	return nil
}

func (c Cosignature) verify(payload []byte) error {
	pub := ed25519.PublicKey(c.Key[:])
	switch c.Algorithm {
	case "", AlgEd25519:
		if len(c.Signature) != ed25519.SignatureSize {
			return ErrBadSignature
		}
		if ed25519.VerifyWithOptions(pub, payload, c.Signature, &ed25519.Options{Context: DocumentApprovalContext}) != nil {
			return ErrBadSignature
		}
		return nil
	case AlgEd25519Digest:
		return verifyDigest(pub, DocumentApprovalContext, payload, c.Signature)
	}
	return ErrUnsupportedAlgorithm
}

// checkCosignatures bounds the approvals of a decoded envelope.
func checkCosignatures(list []Cosignature) error {
	if len(list) > MaxCosignatures {
		return fmt.Errorf("at most %d approvals are allowed", MaxCosignatures)
	}
	seen := make(map[Key]bool, len(list))
	for _, c := range list {
		if c.Key.IsZero() || seen[c.Key] {
			return errors.New("approval keys must be non-zero and distinct")
		}
		seen[c.Key] = true
		if c.Algorithm != "" && c.Algorithm != AlgEd25519 && c.Algorithm != AlgEd25519Digest {
			return ErrUnsupportedAlgorithm
		}
		if len(c.Signature) != ed25519.SignatureSize {
			return errors.New("invalid approval signature size")
		}
	}
	return nil
}

// ApproveDocument checks that env is a document signed by root and returns
// an approval of it with priv, together with the document so the approver
// can review what they sign.
func ApproveDocument(priv ed25519.PrivateKey, env Envelope, root ed25519.PublicKey) (Cosignature, *Document, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Cosignature{}, nil, errors.New("invalid ed25519 private key")
	}
	doc, err := VerifyDocumentSignature(env, root)
	if err != nil {
		return Cosignature{}, nil, err
	}
	sig, err := priv.Sign(nil, env.Payload, &ed25519.Options{Context: DocumentApprovalContext})
	if err != nil {
		return Cosignature{}, nil, fmt.Errorf("sign approval: %w", err)
	}
	var k Key
	copy(k[:], priv.Public().(ed25519.PublicKey))
	return Cosignature{Key: k, Signature: sig}, doc, nil
}

// ApproveDocumentWith is ApproveDocument for an approver key held on a
// hardware token.
func ApproveDocumentWith(signer DigestSigner, env Envelope, root ed25519.PublicKey) (Cosignature, *Document, error) {
	doc, err := VerifyDocumentSignature(env, root)
	if err != nil {
		return Cosignature{}, nil, err
	}
	signed, err := SignWithDigest(signer, DocumentApprovalContext, env.Payload)
	if err != nil {
		return Cosignature{}, nil, err
	}
	var k Key
	copy(k[:], signer.PublicKey())
	return Cosignature{Key: k, Algorithm: AlgEd25519Digest, Signature: signed.Signature}, doc, nil
}

// AddCosignature adds c to env after checking it, replacing an earlier
// approval of the same key. Approvals are kept sorted by key so the
// encoding does not depend on the order they arrived in.
func AddCosignature(env *Envelope, c Cosignature) error {
	if env.Context != DocumentContext {
		return ErrWrongContext
	}
	if err := checkCosignatures([]Cosignature{c}); err != nil {
		return err
	}
	if err := c.verify(env.Payload); err != nil {
		return err
	}
	list := slices.DeleteFunc(slices.Clone(env.Cosignatures), func(o Cosignature) bool { return o.Key == c.Key })
	list = append(list, c)
	if len(list) > MaxCosignatures {
		return fmt.Errorf("at most %d approvals are allowed", MaxCosignatures)
	}
	slices.SortFunc(list, func(a, b Cosignature) int { return bytes.Compare(a.Key[:], b.Key[:]) })
	env.Cosignatures = list
	return nil
}

// PinApproval pins the approval policy of a document this member already
// accepted, for example its stored document when the state is reloaded.
func (s *State) PinApproval(doc *Document) {
	if doc == nil {
		return
	}
	s.Approval = doc.Approval.clone()
	s.Sensitive = doc.Sensitive.clone() // ADR-0174
}

// checkApproval enforces the pinned policy and the document's own policy.
func (s *State) checkApproval(env Envelope, doc *Document) error {
	if err := s.checkApproverKeys(doc.Approval); err != nil {
		return err
	}
	if err := s.Approval.Check(env); err != nil {
		return err
	}
	if !doc.Approval.Equal(s.Approval) {
		return doc.Approval.Check(env)
	}
	return nil
}

// checkApproverKeys refuses approvers that are root or recovery keys: the
// root holder alone must never satisfy a policy.
func (s *State) checkApproverKeys(p *ApprovalPolicy) error {
	if p == nil {
		return nil
	}
	for _, a := range p.Approvers {
		if bytes.Equal(a.Key[:], s.Anchor.RootKey) || slices.Contains(s.RecoveryKeys, a.Key) || slices.Contains(s.RevokedRoots, a.Key) {
			return fmt.Errorf("%w: approver %q uses a root or recovery key", ErrApprovalPolicy, a.Name)
		}
	}
	return nil
}

// adoptApproval pins the policy of a newly accepted document.
func (s *State) adoptApproval(doc *Document) {
	s.Approval = doc.Approval.clone()
}
