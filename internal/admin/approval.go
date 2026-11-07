package admin

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// k-of-n document approval on the owner's side (#5, ADR-0121). The owner
// signs a version as usual (Commit); approvers sign the resulting
// network.json on their own devices (trust.ApproveDocument) and the owner
// adds their approvals here. Members that pinned a policy reject the
// version until enough approvals are attached, so nothing stale is spread
// in the meantime. The history keeps the root-signed bytes unchanged.

// ApprovalStatus summarizes the approvals of the current document.
type ApprovalStatus struct {
	Policy   *trust.ApprovalPolicy
	Approved []string
	Missing  []string
	Complete bool
}

// SetApprovalPolicy returns a Change that sets (or with nil clears) the
// document's approval policy. The new version needs the approvals of the
// current policy and of the new one before members accept it.
func SetApprovalPolicy(p *trust.ApprovalPolicy) Change {
	return func(doc *trust.Document) error {
		if p == nil {
			doc.Approval = nil
			return nil
		}
		cp := &trust.ApprovalPolicy{Threshold: p.Threshold, Approvers: slices.Clone(p.Approvers)}
		if err := cp.Validate(); err != nil {
			return err
		}
		doc.Approval = cp
		return nil
	}
}

// requiredPolicies returns the policies the current document must meet:
// the previous version's (what members have pinned) and its own.
func (n *Network) requiredPolicies(doc *trust.Document) ([]*trust.ApprovalPolicy, error) {
	var out []*trust.ApprovalPolicy
	if doc.Version > 1 {
		_, prev, err := readHistoryVersion(n.dir, doc.Version-1, n.knownRootsLocked())
		if err == nil && prev.Approval != nil {
			out = append(out, prev.Approval)
		} else if err != nil && !errors.Is(err, ErrLastGoodUnavailable) {
			return nil, err
		}
	}
	if doc.Approval != nil && (len(out) == 0 || !out[0].Equal(doc.Approval)) {
		out = append(out, doc.Approval)
	}
	return out, nil
}

// Approvals reports which approvals the current network.json carries.
func (n *Network) Approvals() (ApprovalStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	env, doc, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return ApprovalStatus{}, err
	}
	return n.approvalStatusLocked(env, doc)
}

func (n *Network) approvalStatusLocked(env trust.Envelope, doc *trust.Document) (ApprovalStatus, error) {
	policies, err := n.requiredPolicies(doc)
	if err != nil {
		return ApprovalStatus{}, err
	}
	st := ApprovalStatus{Policy: doc.Approval, Complete: true}
	for _, p := range policies {
		have := p.Approved(env)
		for _, a := range p.Approvers {
			if slices.Contains(have, a.Name) {
				if !slices.Contains(st.Approved, a.Name) {
					st.Approved = append(st.Approved, a.Name)
				}
			} else if !slices.Contains(st.Missing, a.Name) {
				st.Missing = append(st.Missing, a.Name)
			}
		}
		if len(have) < p.Threshold {
			st.Complete = false
		}
	}
	return st, nil
}

// AddApproval attaches an approver's signature to the current network.json.
// The approval must verify and belong to an approver of a required policy.
func (n *Network) AddApproval(c trust.Cosignature) (ApprovalStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	path := filepath.Join(n.dir, documentFile)
	env, doc, err := readEnvelope(path, n.sealed.RootPublicKey())
	if err != nil {
		return ApprovalStatus{}, err
	}
	policies, err := n.requiredPolicies(doc)
	if err != nil {
		return ApprovalStatus{}, err
	}
	known := false
	for _, p := range policies {
		for _, a := range p.Approvers {
			known = known || a.Key == c.Key
		}
	}
	if !known {
		return ApprovalStatus{}, fmt.Errorf("%w: the key is not an approver of this document", trust.ErrApprovalPolicy)
	}
	if err := trust.AddCosignature(&env, c); err != nil {
		return ApprovalStatus{}, err
	}
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		return ApprovalStatus{}, err
	}
	if err := securefile.Replace(path, data); err != nil {
		return ApprovalStatus{}, fmt.Errorf("write network document: %w", err)
	}
	return n.approvalStatusLocked(env, doc)
}

// ApproveWithKey is the approver's side for a key held in a file: it
// verifies data (a signed network.json) against root and returns the
// approval and the document to review.
func ApproveWithKey(priv ed25519.PrivateKey, data []byte, root ed25519.PublicKey) (trust.Cosignature, *trust.Document, error) {
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return trust.Cosignature{}, nil, err
	}
	return trust.ApproveDocument(priv, env, root)
}
