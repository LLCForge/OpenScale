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

// Two-person rule for sensitive devices, owner side (#610, ADR-0174).

// SetSensitivePolicy returns a Change that sets (or with nil removes) the
// sensitive device policy. Targets are sorted for a canonical encoding.
func SetSensitivePolicy(p *trust.SensitivePolicy) Change {
	return func(doc *trust.Document) error {
		if p == nil {
			if doc.Sensitive == nil {
				return errors.New("there is no sensitive device policy")
			}
			doc.Sensitive = nil
			return nil
		}
		c := &trust.SensitivePolicy{Targets: slices.Clone(p.Targets), Threshold: p.Threshold, Approvers: slices.Clone(p.Approvers)}
		slices.Sort(c.Targets)
		doc.Sensitive = c
		return nil
	}
}

// SensitiveState reports the sensitive approvals of the current document.
type SensitiveState struct {
	Devices  []string `json:"devices"`
	Approved []string `json:"approved"`
	Needed   int      `json:"needed"`
	Complete bool     `json:"complete"`
	// Fingerprint is what approvers sign (hex), shown to compare.
	Fingerprint string `json:"fingerprint"`
}

// Sensitive returns the state of the current document's sensitive policy
// against the policy of the previous version on disk (what members pinned).
func (n *Network) Sensitive() (SensitiveState, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	env, doc, err := readEnvelope(filepath.Join(n.dir, documentFile), n.sealed.RootPublicKey())
	if err != nil {
		return SensitiveState{}, err
	}
	return n.sensitiveStateLocked(env, doc), nil
}

func (n *Network) sensitiveStateLocked(env trust.Envelope, doc *trust.Document) SensitiveState {
	fp := trust.SensitiveFingerprint(doc)
	st := SensitiveState{Devices: doc.SensitiveDevices(), Fingerprint: fmt.Sprintf("%x", fp[:8])}
	pinned := n.previousSensitive(doc)
	need := 0
	if pinned != nil {
		need = pinned.Threshold
		st.Approved = trust.SensitiveApproved(pinned, env.SensitiveApprovals, fp)
	}
	if doc.Sensitive != nil && !doc.Sensitive.Equal(pinned) {
		need = max(need, doc.Sensitive.Threshold)
		for _, a := range trust.SensitiveApproved(doc.Sensitive, env.SensitiveApprovals, fp) {
			if !slices.Contains(st.Approved, a) {
				st.Approved = append(st.Approved, a)
			}
		}
	}
	st.Needed = need
	st.Complete = trust.SensitiveStatus(env, doc, pinned) == nil
	if st.Approved == nil {
		st.Approved = []string{}
	}
	return st
}

// previousSensitive returns the policy of the version before doc in the
// history (what members accepted last), or doc's own when there is none.
func (n *Network) previousSensitive(doc *trust.Document) *trust.SensitivePolicy {
	if doc.Version < 2 {
		return nil
	}
	data, err := securefile.ReadPrivate(filepath.Join(n.dir, historyDir, historyName(doc.Version-1)), trust.MaxEnvelopeSize)
	if err != nil {
		return doc.Sensitive
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return doc.Sensitive
	}
	prev, err := trust.VerifyDocumentSignature(env, n.sealed.RootPublicKey())
	if err != nil {
		return doc.Sensitive
	}
	return prev.Sensitive
}

// AddSensitiveApproval adds an approver's signature over the current
// document's sensitive fingerprint to network.json (and its history copy
// is left as signed; members read network.json).
func (n *Network) AddSensitiveApproval(c trust.Cosignature) (SensitiveState, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	path := filepath.Join(n.dir, documentFile)
	env, doc, err := readEnvelope(path, n.sealed.RootPublicKey())
	if err != nil {
		return SensitiveState{}, err
	}
	pinned := n.previousSensitive(doc)
	known := func(p *trust.SensitivePolicy) bool {
		return p != nil && slices.ContainsFunc(p.Approvers, func(a trust.Approver) bool { return a.Key == c.Key })
	}
	if !known(pinned) && !known(doc.Sensitive) {
		return SensitiveState{}, errors.New("this key is not a sensitive device approver")
	}
	if err := trust.AddSensitiveApproval(&env, doc, c); err != nil {
		return SensitiveState{}, err
	}
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		return SensitiveState{}, err
	}
	if err := securefile.Replace(path, data); err != nil {
		return SensitiveState{}, fmt.Errorf("write network document: %w", err)
	}
	return n.sensitiveStateLocked(env, doc), nil
}

// ApproveSensitiveWithKey verifies a document (encoded envelope) against
// the root and returns the approver's signature over its sensitive
// fingerprint, with the document so the approver sees what they approve.
func ApproveSensitiveWithKey(priv ed25519.PrivateKey, data []byte, root ed25519.PublicKey) (trust.Cosignature, *trust.Document, error) {
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return trust.Cosignature{}, nil, err
	}
	doc, err := trust.VerifyDocumentSignature(env, root)
	if err != nil {
		return trust.Cosignature{}, nil, err
	}
	c, err := trust.ApproveSensitive(priv, doc)
	return c, doc, err
}

// ApproveSensitiveWithToken is ApproveSensitiveWithKey for a token key.
func ApproveSensitiveWithToken(signer trust.DigestSigner, data []byte, root ed25519.PublicKey) (trust.Cosignature, *trust.Document, error) {
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return trust.Cosignature{}, nil, err
	}
	doc, err := trust.VerifyDocumentSignature(env, root)
	if err != nil {
		return trust.Cosignature{}, nil, err
	}
	c, err := trust.ApproveSensitiveWith(signer, doc)
	return c, doc, err
}
