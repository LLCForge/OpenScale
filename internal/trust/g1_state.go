package trust

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
)

// Member state for delegated administrators (ADR-0172) and the sensitive
// device policy (ADR-0174).

// validateG1 checks the document fields added by ADR-0172 and ADR-0174.
func (doc *Document) validateG1() error {
	if err := doc.validateRevokedAdmins(); err != nil {
		return err
	}
	return doc.validateSensitive()
}

// checkG1Envelope bounds the envelope fields added by ADR-0172 and
// ADR-0174 while decoding.
func checkG1Envelope(e Envelope) error {
	if e.Admin != nil {
		if e.Context != DocumentContext {
			return errors.New("only network documents may carry an administrator proof")
		}
		if err := e.Admin.check(); err != nil {
			return err
		}
	}
	if len(e.SensitiveApprovals) > 0 && e.Context != DocumentContext {
		return errors.New("only network documents may carry sensitive approvals")
	}
	return checkCosignatures(e.SensitiveApprovals)
}

// checkAdmin refuses an administrator document whose base is older than
// (or forks from) the newest root-signed document this member accepted, or
// whose grant that document revoked.
func (s *State) checkAdmin(adm *AdminVerified) error {
	if adm == nil {
		return nil
	}
	switch {
	case adm.Base.Version < s.RootBaseVersion:
		return fmt.Errorf("%w: base version %d is older than the accepted root version %d", ErrAdminBase, adm.Base.Version, s.RootBaseVersion)
	case adm.Base.Version == s.RootBaseVersion && s.RootBaseVersion != 0 && adm.BaseDigest != s.RootBaseDigest:
		return fmt.Errorf("%w: base differs from the accepted root version %d", ErrAdminBase, s.RootBaseVersion)
	case slices.Contains(s.RevokedAdmins, adm.Grant.ID):
		return ErrAdminRevoked
	}
	return nil
}

// adoptG1 records the root base and the sensitive policy of a newly
// accepted document.
func (s *State) adoptG1(doc *Document, digest [32]byte, adm *AdminVerified) {
	switch {
	case adm == nil:
		s.RootBaseVersion, s.RootBaseDigest = doc.Version, digest
		s.RevokedAdmins = slices.Clone(doc.RevokedAdmins)
	case adm.Base.Version > s.RootBaseVersion:
		s.RootBaseVersion, s.RootBaseDigest = adm.Base.Version, adm.BaseDigest
		s.RevokedAdmins = slices.Clone(adm.Base.RevokedAdmins)
	}
	s.Sensitive = doc.Sensitive.clone()
}

// PinStored pins what a member keeps from its stored, previously accepted
// envelope when its state is reloaded: the approval and sensitive policies
// and the root base of a delegated administrator's document.
func (s *State) PinStored(env Envelope, doc *Document) {
	if doc == nil {
		return
	}
	s.PinApproval(doc)
	if env.Admin == nil {
		s.RootBaseVersion, s.RootBaseDigest = doc.Version, sha256.Sum256(env.Payload)
		s.RevokedAdmins = slices.Clone(doc.RevokedAdmins)
		return
	}
	baseEnv, err := UnmarshalEnvelope(env.Admin.Base)
	if err != nil || baseEnv.Admin != nil {
		return
	}
	base, digest, err := verifyRootDocument(baseEnv, s.Anchor.RootKey)
	if err != nil {
		return
	}
	s.RootBaseVersion, s.RootBaseDigest = base.Version, digest
	s.RevokedAdmins = slices.Clone(base.RevokedAdmins)
}
