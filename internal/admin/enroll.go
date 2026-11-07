package admin

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

// ErrFingerprintMismatch is returned when the typed fingerprint does not
// match the enrollment request.
var ErrFingerprintMismatch = errors.New("fingerprint mismatch")

// ErrDuplicateRequest is returned when an enrollment request was already
// used to add a device.
var ErrDuplicateRequest = errors.New("enrollment request already used")

// PendingDevice is a verified enrollment request waiting for the owner.
type PendingDevice struct {
	Request     *trust.EnrollmentRequest
	Fingerprint string
	// TPM is the join policy decision when the document has a join policy
	// or the request carries TPM evidence (#611); nil otherwise.
	TPM *tpm.Verdict
}

// InspectRequest decodes and verifies an enrollment request line. It also
// rejects requests already used by a current or revoked device, which makes
// every request single use.
func (n *Network) InspectRequest(line string, now time.Time) (*PendingDevice, error) {
	env, err := trust.DecodeEnrollment(line)
	if err != nil {
		return nil, err
	}
	req, err := trust.OpenEnrollmentRequest(env, now)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, d := range n.doc.Devices {
		if d.ID == req.DeviceID || d.SigningKey == req.SigningKey || d.WireGuardKey == req.WireGuardKey {
			return nil, ErrDuplicateRequest
		}
	}
	for _, r := range n.doc.Revoked {
		if r.DeviceID == req.DeviceID || r.SigningKey == req.SigningKey || r.WireGuardKey == req.WireGuardKey {
			return nil, trust.ErrRevokedKey
		}
	}
	for _, r := range n.doc.RetiredKeys {
		if r.SigningKey == req.SigningKey || r.WireGuardKey == req.WireGuardKey {
			return nil, trust.ErrRevokedKey
		}
	}
	verdict, err := checkJoinPolicy(n.doc.JoinPolicy, req.TPMEvidence, now)
	if err != nil {
		return nil, err
	}
	return &PendingDevice{Request: req, Fingerprint: req.Fingerprint(), TPM: verdict}, nil
}

// ConfirmFingerprint compares a fingerprint typed by the owner with the
// request's fingerprint in constant time.
func (p *PendingDevice) ConfirmFingerprint(typed string) error {
	got := []byte(trust.NormalizeFingerprint(typed))
	want := []byte(trust.NormalizeFingerprint(p.Fingerprint))
	if len(got) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrFingerprintMismatch
	}
	return nil
}
