package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TPM evidence at enrollment (#611, ADR-0208).
//
// A joining device may attach what it states about its TPM (the tpm
// package's Evidence, kept opaque here so the trust package does not
// depend on platform TPM code) to its self-signed enrollment request. The
// owner may sign a JoinPolicy into the document; the owner's tools then
// refuse requests whose evidence does not satisfy it (admin.InspectRequest).
// Both fields are optional and omitted when empty, so documents and
// requests without them encode exactly as before. An older owner tool
// rejects a request that carries evidence (strict decoding), and an older
// client rejects a document with a join policy: raise min_client_version
// before signing one.

// MaxTPMEvidence bounds the evidence carried in an enrollment request.
const MaxTPMEvidence = 3072

// JoinPolicy is the owner's TPM requirement for new devices.
type JoinPolicy struct {
	// RequireTPM refuses devices that do not state a TPM 2.0. A verified
	// EK certificate chain needs manufacturer roots the owner's tools do
	// not ship yet, so there is no EK requirement in this version.
	RequireTPM bool `json:"require_tpm,omitempty"`
	// Manufacturers lists the accepted TPM vendor IDs ("INTC", "AMD",
	// "IFX", "NTC", "STM", "MSFT"); empty accepts any.
	Manufacturers []string `json:"manufacturers,omitempty"`
}

// Validate checks the policy strictly.
func (p *JoinPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if !p.RequireTPM && len(p.Manufacturers) == 0 {
		return errors.New("join_policy is empty; omit it instead")
	}
	if len(p.Manufacturers) > 16 {
		return errors.New("join_policy: at most 16 manufacturers")
	}
	seen := map[string]bool{}
	for _, m := range p.Manufacturers {
		if m == "" || len(m) > 4 || strings.ToUpper(m) != m || strings.TrimSpace(m) != m {
			return fmt.Errorf("join_policy: invalid manufacturer code %q", m)
		}
		for _, r := range m {
			if r < 'A' || r > 'Z' {
				return fmt.Errorf("join_policy: invalid manufacturer code %q", m)
			}
		}
		if seen[m] {
			return fmt.Errorf("join_policy: manufacturer %q listed twice", m)
		}
		seen[m] = true
	}
	return nil
}

func validTPMEvidence(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > MaxTPMEvidence {
		return errors.New("enrollment request: TPM evidence is too large")
	}
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' || !json.Valid(t) {
		return errors.New("enrollment request: TPM evidence is not a JSON object")
	}
	return nil
}

// NewEnrollmentRequestWithEvidence is NewEnrollmentRequest with the
// device's TPM evidence (JSON of tpm.Evidence) attached; nil attaches none.
func (s *DeviceSecrets) NewEnrollmentRequestWithEvidence(hostname string, now time.Time, evidence []byte) (Envelope, *EnrollmentRequest, error) {
	if err := validTPMEvidence(evidence); err != nil {
		return Envelope{}, nil, err
	}
	return s.newEnrollmentRequest(hostname, now, evidence)
}
