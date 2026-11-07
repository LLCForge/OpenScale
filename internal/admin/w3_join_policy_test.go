package admin

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

func evidenceLine(t *testing.T, ev *tpm.Evidence) string {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, testNow)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if ev != nil {
		if raw, err = json.Marshal(ev); err != nil {
			t.Fatal(err)
		}
	}
	env, _, err := s.NewEnrollmentRequestWithEvidence("pc", testNow, raw)
	if err != nil {
		t.Fatal(err)
	}
	line, err := trust.EncodeEnrollment(env)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// TestJoinPolicyAtEnrollment covers #611 end to end on the owner's side:
// the device's TPM evidence travels in the signed enrollment request and
// the root-signed join policy decides whether the owner's tools accept it.
func TestJoinPolicyAtEnrollment(t *testing.T) {
	n := newNetwork(t)
	withTPM := &tpm.Evidence{V: 1, Method: tpm.MethodPresence, TPM: true, Version: "2.0", Manufacturer: "INTC"}
	noTPM := &tpm.Evidence{V: 1, Method: tpm.MethodNone}

	// Without a policy everything is accepted; evidence is only reported.
	p, err := n.InspectRequest(evidenceLine(t, withTPM), testNow)
	if err != nil || p.TPM == nil || !p.TPM.OK || p.TPM.Strength != "claim" {
		t.Fatalf("no policy: %+v %v", p, err)
	}
	if p, err := n.InspectRequest(evidenceLine(t, nil), testNow); err != nil || p.TPM != nil {
		t.Fatalf("plain request without policy: %+v %v", p, err)
	}

	// The owner signs a policy: TPM 2.0 from Intel or AMD.
	plan, err := n.Prepare(testNow, trust.DefaultValidity, func(doc *trust.Document) error {
		doc.JoinPolicy = &trust.JoinPolicy{RequireTPM: true, Manufacturers: []string{"INTC", "AMD"}}
		return nil
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if doc, err := n.Document(); err != nil || doc.JoinPolicy == nil {
		t.Fatal("join policy not in the signed document")
	}
	if p, err := n.InspectRequest(evidenceLine(t, withTPM), testNow); err != nil || !p.TPM.OK {
		t.Fatalf("matching TPM refused: %+v %v", p, err)
	}
	for name, ev := range map[string]*tpm.Evidence{
		"no evidence":  nil,
		"no TPM":       noTPM,
		"other vendor": {V: 1, Method: tpm.MethodPresence, TPM: true, Version: "2.0", Manufacturer: "STM"},
		"TPM 1.2":      {V: 1, Method: tpm.MethodPresence, TPM: true, Version: "1.2", Manufacturer: "INTC"},
	} {
		if _, err := n.InspectRequest(evidenceLine(t, ev), testNow); !errors.Is(err, ErrJoinPolicy) {
			t.Errorf("%s: err = %v, want ErrJoinPolicy", name, err)
		}
	}
}

func TestJoinPolicyValidation(t *testing.T) {
	for _, p := range []*trust.JoinPolicy{
		{},
		{RequireTPM: true, Manufacturers: []string{"intc"}},
		{RequireTPM: true, Manufacturers: []string{"INTC", "INTC"}},
		{Manufacturers: []string{"TOOLONG"}},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("policy %+v accepted", p)
		}
	}
	if err := (&trust.JoinPolicy{RequireTPM: true}).Validate(); err != nil {
		t.Fatal(err)
	}
	var none *trust.JoinPolicy
	if err := none.Validate(); err != nil {
		t.Fatal(err)
	}
	// Evidence that is not a JSON object never enters a request.
	s, _ := trust.GenerateDeviceSecrets(rand.Reader, testNow)
	if _, _, err := s.NewEnrollmentRequestWithEvidence("pc", testNow, []byte(`[1]`)); err == nil {
		t.Fatal("array evidence accepted")
	}
	// A request without evidence encodes exactly as before (no new key).
	env, _, err := s.NewEnrollmentRequest("pc", testNow)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["tpm_evidence"]; ok {
		t.Fatal("empty evidence was encoded")
	}
}
