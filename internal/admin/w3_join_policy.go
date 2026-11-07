package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

// ErrJoinPolicy is wrapped when a request does not satisfy the document's
// TPM join policy (#611).
var ErrJoinPolicy = errors.New("katılım politikası karşılanmadı")

// checkJoinPolicy evaluates the request's TPM evidence against the signed
// join policy. Without a policy, evidence is only reported. The verdict's
// strength stays "claim": the evidence is the device's own statement and no
// manufacturer roots are configured, so a copied EK certificate would pass
// (ADR-0208); the policy keeps honest devices without a TPM out, it does
// not prove the key lives in one.
func checkJoinPolicy(policy *trust.JoinPolicy, raw json.RawMessage, now time.Time) (*tpm.Verdict, error) {
	if policy == nil && len(raw) == 0 {
		return nil, nil
	}
	ev := tpm.Evidence{V: 1, Method: tpm.MethodNone}
	if len(raw) > 0 {
		if err := decodeEvidence(raw, &ev); err != nil {
			if policy == nil {
				v := tpm.Verdict{OK: false, Strength: "claim", Reasons: []string{"TPM kanıtı okunamadı: " + err.Error()}}
				return &v, nil
			}
			return nil, fmt.Errorf("%w: TPM kanıtı okunamadı: %v", ErrJoinPolicy, err)
		}
	}
	p := tpm.JoinPolicy{}
	if policy != nil {
		p = tpm.JoinPolicy{RequireTPM: policy.RequireTPM, Manufacturers: policy.Manufacturers}
	}
	v := tpm.EvaluateJoin(p, ev, nil, now)
	if policy != nil && !v.OK {
		if len(raw) == 0 {
			return nil, fmt.Errorf("%w: istek TPM kanıtı taşımıyor; cihazda isteği TPM kanıtıyla yeniden oluşturun", ErrJoinPolicy)
		}
		return nil, fmt.Errorf("%w: %s", ErrJoinPolicy, strings.Join(v.Reasons, "; "))
	}
	return &v, nil
}

func decodeEvidence(raw json.RawMessage, ev *tpm.Evidence) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(ev); err != nil {
		return err
	}
	return ev.Validate()
}
