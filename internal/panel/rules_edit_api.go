package panel

import (
	"errors"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Editing one rule in place (panel critique 2026-10-30): the owner changes
// a rule with one signature instead of adding a new rule and deleting the
// old one with two. The rule keeps its position, so deny-before-allow
// order and the "Kural N" numbers in warnings stay the same.

// errRuleNotFound is shown when the rule list changed under the form.
var errRuleNotFound = errors.New("Kural bulunamadı; liste başka bir yerden değişmiş olabilir. Sayfayı yenile ve tekrar dene.")

// errRuleKindChange refuses turning a traffic rule into a service rule or
// back; that is a different rule, added and removed on its own.
var errRuleKindChange = errors.New("Trafik kuralı servis kuralına (veya tersine) çevrilemez; yeni kural ekleyip eskisini sil.")

type editRuleRequest struct {
	addRuleRequest
	// Index is the 0-based position of the rule in the document.
	Index int `json:"index"`
	// ClearWindow removes a one-time access window; without it and
	// without WindowMinutes the rule keeps its current end time.
	ClearWindow bool `json:"clearWindow"`
}

func (s *Server) handleEditRule(w http.ResponseWriter, r *http.Request) {
	var req editRuleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Index < 0 || req.Index >= trust.MaxRules {
		writeError(w, http.StatusBadRequest, errRuleNotFound.Error())
		return
	}
	rule, ok := s.ruleFromRequest(w, req.addRuleRequest)
	if !ok {
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error {
		return replaceRule(doc, req.Index, rule, req.ClearWindow)
	})
}

// replaceRule puts rule at index. Settings the edit form does not carry
// (disabled state, schedule, start time, ICMP types of an unchanged ICMP
// rule and, unless cleared or replaced, the end of an access window) are
// kept from the old rule. The document is left unchanged on error.
func replaceRule(doc *trust.Document, index int, rule trust.Rule, clearWindow bool) error {
	if index < 0 || index >= len(doc.Rules) {
		return errRuleNotFound
	}
	old := doc.Rules[index]
	if (old.Service == "") != (rule.Service == "") {
		return errRuleKindChange
	}
	rule.Disabled = old.Disabled
	rule.Schedule = old.Schedule
	rule.NotBefore = old.NotBefore
	if rule.NotAfter.IsZero() && !clearWindow {
		rule.NotAfter = old.NotAfter
	}
	if len(rule.ICMPTypes) == 0 && rule.Protocol == old.Protocol {
		rule.ICMPTypes = old.ICMPTypes
	}
	if rule.Ports == nil {
		rule.Ports = []string{}
	}
	// Allow is stored empty, as AddRule does, so an unchanged allow rule
	// encodes exactly as before.
	if rule.Action == trust.RuleAllow {
		rule.Action = ""
	}
	doc.Rules[index] = rule
	if err := doc.Validate(); err != nil {
		doc.Rules[index] = old
		return err
	}
	return nil
}

// formatRuleTime is RFC 3339 in UTC, or "" for the zero time.
func formatRuleTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
