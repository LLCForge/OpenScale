package trust

import (
	"encoding/json"
	"fmt"
	"time"
)

// Rule scope analysis (#112, ADR-0120): warnings shown before signing. They
// never block a signature by themselves; broad allow rules additionally
// need explicit confirmation in the CLI and the panel.

// PolicyWarning is one finding. Rule is the rule index or -1.
type PolicyWarning struct {
	Rule    int    `json:"rule"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Warning codes.
const (
	WarnBroad          = "broad"
	WarnShadowed       = "shadowed"
	WarnMatchesNothing = "matches_nothing"
	WarnExpired        = "expired"
	WarnNotYet         = "not_yet"
	WarnClock          = "clock"
	WarnUnusedTag      = "unused_tag"
)

// maxLintPairs bounds the device pair enumeration of the analysis.
const maxLintPairs = 1 << 16

// coversAll reports whether a from or to list matches every device: "*" or
// a range holding a whole network prefix.
func (doc *Document) coversAll(entries []string) bool {
	for _, e := range entries {
		if e == RuleWildcard {
			return true
		}
		if isAddrEntry(e) {
			if p, ok := doc.entryPrefix(e); ok && (p == doc.IPv4Prefix || p == doc.IPv6Prefix) {
				return true
			}
		}
	}
	return false
}

// IsBroadRule reports an enabled allow rule that opens every device to
// every device on every port of its protocol. Such a rule needs explicit
// confirmation before signing (#112).
func (doc *Document) IsBroadRule(r Rule) bool {
	if r.Disabled || r.IsDeny() || r.Service != "" || !doc.coversAll(r.From) || !doc.coversAll(r.To) {
		return false
	}
	switch r.Protocol {
	case ProtocolAny:
		return true
	case ProtocolTCP, ProtocolUDP:
		for _, p := range r.Ports {
			if lo, hi, err := ParsePortRange(p); err == nil && lo <= 1 && hi == 65535 {
				return true
			}
		}
	}
	return false
}

// NewBroadRules returns the broad rules of next that prev does not have
// (compared by content), so only newly added ones need confirmation.
func NewBroadRules(prev, next *Document) []int {
	have := map[string]int{}
	if prev != nil {
		for _, r := range prev.Rules {
			if prev.IsBroadRule(r) {
				have[ruleKey(r)]++
			}
		}
	}
	var out []int
	for i, r := range next.Rules {
		if !next.IsBroadRule(r) {
			continue
		}
		k := ruleKey(r)
		if have[k] > 0 {
			have[k]--
			continue
		}
		out = append(out, i)
	}
	return out
}

func ruleKey(r Rule) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// matchedDevices returns the devices an entry list covers.
func (doc *Document) matchedDevices(entries []string) []string {
	var out []string
	for _, d := range doc.Devices {
		if doc.matchesAny(entries, doc.subject(d.Name)) {
			out = append(out, d.Name)
		}
	}
	return out
}

// PolicyWarnings analyses the rules at time now.
func (doc *Document) PolicyWarnings(now time.Time) []PolicyWarning {
	var out []PolicyWarning
	add := func(i int, code, format string, args ...any) {
		out = append(out, PolicyWarning{Rule: i, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	for i, r := range doc.Rules {
		n := i + 1
		if r.Disabled {
			continue
		}
		if doc.IsBroadRule(r) {
			add(i, WarnBroad, "Kural %d bütün cihazlardan bütün cihazlara erişim açıyor; varsayılan reddet ilkesini fiilen kapatır.", n)
		}
		if !r.NotAfter.IsZero() && !now.Before(r.NotAfter) {
			add(i, WarnExpired, "Kural %d'nin süresi %s tarihinde doldu; artık hiçbir trafiğe uygulanmıyor, silinebilir.", n, r.NotAfter.UTC().Format(time.RFC3339))
		}
		if !r.NotBefore.IsZero() && now.Before(r.NotBefore) {
			add(i, WarnNotYet, "Kural %d %s tarihinde başlayacak.", n, r.NotBefore.UTC().Format(time.RFC3339))
		}
		if r.HasTimeConditions() {
			add(i, WarnClock, "Kural %d zamana bağlı; her cihaz kendi saatine göre uygular. Saati yanlış bir cihaz kuralı yanlış zamanda açar veya kapatır.", n)
		}
		doc.lintCoverage(i, r, add)
	}
	for _, t := range doc.TagUsage() {
		add(-1, WarnUnusedTag, "tag:%s hiçbir cihazda yok; ona başvuran kurallar şimdilik hiçbir şeyle eşleşmez.", t)
	}
	return append(out, doc.rangeWarnings()...) // #277, f4a_lint.go
}

// lintCoverage reports rules that match no device pair and allow rules
// that an unconditional deny rule fully overrides.
func (doc *Document) lintCoverage(i int, r Rule, add func(int, string, string, ...any)) {
	from, to := doc.matchedDevices(r.From), doc.matchedDevices(r.trafficTo())
	if len(from)*len(to) > maxLintPairs {
		return
	}
	type pair struct{ a, b string }
	var pairs []pair
	for _, a := range from {
		for _, b := range to {
			if a != b {
				pairs = append(pairs, pair{a, b})
				if r.Bidirectional {
					pairs = append(pairs, pair{b, a})
				}
			}
		}
	}
	n := i + 1
	if len(pairs) == 0 && doc.routedCoverage(r) {
		// A routed CIDR rule (ADR-0133) reaches a router's LAN, not a device.
		return
	}
	if len(pairs) == 0 {
		what := "izin"
		if r.IsDeny() {
			what = "ret (yazım hatası olabilir)"
		}
		add(i, WarnMatchesNothing, "Kural %d şu anki hiçbir cihaz çiftiyle eşleşmiyor; etkisiz %s kuralı.", n, what)
		return
	}
	if r.IsDeny() {
		return
	}
	for j, d := range doc.Rules {
		if j == i || d.Disabled || !d.IsDeny() || d.Protocol != ProtocolAny || d.HasTimeConditions() {
			continue
		}
		all := true
		for _, p := range pairs {
			if !doc.ruleCovers(d, doc.subject(p.a), doc.subject(p.b)) {
				all = false
				break
			}
		}
		if all {
			add(i, WarnShadowed, "Kural %d hiçbir zaman uygulanmaz: reddet kuralı %d aynı cihaz çiftlerinin bütün trafiğini reddediyor.", n, j+1)
			return
		}
	}
}
