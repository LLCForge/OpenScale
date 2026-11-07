package admin

import (
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// Difference lines for the rule language extensions (ADR-0120).

// ruleExtString renders the bidirectional, ICMP type and time fields of a
// rule, or "" when none is set, so the difference shows changes to them.
func ruleExtString(r trust.Rule) string {
	var parts []string
	if r.Bidirectional {
		parts = append(parts, "çift yönlü")
	}
	if len(r.ICMPTypes) > 0 {
		parts = append(parts, "icmp türleri: "+strings.Join(r.ICMPTypes, ","))
	}
	if t := trust.RuleTimeSummary(r); t != "" {
		parts = append(parts, t)
	}
	if len(parts) == 0 {
		return ""
	}
	return " [" + strings.Join(parts, "; ") + "]"
}

func policyExtChanges(prev, next *trust.Document) []string {
	var out []string
	before := map[string]string{}
	for _, h := range prev.Hosts {
		before[h.Name] = h.Prefix.String()
	}
	after := map[string]string{}
	for _, h := range next.Hosts {
		after[h.Name] = h.Prefix.String()
		switch old, ok := before[h.Name]; {
		case !ok:
			out = append(out, fmt.Sprintf("+ adres host:%s = %s", h.Name, h.Prefix))
		case old != h.Prefix.String():
			out = append(out, fmt.Sprintf("~ adres host:%s %s -> %s", h.Name, old, h.Prefix))
		}
	}
	for _, h := range prev.Hosts {
		if _, ok := after[h.Name]; !ok {
			out = append(out, fmt.Sprintf("- adres host:%s", h.Name))
		}
	}
	counts := map[string]int{}
	for _, t := range prev.PolicyTests {
		counts[t.String()]++
	}
	for _, t := range next.PolicyTests {
		k := t.String()
		if counts[k] > 0 {
			counts[k]--
			continue
		}
		out = append(out, "+ kural testi "+k)
	}
	nextCounts := map[string]int{}
	for _, t := range next.PolicyTests {
		nextCounts[t.String()]++
	}
	for _, t := range prev.PolicyTests {
		k := t.String()
		if nextCounts[k] > 0 {
			nextCounts[k]--
			continue
		}
		out = append(out, "- kural testi "+k)
	}
	return out
}
