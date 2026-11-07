package admin

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// Risk-scored, human-readable change summary (#600, ADR-0177). Shown next
// to the diff before every signature (CLI, panel, administrator plans):
// "3 cihaz eklenecek, 1 kural erişimi genişletecek". Items that widen
// access are flagged so the panel can show them in red. The score is a
// fixed, documented heuristic; it informs, it never blocks.

// Risk levels.
const (
	RiskLow      = "düşük"
	RiskMedium   = "orta"
	RiskHigh     = "yüksek"
	RiskCritical = "kritik"
)

// maxReachDevices bounds the reachability comparison (pairs grow
// quadratically).
const maxReachDevices = 256

// RiskItem is one line of the summary.
type RiskItem struct {
	Text   string `json:"text"`
	Points int    `json:"points"`
	// Widens marks a change that widens access (shown in red).
	Widens bool `json:"widens"`
}

// RiskReport is the summary of one change.
type RiskReport struct {
	Score   int        `json:"score"`
	Level   string     `json:"level"`
	Widens  bool       `json:"widens"`
	Summary string     `json:"summary"`
	Items   []RiskItem `json:"items"`
}

// Lines renders the report as Turkish text; widening items start with
// "[!]".
func (r RiskReport) Lines() []string {
	lines := []string{fmt.Sprintf("Risk: %s (%d puan) — %s", r.Level, r.Score, r.Summary)}
	for _, it := range r.Items {
		mark := "   "
		if it.Widens {
			mark = "[!]"
		}
		lines = append(lines, fmt.Sprintf("%s %s (+%d)", mark, it.Text, it.Points))
	}
	return lines
}

// AssessRisk scores the change from prev to next.
func AssessRisk(prev, next *trust.Document) RiskReport {
	var r RiskReport
	add := func(points int, widens bool, format string, args ...any) {
		r.Items = append(r.Items, RiskItem{Text: fmt.Sprintf(format, args...), Points: points, Widens: widens})
	}
	before := make(map[string]trust.Device, len(prev.Devices))
	for _, d := range prev.Devices {
		before[d.ID] = d
	}
	after := make(map[string]bool, len(next.Devices))
	added := 0
	for _, d := range next.Devices {
		after[d.ID] = true
		old, ok := before[d.ID]
		if !ok {
			added++
		}
		for _, role := range d.Roles {
			if ok && old.HasRole(role) {
				continue
			}
			switch role {
			case trust.RoleAdmin:
				add(40, true, "%s yönetici rolü alıyor", d.Name)
			case trust.RoleExitNode:
				add(15, true, "%s çıkış düğümü oluyor", d.Name)
			}
		}
		if n := len(d.Routes) - len(old.Routes); n > 0 {
			add(15, true, "%s %d yeni alt ağ yönlendirecek", d.Name, n)
		}
	}
	removed := 0
	for _, d := range prev.Devices {
		if !after[d.ID] {
			removed++
		}
	}
	if added > 0 {
		add(10*added, true, "%d cihaz eklenecek", added)
	}
	if removed > 0 {
		add(0, false, "%d cihaz çıkarılacak", removed)
	}

	addedRules := ruleDelta(prev.Rules, next.Rules)
	removedRules := ruleDelta(next.Rules, prev.Rules)
	widening, narrowing := 0, 0
	for _, rule := range addedRules {
		if rule.Disabled {
			continue
		}
		if rule.IsDeny() {
			narrowing++
			continue
		}
		widening++
		points := 10
		if slices.Contains(rule.From, trust.RuleWildcard) || slices.Contains(rule.To, trust.RuleWildcard) {
			points += 25
		}
		if rule.AllowRoot {
			points += 30
		}
		if rule.AllowUnattended || rule.AllowControl {
			points += 20
		}
		add(points, true, "kural erişimi genişletecek: %s", RuleString(rule))
	}
	for _, rule := range removedRules {
		if rule.Disabled {
			continue
		}
		if rule.IsDeny() {
			widening++
			add(15, true, "reddetme kuralı kalkıyor: %s", RuleString(rule))
		} else {
			narrowing++
		}
	}
	if narrowing > 0 {
		add(0, false, "%d kural erişimi daraltacak", narrowing)
	}
	if n := newReachablePairs(prev, next); n > 0 {
		add(min(50, 2*n), true, "%d yeni cihaz çifti birbirine erişebilecek", n)
	}

	if prev.Approval != nil && (next.Approval == nil || next.Approval.Threshold < prev.Approval.Threshold) {
		add(50, true, "belge onay politikası kalkıyor veya zayıflıyor")
	}
	if prev.Sensitive != nil && (next.Sensitive == nil || next.Sensitive.Threshold < prev.Sensitive.Threshold) {
		add(50, true, "hassas cihaz çift onay kuralı kalkıyor veya zayıflıyor")
	}
	if !slices.Equal(prev.RecoveryKeys, next.RecoveryKeys) {
		add(40, true, "kurtarma anahtarları değişiyor")
	}
	if !sameCoordinator(prev.Coordinator, next.Coordinator) {
		add(30, true, "koordinatör değişiyor")
	}
	if prev.Lockdown != nil && next.Lockdown == nil {
		add(20, true, "acil kilit kaldırılıyor")
	}
	if prev.Lockdown == nil && next.Lockdown != nil {
		add(0, false, "acil kilit açılıyor (erişim daralır)")
	}
	if n := len(next.RevokedAdmins) - len(prev.RevokedAdmins); n > 0 {
		add(0, false, "%d yönetici yetkisi geri alınıyor", n)
	}
	if prev.ExitUsers != nil && next.ExitUsers == nil {
		add(15, true, "çıkış düğümü kısıtlaması kalkıyor")
	}
	if n := len(next.Invites) - len(prev.Invites); n > 0 {
		add(5*n, true, "%d yeni davet", n)
	}

	var parts []string
	for _, it := range r.Items {
		r.Score += it.Points
		r.Widens = r.Widens || it.Widens
	}
	if added > 0 {
		parts = append(parts, fmt.Sprintf("%d cihaz eklenecek", added))
	}
	if removed > 0 {
		parts = append(parts, fmt.Sprintf("%d cihaz çıkarılacak", removed))
	}
	if widening > 0 {
		parts = append(parts, fmt.Sprintf("%d kural erişimi genişletecek", widening))
	}
	if narrowing > 0 {
		parts = append(parts, fmt.Sprintf("%d kural erişimi daraltacak", narrowing))
	}
	if len(parts) == 0 {
		parts = append(parts, "erişimi değiştiren bir değişiklik yok")
	}
	r.Summary = strings.Join(parts, ", ")
	switch {
	case r.Score >= 100:
		r.Level = RiskCritical
	case r.Score >= 50:
		r.Level = RiskHigh
	case r.Score >= 20:
		r.Level = RiskMedium
	default:
		r.Level = RiskLow
	}
	if r.Items == nil {
		r.Items = []RiskItem{}
	}
	return r
}

// ruleDelta returns the rules of a that are not in b (multiset).
func ruleDelta(b, a []trust.Rule) []trust.Rule {
	count := make(map[string]int, len(b))
	for _, r := range b {
		count[ruleKey(r)]++
	}
	var out []trust.Rule
	for _, r := range a {
		k := ruleKey(r)
		if count[k] > 0 {
			count[k]--
			continue
		}
		out = append(out, r)
	}
	return out
}

func ruleKey(r trust.Rule) string {
	return fmt.Sprintf("%v|%v|%s|%v|%s|%s|%v|%v|%v|%v|%v", r.From, r.To, r.Protocol, r.Ports, r.Action, r.Service, r.Users, r.AllowRoot, r.AllowControl, r.AllowUnattended, r.Bidirectional)
}

// newReachablePairs counts device pairs (by name) visible in next but not
// in prev; 0 when the network is too large to compare.
func newReachablePairs(prev, next *trust.Document) int {
	if len(next.Devices) > maxReachDevices || len(prev.Devices) > maxReachDevices {
		return 0
	}
	had := make(map[[2]string]bool)
	for i, a := range prev.Devices {
		for _, b := range prev.Devices[i+1:] {
			if prev.Visible(a.Name, b.Name) {
				had[pairKey(a.Name, b.Name)] = true
			}
		}
	}
	n := 0
	for i, a := range next.Devices {
		for _, b := range next.Devices[i+1:] {
			if next.Visible(a.Name, b.Name) && !had[pairKey(a.Name, b.Name)] {
				n++
			}
		}
	}
	return n
}

func pairKey(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}
