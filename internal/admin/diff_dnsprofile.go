package admin

import (
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// DNSProfileString describes one DNS filter profile (#416) for diffs and
// the command line.
func DNSProfileString(p trust.DNSProfile) string {
	var flags []string
	if p.SafeSearch {
		flags = append(flags, "güvenli arama")
	}
	if p.NoBlocklist {
		flags = append(flags, "engel listesi yok")
	}
	s := p.Name + ": " + strings.Join(p.Members, ", ")
	if len(flags) > 0 {
		s += " (" + strings.Join(flags, ", ") + ")"
	}
	return s
}

// dnsProfileChanges lists added, removed and changed profiles.
func dnsProfileChanges(prev, next *trust.Document) []string {
	old := make(map[string]trust.DNSProfile, len(prev.DNSProfiles))
	for _, p := range prev.DNSProfiles {
		old[p.Name] = p
	}
	var out []string
	seen := make(map[string]bool, len(next.DNSProfiles))
	for _, p := range next.DNSProfiles {
		seen[p.Name] = true
		o, ok := old[p.Name]
		switch {
		case !ok:
			out = append(out, "DNS profili eklendi: "+DNSProfileString(p))
		case DNSProfileString(o) != DNSProfileString(p):
			out = append(out, fmt.Sprintf("DNS profili değişti: %s -> %s", DNSProfileString(o), DNSProfileString(p)))
		}
	}
	for _, p := range prev.DNSProfiles {
		if !seen[p.Name] {
			out = append(out, "DNS profili kaldırıldı: "+p.Name)
		}
	}
	return out
}
