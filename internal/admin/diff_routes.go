package admin

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// routingChanges lists approved subnet routes, plain WireGuard exit nodes
// and address strategy changes (ADR-0133). Approving a route is a signed
// change like any other, so the owner sees it before signing (F-033).
func routingChanges(prev, next *trust.Document) []string {
	var out []string
	before := map[string][]netip.Prefix{}
	for _, d := range prev.Devices {
		before[d.ID] = d.Routes
	}
	for _, d := range next.Devices {
		old := before[d.ID]
		for _, p := range d.Routes {
			if !slices.Contains(old, p) {
				out = append(out, fmt.Sprintf("+ alt ağ rotası %s (yönlendirici %s)", p, d.Name))
			}
		}
		for _, p := range old {
			if !slices.Contains(d.Routes, p) {
				out = append(out, fmt.Sprintf("- alt ağ rotası %s (yönlendirici %s)", p, d.Name))
			}
		}
	}
	prevExits := map[string]trust.ExternalExit{}
	for _, x := range prev.ExternalExits {
		prevExits[x.Name] = x
	}
	for _, x := range next.ExternalExits {
		old, ok := prevExits[x.Name]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("+ düz WireGuard çıkış düğümü %s (%s, DNS %s)", x.Name, x.Endpoint, x.DNS))
		case old != x:
			out = append(out, fmt.Sprintf("~ düz WireGuard çıkış düğümü %s (%s, DNS %s)", x.Name, x.Endpoint, x.DNS))
		}
		delete(prevExits, x.Name)
	}
	for name := range prevExits {
		out = append(out, "- düz WireGuard çıkış düğümü "+name)
	}
	slices.Sort(out[len(out)-len(prevExits):])
	if a, b := addressingString(prev.Addressing), addressingString(next.Addressing); a != b {
		out = append(out, fmt.Sprintf("Adres atama: %s -> %s", a, b))
	}
	return out
}

func addressingString(a *trust.Addressing) string {
	if a == nil {
		return "ilk boş adres"
	}
	s := "ilk boş adres"
	switch a.Strategy {
	case trust.AssignSequential:
		s = "sıralı"
	case trust.AssignRandom:
		s = "rastgele"
	}
	if len(a.Reserved) > 0 {
		parts := make([]string, len(a.Reserved))
		for i, p := range a.Reserved {
			parts[i] = p.String()
		}
		s += ", ayrılmış " + strings.Join(parts, ",")
	}
	return s
}
