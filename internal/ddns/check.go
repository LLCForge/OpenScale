package ddns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Consistency check (#448). A device that is connected to the
// coordinator knows the address its tunnel really talks to (WireGuard
// follows the coordinator when its address changes); a dynamic DNS name
// that still resolves to the old address breaks the next start or the
// next new device, long before the running tunnels notice. Check compares
// the two.

// Status of a check.
type Status string

// Statuses.
const (
	// StatusOK: the name resolves to the observed address.
	StatusOK Status = "ok"
	// StatusStale: the name resolves, but not to the observed address.
	StatusStale Status = "stale"
	// StatusUnresolved: the name does not resolve.
	StatusUnresolved Status = "unresolved"
	// StatusUnknown: nothing to compare (an IP endpoint, or no public
	// observed address).
	StatusUnknown Status = "unknown"
)

// CheckResult is the outcome of Check.
type CheckResult struct {
	Host     string       `json:"host"`
	Resolved []netip.Addr `json:"resolved,omitempty"`
	Observed netip.Addr   `json:"observed,omitzero"`
	Status   Status       `json:"status"`
	Message  string       `json:"message"`
}

// Lookup resolves a host name.
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemLookup uses the system resolver.
func SystemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Public reports whether a is a global unicast address that is not
// private, shared (100.64/10, CGNAT) or otherwise local.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	if a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return false
	}
	return true
}

// Check resolves host and compares it with the observed address.
func Check(ctx context.Context, lookup Lookup, host string, observed netip.Addr) CheckResult {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	r := CheckResult{Host: host, Observed: observed.Unmap()}
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		r.Status, r.Message = StatusUnknown, "Koordinatör adresi bir IP adresi; dinamik DNS kullanılmıyor."
		return r
	}
	if !Public(r.Observed) {
		r.Status, r.Message = StatusUnknown, "Koordinatörün genel adresi görülemedi (aynı yerel ağ, aktarıcı veya TCP yolu); karşılaştırma yapılmadı."
		return r
	}
	if lookup == nil {
		lookup = SystemLookup
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		r.Status, r.Message = StatusUnresolved, "Ad çözülemedi: yeni cihazlar ve yeniden başlayan cihazlar koordinatörü bulamaz."
		return r
	}
	for _, a := range addrs {
		r.Resolved = append(r.Resolved, a.Unmap())
	}
	slices.SortFunc(r.Resolved, func(a, b netip.Addr) int { return a.Compare(b) })
	if slices.Contains(r.Resolved, r.Observed) {
		r.Status, r.Message = StatusOK, "Dinamik DNS kaydı koordinatörün gerçek adresini gösteriyor."
		return r
	}
	r.Status = StatusStale
	r.Message = "Dinamik DNS kaydı güncel değil: ad " + joinAddrs(r.Resolved) + " gösteriyor, koordinatör " + r.Observed.String() +
		" adresinde. Çalışan tüneller sürüyor, ama yeniden başlayan cihazlar bağlanamaz."
	return r
}

func joinAddrs(a []netip.Addr) string {
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = x.String()
	}
	return strings.Join(s, ", ")
}
