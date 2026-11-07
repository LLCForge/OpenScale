package magicdns

import (
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// serviceOwner answers the names of published services (ADR-0139):
// "<service>.<device>" resolves to the device when an enabled serve rule
// names it as destination, even without device subdomains (F-055). Only
// one label below the device is answered; the service itself decides
// which names it serves.
func (z zone) serviceOwner(rel string) (trust.Device, bool) {
	svc, dev, ok := strings.Cut(rel, ".")
	if !ok || strings.Contains(dev, ".") || !serviceLabel(svc) {
		return trust.Device{}, false
	}
	d, ok := z.owners[dev]
	if !ok || !z.doc.HostsService(d.Name, trust.ServiceServe) {
		return trust.Device{}, false
	}
	return d, true
}

// serviceLabel reports whether s is a service name label.
func serviceLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
