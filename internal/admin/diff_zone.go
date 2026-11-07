package admin

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// zoneChanges describes changes of the magic_dns section and of device
// aliases (ADR-0034) for the owner's review.
func zoneChanges(prev, next *trust.Document) []string {
	var out []string
	a, b := prev.MagicDNS, next.MagicDNS
	if a == nil {
		a = &trust.MagicDNSSettings{}
	}
	if b == nil {
		b = &trust.MagicDNSSettings{}
	}
	if x, y := strings.Join(a.Search, ","), strings.Join(b.Search, ","); x != y {
		out = append(out, fmt.Sprintf("Arama alanları: %s -> %s", orNone(x), orNone(y)))
	}
	if a.DeviceSubdomains != b.DeviceSubdomains {
		out = append(out, fmt.Sprintf("Cihaz alt alanları: %s -> %s", onOff(a.DeviceSubdomains), onOff(b.DeviceSubdomains)))
	}
	for _, r := range b.Records {
		if !slices.Contains(a.Records, r) {
			out = append(out, "+ DNS kaydı "+recordString(r))
		}
	}
	for _, r := range a.Records {
		if !slices.Contains(b.Records, r) {
			out = append(out, "- DNS kaydı "+recordString(r))
		}
	}
	before := make(map[string][]string, len(prev.Devices))
	for _, d := range prev.Devices {
		before[d.ID] = d.Aliases
	}
	for _, d := range next.Devices {
		if old := before[d.ID]; !slices.Equal(old, d.Aliases) {
			out = append(out, fmt.Sprintf("%s takma adları: %s -> %s", d.Name, orNone(strings.Join(old, ",")), orNone(strings.Join(d.Aliases, ","))))
		}
	}
	return out
}

func recordString(r trust.DNSRecord) string {
	if r.Type == trust.RecordSRV {
		return fmt.Sprintf("%s SRV %d %d %d %s", r.Name, r.Priority, r.Weight, r.Port, r.Value)
	}
	return r.Name + " " + r.Type + " " + r.Value
}

func orNone(s string) string {
	if s == "" {
		return "yok"
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "açık"
	}
	return "kapalı"
}
