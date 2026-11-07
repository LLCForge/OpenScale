package magicdns

import (
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

// Management panel name (ADR-0191). "yonetim.<network domain>" resolves to
// the devices the signed document lets serve the remote panel (an enabled
// panel rule names them as destination, ADR-0107). The name exists only
// when it is unambiguous: no device, alias or magic_dns record may use the
// label, otherwise the name is not answered and the panel does not accept
// it either (PanelHosts is the single source for both).

// PanelLabel is the panel's label under the network domain.
const PanelLabel = "yonetim"

// PanelHosts returns the devices "yonetim.<domain>" resolves to, sorted by
// name; nil when the name is not answered.
func PanelHosts(doc *trust.Document) []trust.Device {
	if doc == nil || doc.DNSDomain == "" {
		return nil
	}
	if doc.MagicDNS != nil {
		for _, r := range doc.MagicDNS.Records {
			if r.Name == PanelLabel || strings.HasSuffix(r.Name, "."+PanelLabel) {
				return nil
			}
		}
	}
	var out []trust.Device
	for _, d := range doc.Devices {
		if d.Name == PanelLabel || slices.Contains(d.Aliases, PanelLabel) {
			return nil
		}
		if doc.HostsService(d.Name, trust.ServicePanel) {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b trust.Device) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// PanelName returns "yonetim.<domain>" when the name is answered, "" else.
func PanelName(doc *trust.Document) string {
	if len(PanelHosts(doc)) == 0 {
		return ""
	}
	return PanelLabel + "." + doc.DNSDomain
}

// panelAnswer answers the panel name inside lookup.
func (z zone) panelAnswer(rel string, owner dnsmessage.Name, qtype dnsmessage.Type) (bool, []rr) {
	if rel != PanelLabel {
		return false, nil
	}
	hosts := PanelHosts(z.doc)
	if len(hosts) == 0 {
		return false, nil
	}
	var out []rr
	for _, d := range hosts {
		out = append(out, addrRRs(owner, qtype, d.IPv4, d.IPv6)...)
	}
	return true, out
}
