package coordinator

import (
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Information minimisation, coordinator side (#629, ADR-0182). The
// coordinator only needs, per device: its id, WireGuard key, overlay
// addresses, expiry and whether it holds the admin role (CoordinatorView).
// Names, tags, groups and rules are needed for one thing only: which peers'
// endpoints a device may learn (TunnelPeersOf). When the owner seals the
// policy for the members (the document format belongs to the trust
// package's owner; the coordinator only asks SealedPolicy whether the
// policy it sees is a sealed placeholder), a blind coordinator hands every
// member the endpoints of all current members instead and the devices
// enforce the rules themselves, as they already do for traffic. Names never
// reach the logs in blind mode (redacting logger, g2_meta.go).
//
// The trade-off is explicit: a member learns more endpoints than its rules
// let it use. The coordinator learns less: no names, no rules.

// SealedPolicyProbe reports whether doc's policy part is sealed for the
// members, i.e. the coordinator must not rely on names, tags or rules. It is
// implemented by the owner of the document format (trust package).
type SealedPolicyProbe func(doc *trust.Document) bool

// ViewEntry is everything the coordinator needs about one device.
type ViewEntry struct {
	ID           string
	WireGuardKey trust.Key
	IPv4, IPv6   netip.Addr
	ExpiresAt    time.Time
	Admin        bool
}

// CoordinatorView projects doc onto the fields the coordinator uses.
func CoordinatorView(doc *trust.Document) []ViewEntry {
	out := make([]ViewEntry, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		out = append(out, ViewEntry{ID: d.ID, WireGuardKey: d.WireGuardKey, IPv4: d.IPv4, IPv6: d.IPv6, ExpiresAt: d.ExpiresAt, Admin: d.HasRole(trust.RoleAdmin)})
	}
	return out
}

// blind reports whether this request must be served without the policy.
func (s *Server) blind(doc *trust.Document) bool {
	// A members-only document (ADR-0178) has no names or rules to use: the
	// coordinator is blind whatever its own setting says.
	if trust.IsMembersOnly(doc) {
		return true
	}
	return s.g2 != nil && s.g2.hard.Blind && s.cfg.SealedPolicy != nil && s.cfg.SealedPolicy(doc)
}

// visiblePeers returns the devices whose endpoints self may learn.
func (s *Server) visiblePeers(doc *trust.Document, self *trust.Device) []trust.Device {
	if !s.blind(doc) {
		return doc.TunnelPeersOf(self.Name)
	}
	now := s.cfg.Now()
	out := make([]trust.Device, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		if d.ID != self.ID && now.Before(d.ExpiresAt) {
			out = append(out, d)
		}
	}
	return out
}
