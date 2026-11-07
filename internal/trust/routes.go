package trust

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Subnet routing (ADR-0133; #70, #258, F-032, F-033, F-040, F-073).
//
// A device forwards traffic for the address ranges in its Routes field.
// The field is part of the root-signed document, so a route exists only
// after the owner signs it: a device can ask for a route with a signed
// route advertisement (route_advert.go), but nothing it says on its own
// makes a route valid, and there is no automatic approver.
//
// Rules reach addresses behind a router only through explicit CIDR or
// "host:" entries that lie inside an approved route. The wildcard "*",
// device names, tags and groups never cover them, so approving a route
// changes nothing until the owner also signs a rule for it, and no rule
// written before ADR-0133 changes its meaning.

// Route limits.
const (
	// MaxDeviceRoutes bounds the routes one device may forward.
	MaxDeviceRoutes = 32
	// minRouteBits4 and minRouteBits6 bound how wide a route may be.
	minRouteBits4 = 8
	minRouteBits6 = 16
)

// validateRoutePrefix checks one route: a masked prefix inside the private
// IPv4 ranges (10/8, 172.16/12, 192.168/16, 100.64/10) or the IPv6 unique
// local range. Internet ranges are refused: the packet filter treats
// internet destinations as exit node traffic, and a route must never make
// such traffic bypass the rules (ADR-0133).
func validateRoutePrefix(p netip.Prefix) error {
	if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return fmt.Errorf("route %s is not a masked CIDR range", p)
	}
	if p.Addr().Is4() {
		if p.Bits() < minRouteBits4 {
			return fmt.Errorf("route %s is wider than /%d", p, minRouteBits4)
		}
		for _, allowed := range allowedIPv4Ranges {
			if allowed.Bits() <= p.Bits() && allowed.Contains(p.Addr()) {
				return nil
			}
		}
		return fmt.Errorf("route %s must be inside 10/8, 172.16/12, 192.168/16 or 100.64/10", p)
	}
	if p.Bits() < minRouteBits6 {
		return fmt.Errorf("route %s is wider than /%d", p, minRouteBits6)
	}
	if !ulaRange.Contains(p.Addr()) {
		return fmt.Errorf("route %s must be inside the fc00::/7 unique local range", p)
	}
	return nil
}

// ValidateRoutePrefix is validateRoutePrefix for callers outside the
// package (CLI and panel input checks).
func ValidateRoutePrefix(p netip.Prefix) error { return validateRoutePrefix(p) }

// overlapsOverlay reports whether p overlaps one of the network prefixes.
func (doc *Document) overlapsOverlay(p netip.Prefix) bool {
	for _, o := range []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix} {
		if o.IsValid() && o.Overlaps(p) {
			return true
		}
	}
	return false
}

// validateRouting checks device routes, external exit nodes and the address
// assignment settings (ADR-0133). Called by Validate.
func (doc *Document) validateRouting(names map[string]bool) error {
	type owned struct {
		prefix netip.Prefix
		device string
	}
	var all []owned
	for _, d := range doc.Devices {
		if len(d.Routes) == 0 {
			continue
		}
		if len(d.Routes) > MaxDeviceRoutes {
			return fmt.Errorf("device %s: at most %d routes are allowed", d.Name, MaxDeviceRoutes)
		}
		if d.Ephemeral {
			// An ephemeral device leaves the document by itself; rules that
			// name its routes would then make the next version invalid.
			return fmt.Errorf("device %s: ephemeral devices cannot route subnets", d.Name)
		}
		for _, p := range d.Routes {
			if err := validateRoutePrefix(p); err != nil {
				return fmt.Errorf("device %s: %w", d.Name, err)
			}
			if doc.overlapsOverlay(p) {
				return fmt.Errorf("device %s: route %s overlaps the network prefixes", d.Name, p)
			}
			// Overlapping routes (F-040) are refused: WireGuard needs one
			// owner per address and the filter decides by address. The
			// 4via6 design of ADR-0133 is the way to serve them later.
			for _, o := range all {
				if o.prefix.Overlaps(p) {
					return fmt.Errorf("device %s: route %s overlaps route %s of %s", d.Name, p, o.prefix, o.device)
				}
			}
			all = append(all, owned{p, d.Name})
		}
	}
	if err := doc.validateExternalExits(names); err != nil {
		return err
	}
	return doc.validateAddressing()
}

// insideApprovedRoute reports whether p lies inside one approved route.
func (doc *Document) insideApprovedRoute(p netip.Prefix) bool {
	_, _, ok := doc.routeContaining(p)
	return ok
}

func (doc *Document) routeContaining(p netip.Prefix) (Device, netip.Prefix, bool) {
	if !p.IsValid() {
		return Device{}, netip.Prefix{}, false
	}
	for _, d := range doc.Devices {
		for _, r := range d.Routes {
			if r.Addr().Is4() == p.Addr().Is4() && r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
				return d, r, true
			}
		}
	}
	return Device{}, netip.Prefix{}, false
}

// RouteOwner returns the device whose approved route contains a, and that
// route.
func (doc *Document) RouteOwner(a netip.Addr) (Device, netip.Prefix, bool) {
	a = a.Unmap()
	if !a.IsValid() {
		return Device{}, netip.Prefix{}, false
	}
	return doc.routeContaining(netip.PrefixFrom(a, a.BitLen()))
}

// AllRoutes lists every approved route with its device, in document order.
func (doc *Document) AllRoutes() []DeviceRoute {
	var out []DeviceRoute
	for _, d := range doc.Devices {
		for _, r := range d.Routes {
			out = append(out, DeviceRoute{Device: d.Name, Prefix: r})
		}
	}
	return out
}

// DeviceRoute is an approved route and the device that forwards it.
type DeviceRoute struct {
	Device string       `json:"device"`
	Prefix netip.Prefix `json:"prefix"`
}

// TrafficEnd is one end of routed traffic: a device by name, or an address
// behind a subnet router (Device empty).
type TrafficEnd struct {
	Device string
	Addr   netip.Addr
}

// DeviceEnd is a traffic end naming a device.
func DeviceEnd(name string) TrafficEnd { return TrafficEnd{Device: name} }

// AddrEnd is a traffic end naming an address behind a subnet router.
func AddrEnd(a netip.Addr) TrafficEnd { return TrafficEnd{Addr: a.Unmap()} }

func (doc *Document) endSubject(e TrafficEnd) subject {
	if e.Device != "" {
		return doc.subject(e.Device)
	}
	s := subject{routed: true}
	if e.Addr.Is4() {
		s.v4 = e.Addr
	} else {
		s.v6 = e.Addr
	}
	doc.fillGroups(&s) // range members of groups (#277, ADR-0232)
	return s
}

// EvaluateRouted decides traffic in which one end is an address behind a
// subnet router. The order is that of ADR-0021 (a matching deny rule wins,
// otherwise a matching allow rule allows, otherwise deny). Service rules
// never apply: services run on OpenScale devices, not on the hosts behind
// a router. An address that is not inside an approved route is refused,
// and so is traffic between two routed addresses.
func (doc *Document) EvaluateRouted(src, dst TrafficEnd, q PacketQuery) Decision {
	d := Decision{Rule: -1, Reason: ReasonDefaultDeny}
	if (src.Device == "") == (dst.Device == "") {
		return d
	}
	for _, e := range []TrafficEnd{src, dst} {
		if e.Device == "" {
			if _, _, ok := doc.RouteOwner(e.Addr); !ok {
				return d
			}
		}
	}
	s, t := doc.endSubject(src), doc.endSubject(dst)
	deny := -1
	for i, r := range doc.Rules {
		if doc.ruleOff(r) || r.Service != "" || !r.ActiveAt(q.At) || !ruleMatchesPacket(r, q) || !doc.ruleCovers(r, s, t) {
			continue
		}
		if r.IsDeny() {
			if deny < 0 {
				deny = i
			}
			continue
		}
		d.Allows = append(d.Allows, i)
	}
	switch {
	case deny >= 0:
		d.Rule, d.Reason = deny, ReasonDeny
	case len(d.Allows) > 0:
		d.Allowed, d.Rule, d.Reason = true, d.Allows[0], ReasonAllow
	}
	return d
}

// AllowsRoutedPacketAt reports whether the routed connection q may open.
func (doc *Document) AllowsRoutedPacketAt(src, dst TrafficEnd, q PacketQuery) bool {
	return doc.EvaluateRouted(src, dst, q).Allowed
}

// entriesOverlap reports whether one address entry of a rule list overlaps
// one of routes.
func (doc *Document) entriesOverlap(entries []string, routes []netip.Prefix) bool {
	for _, e := range entries {
		if g, ok := strings.CutPrefix(e, GroupPrefix); ok {
			// A group's range members reach routes too (#277, ADR-0232).
			if grp, found := doc.GroupByName(g); found && doc.entriesOverlap(addrMembers(grp.Members), routes) {
				return true
			}
			continue
		}
		if !isAddrEntry(e) {
			continue
		}
		p, ok := doc.entryPrefix(e)
		if !ok {
			continue
		}
		for _, r := range routes {
			if r.Overlaps(p) {
				return true
			}
		}
	}
	return false
}

// RouteVisible reports whether device a has an enabled allow rule to or
// from an address in device b's routes. Such a pair becomes a tunnel peer
// and a carries b's routes in b's allowed addresses. Like Visible it
// ignores time conditions and deny rules: peers stay stable and the packet
// filter decides each connection.
func (doc *Document) RouteVisible(a, b string) bool {
	if a == b {
		return false
	}
	router, ok := doc.DeviceByName(b)
	if !ok || len(router.Routes) == 0 {
		return false
	}
	sa := doc.subject(a)
	for _, r := range doc.Rules {
		if doc.ruleOff(r) || r.IsDeny() || r.Service != "" {
			continue
		}
		if doc.matchesAny(r.From, sa) && doc.entriesOverlap(r.To, router.Routes) {
			return true
		}
		// Hosts behind the router opening connections to a (also covers
		// the second direction of a bidirectional rule).
		if doc.matchesAny(r.To, sa) && doc.entriesOverlap(r.From, router.Routes) {
			return true
		}
	}
	return false
}

// RoutesVia returns the routes of peer that self reaches through it: all
// of peer's approved routes when RouteVisible(self, peer), otherwise none.
func (doc *Document) RoutesVia(self, peer string) []netip.Prefix {
	if !doc.RouteVisible(self, peer) {
		return nil
	}
	d, _ := doc.DeviceByName(peer)
	return slices.Clone(d.Routes)
}

// routePeer reports whether a and b are tunnel peers because of routes.
func (doc *Document) routePeer(a, b string) bool {
	return doc.RouteVisible(a, b) || doc.RouteVisible(b, a)
}

// --- editing ---

// normalizeRoutes sorts and de-duplicates routes; an empty list is nil so
// the field is omitted.
func normalizeRoutes(routes []netip.Prefix) []netip.Prefix {
	out := slices.Clone(routes)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// SetDeviceRoutes replaces the approved routes of a device. The owner's
// signature over the next document is the approval (F-033). Removing a
// route that a rule or named address still uses fails; remove those first.
func (doc *Document) SetDeviceRoutes(name string, routes []netip.Prefix) error {
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
		if idx < 0 {
			return ErrUnknownDevice
		}
		for _, p := range routes {
			if err := validateRoutePrefix(p); err != nil {
				return err
			}
		}
		doc.Devices[idx].Routes = normalizeRoutes(routes)
		return nil
	})
}

// ApproveRoutes adds routes to a device's approved routes.
func (doc *Document) ApproveRoutes(name string, routes []netip.Prefix) error {
	d, ok := doc.DeviceByName(name)
	if !ok {
		return ErrUnknownDevice
	}
	return doc.SetDeviceRoutes(name, append(slices.Clone(d.Routes), routes...))
}

// RemoveDeviceRoute withdraws one approved route.
func (doc *Document) RemoveDeviceRoute(name string, route netip.Prefix) error {
	d, ok := doc.DeviceByName(name)
	if !ok {
		return ErrUnknownDevice
	}
	if !slices.Contains(d.Routes, route) {
		return errors.New("route not found")
	}
	return doc.SetDeviceRoutes(name, slices.DeleteFunc(slices.Clone(d.Routes), func(p netip.Prefix) bool { return p == route }))
}

// dropUnroutedRefs removes rule entries and named addresses that lie
// outside the overlay and outside every approved route, for example after
// the router that served them was revoked. Rules left without a source or
// destination are dropped and counted, like RevokeDevice does for device
// entries; revoking a router must never fail because of its routes.
func (doc *Document) dropUnroutedRefs() int {
	stale := func(p netip.Prefix) bool {
		return p.IsValid() && !doc.insideOverlay(p) && !doc.insideApprovedRoute(p)
	}
	staleHosts := map[string]bool{}
	if len(doc.Hosts) > 0 {
		doc.Hosts = slices.DeleteFunc(doc.Hosts, func(h NamedAddress) bool {
			if stale(h.Prefix) {
				staleHosts[h.Name] = true
				return true
			}
			return false
		})
		if len(doc.Hosts) == 0 {
			doc.Hosts = nil
		}
	}
	staleEntry := func(e string) bool {
		if h, ok := strings.CutPrefix(e, HostPrefix); ok {
			return staleHosts[h]
		}
		if !strings.Contains(e, "/") {
			return false
		}
		p, err := netip.ParsePrefix(e)
		return err == nil && stale(p)
	}
	dropped := 0
	kept := doc.Rules[:0]
	for _, r := range doc.Rules {
		r.From = slices.DeleteFunc(r.From, staleEntry)
		r.To = slices.DeleteFunc(r.To, staleEntry)
		if len(r.From) == 0 || len(r.To) == 0 {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	doc.Rules = kept
	return dropped
}

// --- plain WireGuard exit nodes (F-045, #264) ---

// MaxExternalExits bounds the plain WireGuard exit nodes of a network.
const MaxExternalExits = 8

// ExternalExit is the owner's own plain WireGuard server used as an exit
// node (F-045). It is not a member: it has no signing key, receives no
// document and is reached only for internet traffic. The owner configures
// the server with each member's WireGuard key and overlay addresses as
// allowed IPs (ExternalExitPeerConfig prints that part) and masquerades
// them. Commercial VPN providers are out of scope (ADR-0008): they would be
// a third party.
type ExternalExit struct {
	Name         string `json:"name"`
	WireGuardKey Key    `json:"wireguard_key"`
	Endpoint     string `json:"endpoint"`
	// DNS is the resolver inside the server's tunnel; every query of a
	// device using this exit goes there.
	DNS         netip.Addr `json:"dns"`
	Description string     `json:"description,omitempty"`
}

// ExternalExitByName returns a plain WireGuard exit node.
func (doc *Document) ExternalExitByName(name string) (ExternalExit, bool) {
	for _, x := range doc.ExternalExits {
		if x.Name == name {
			return x, true
		}
	}
	return ExternalExit{}, false
}

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || len(host) > maxEndpointHostLen {
		return errors.New("endpoint must be host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strings.HasPrefix(port, "0") {
		return errors.New("endpoint port must be 1-65535")
	}
	if _, err := netip.ParseAddr(host); err != nil && !isValidDomain(host) {
		return errors.New("endpoint host must be an IP address or domain name")
	}
	return nil
}

func (doc *Document) validateExternalExits(names map[string]bool) error {
	if len(doc.ExternalExits) == 0 {
		return nil
	}
	if len(doc.ExternalExits) > MaxExternalExits {
		return fmt.Errorf("at most %d external exit nodes are allowed", MaxExternalExits)
	}
	keys := map[Key]bool{}
	for _, d := range doc.Devices {
		keys[d.SigningKey], keys[d.WireGuardKey] = true, true
	}
	if doc.Coordinator != nil {
		keys[doc.Coordinator.WireGuardKey] = true
	}
	for _, c := range doc.Coordinators {
		keys[c.WireGuardKey] = true
	}
	for _, r := range doc.Revoked {
		keys[r.SigningKey], keys[r.WireGuardKey] = true, true
	}
	seen := map[string]bool{}
	for i, x := range doc.ExternalExits {
		switch {
		case !isValidLabel(x.Name) || x.Name == CoordinatorName:
			return fmt.Errorf("external exit %d: name must be a lowercase DNS label", i)
		case names[x.Name] || seen[x.Name]:
			return fmt.Errorf("external exit %s: name is already used", x.Name)
		case x.WireGuardKey.IsZero() || keys[x.WireGuardKey] || doc.keyRetired(x.WireGuardKey):
			return fmt.Errorf("external exit %s: wireguard_key is missing or already used", x.Name)
		case !x.DNS.IsValid() || !x.DNS.Is4() || x.DNS.IsUnspecified() || x.DNS.IsLoopback() || x.DNS.IsMulticast() ||
			x.DNS.IsLinkLocalUnicast() || doc.IPv4Prefix.Contains(x.DNS):
			return fmt.Errorf("external exit %s: dns must be an IPv4 resolver address outside the network", x.Name)
		}
		if err := validateEndpoint(x.Endpoint); err != nil {
			return fmt.Errorf("external exit %s: %w", x.Name, err)
		}
		if err := validateDescription(x.Description); err != nil {
			return fmt.Errorf("external exit %s: %w", x.Name, err)
		}
		if _, _, routed := doc.RouteOwner(x.DNS); routed {
			return fmt.Errorf("external exit %s: dns lies inside an approved route", x.Name)
		}
		seen[x.Name] = true
		keys[x.WireGuardKey] = true
	}
	return nil
}

// SetExternalExit adds or replaces a plain WireGuard exit node.
func (doc *Document) SetExternalExit(x ExternalExit) error {
	return doc.transact(func() error {
		if idx := slices.IndexFunc(doc.ExternalExits, func(o ExternalExit) bool { return o.Name == x.Name }); idx >= 0 {
			doc.ExternalExits[idx] = x
		} else {
			doc.ExternalExits = append(doc.ExternalExits, x)
		}
		return nil
	})
}

// RemoveExternalExit deletes a plain WireGuard exit node.
func (doc *Document) RemoveExternalExit(name string) error {
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.ExternalExits, func(o ExternalExit) bool { return o.Name == name })
		if idx < 0 {
			return errors.New("external exit node not found")
		}
		doc.ExternalExits = slices.Delete(doc.ExternalExits, idx, idx+1)
		if len(doc.ExternalExits) == 0 {
			doc.ExternalExits = nil
		}
		return nil
	})
}

// ExternalExitPeerConfig renders the [Peer] sections the owner adds to the
// plain WireGuard server: one per device allowed to use exit nodes, with
// the device's overlay addresses as allowed IPs. The server must
// masquerade these addresses; the text says so in a comment.
func (doc *Document) ExternalExitPeerConfig() string {
	var b strings.Builder
	b.WriteString("# OpenScale cihazları (ADR-0133). Sunucu bu adresleri internete çıkarken maskelemeli (NAT).\n")
	for _, d := range doc.Devices {
		if !doc.MayUseExitNode(d.Name) {
			continue
		}
		fmt.Fprintf(&b, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32, %s/128\n", d.Name, d.WireGuardKey, d.IPv4, d.IPv6)
	}
	return b.String()
}
