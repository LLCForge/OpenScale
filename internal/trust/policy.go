package trust

import (
	"net/netip"
	"strings"
)

// Rule evaluation used by devices and the coordinator (ADR-0007, ADR-0013,
// ADR-0021).
//
// Order of evaluation for traffic from src to dst:
//  1. A device never matches itself.
//  2. Disabled rules are skipped.
//  3. If any matching deny rule exists, the traffic is denied.
//  4. Otherwise it is allowed if any matching allow rule exists.
//  5. Otherwise it is denied (default deny).
//
// A document without tags, groups, deny or disabled rules and numeric
// protocols evaluates exactly as before ADR-0021.

// subject is a device as seen by rule matching: its name, tags and the
// groups it belongs to (resolved once, so rule evaluation stays linear in
// the number of rule entries).
type subject struct {
	name   string
	tags   []string
	groups map[string]bool
	// v4 and v6 are the device's tunnel addresses for CIDR and "host:"
	// entries (ADR-0120); invalid for a name that is not a device.
	v4, v6 netip.Addr
	// routed marks an address behind a subnet router (ADR-0133): only
	// CIDR and "host:" entries cover it, never "*".
	routed bool
}

func (doc *Document) subject(name string) subject {
	s := subject{name: name}
	for i := range doc.Devices {
		if doc.Devices[i].Name == name {
			s.tags = doc.Devices[i].Tags
			s.v4, s.v6 = doc.Devices[i].IPv4, doc.Devices[i].IPv6
			break
		}
	}
	doc.fillGroups(&s)
	return s
}

// fillGroups resolves the groups s belongs to: by name, by tag or, for a
// CIDR or "host:" member (#277, ADR-0232), by one of its addresses. A
// routed address (ADR-0133) has no name or tags and joins a group only
// through an explicit range member.
func (doc *Document) fillGroups(s *subject) {
	for _, g := range doc.Groups {
		for _, m := range g.Members {
			if isAddrEntry(m) {
				if doc.addrEntryMatches(m, *s) {
					if s.groups == nil {
						s.groups = make(map[string]bool, len(doc.Groups))
					}
					s.groups[g.Name] = true
					break
				}
				continue
			}
			t, isTag := strings.CutPrefix(m, TagPrefix)
			if (isTag && s.hasTag(t)) || (!isTag && s.name != "" && m == s.name) {
				if s.groups == nil {
					s.groups = make(map[string]bool, len(doc.Groups))
				}
				s.groups[g.Name] = true
				break
			}
		}
	}
}

func (s subject) hasTag(tag string) bool {
	for _, t := range s.tags {
		if t == tag {
			return true
		}
	}
	return false
}

// entryMatches reports whether one rule entry ("*", a device name,
// "tag:x" or "group:x") covers s.
func (doc *Document) entryMatches(e string, s subject) bool {
	if e == RuleWildcard {
		return !s.routed
	}
	if isAddrEntry(e) {
		return doc.addrEntryMatches(e, s)
	}
	if t, ok := strings.CutPrefix(e, TagPrefix); ok {
		return s.hasTag(t)
	}
	if g, ok := strings.CutPrefix(e, GroupPrefix); ok {
		return s.groups[g]
	}
	return e == s.name
}

func (doc *Document) matchesAny(entries []string, s subject) bool {
	for _, e := range entries {
		if doc.entryMatches(e, s) {
			return true
		}
	}
	return false
}

// Visible reports whether two distinct devices share at least one enabled
// allow rule in either direction. Only visible peers are configured and
// told about each other's endpoints. A direction covered by a deny rule for
// every protocol ("any") does not count.
func (doc *Document) Visible(a, b string) bool {
	if a == b {
		return false
	}
	if doc.Lockdown != nil { // #361, p01_fields.go
		return doc.lockdownAllows(a, b) || doc.lockdownAllows(b, a)
	}
	sa, sb := doc.subject(a), doc.subject(b)
	return doc.directionVisible(sa, sb) || doc.directionVisible(sb, sa)
}

func (doc *Document) directionVisible(src, dst subject) bool {
	allowed := false
	for _, r := range doc.Rules {
		// Visibility ignores time conditions (ADR-0120): peers stay stable
		// and the destination's packet filter is the security boundary.
		if r.Disabled || !doc.ruleCovers(r, src, dst) {
			continue
		}
		if r.IsDeny() {
			if r.Protocol == ProtocolAny && !r.HasTimeConditions() {
				return false
			}
			continue
		}
		allowed = true
	}
	return allowed
}

// PeersOf returns the devices visible to the named device.
func (doc *Document) PeersOf(name string) []Device {
	var peers []Device
	for _, d := range doc.Devices {
		if doc.Visible(name, d.Name) {
			peers = append(peers, d)
		}
	}
	return peers
}

// protoUnknown marks a packet protocol that only "any" rules match.
const protoUnknown = -1

// Allows reports whether device src may open a new connection to device
// dst. port is ignored for ICMP and other protocols. proto is tcp, udp,
// icmp or a numeric protocol; anything else matches only "any" rules.
func (doc *Document) Allows(src, dst string, proto Protocol, port uint16) bool {
	num := protoUnknown
	switch proto {
	case ProtocolTCP:
		num = ipProtoTCP
	case ProtocolUDP:
		num = ipProtoUDP
	case ProtocolICMP:
		num = ipProtoICMP
	default:
		if n, ok := ProtocolNumber(proto); ok {
			num = int(n)
		}
	}
	return doc.allows(src, dst, num, port)
}

// AllowsIP is Allows with the packet's IANA protocol number (the IPv4
// protocol or IPv6 next header field): 6 is tcp, 17 udp, 1 and 58 icmp.
// Packet filters should prefer it so numeric rules (F-074) take effect.
func (doc *Document) AllowsIP(src, dst string, ipProto uint8, port uint16) bool {
	return doc.allows(src, dst, int(ipProto), port)
}

// allows evaluates at the device clock with an unknown ICMP type
// (evaluate in policy_ext.go, ADR-0120). Rules without the new fields
// decide exactly as before.
func (doc *Document) allows(src, dst string, num int, port uint16) bool {
	return doc.evaluate(src, dst, PacketQuery{Proto: num, Port: port, ICMPType: -1, At: timeNow()}).Allowed
}

func protoMatches(r Rule, num int, port uint16) bool {
	if r.Service != "" {
		// A service rule opens only its service's fixed TCP port
		// (ADR-0030, ADR-0031).
		return num == ipProtoTCP && (port == r.Service.Port() || r.Service.opensE2EPort(port))
	}
	switch r.Protocol {
	case ProtocolAny:
		return true
	case ProtocolICMP:
		return num == ipProtoICMP || num == ipProtoICMPv6
	case ProtocolTCP:
		return num == ipProtoTCP && portAllowed(r.Ports, port)
	case ProtocolUDP:
		return num == ipProtoUDP && portAllowed(r.Ports, port)
	default:
		n, ok := ProtocolNumber(r.Protocol)
		return ok && int(n) == num
	}
}

func portAllowed(specs []string, port uint16) bool {
	for _, s := range specs {
		lo, hi, err := ParsePortRange(s)
		if err == nil && port >= lo && port <= hi {
			return true
		}
	}
	return false
}

// MayUseExitNode reports whether the named device may send its internet
// traffic through an exit node. Without an exit_users list every device
// may, as before ADR-0021. The exit node's forwarding path must check this
// for every new flow; peer configuration alone is not a security boundary.
func (doc *Document) MayUseExitNode(name string) bool {
	if doc.Lockdown != nil { // #361: no exit traffic while locked
		return false
	}
	if doc.ExitUsers == nil {
		return true
	}
	return doc.matchesAny(*doc.ExitUsers, doc.subject(name))
}

// TunnelPeersOf returns the devices that get a WireGuard peer entry with
// the named device: the visible ones, plus admin devices, exit nodes the
// device may use and, for an admin, every device; an exit node peers with
// every device allowed to use it. The extra peers carry only the owner's
// status queries (ADR-0015) and exit traffic; traffic between them is still
// decided by Allows.
func (doc *Document) TunnelPeersOf(name string) []Device {
	self, ok := doc.DeviceByName(name)
	if !ok {
		return nil
	}
	isAdmin, isExit := self.HasRole(RoleAdmin), self.HasRole(RoleExitNode)
	selfMayExit := doc.MayUseExitNode(name)
	var peers []Device
	for _, d := range doc.Devices {
		if d.Name == name {
			continue
		}
		// Exit nodes peer with every device that may use them (ADR-0018,
		// ADR-0021); the packet filter still decides what flows.
		exitPair := (isExit && doc.MayUseExitNode(d.Name)) || (d.HasRole(RoleExitNode) && selfMayExit)
		// Subnet routers peer with devices a rule lets reach their routes
		// (ADR-0133).
		if isAdmin || d.HasRole(RoleAdmin) || exitPair || doc.Visible(name, d.Name) || doc.routePeer(name, d.Name) {
			peers = append(peers, d)
		}
	}
	return peers
}
