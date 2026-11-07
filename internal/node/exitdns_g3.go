package node

import "net/netip"

// peerAddrRefused is exitDNSRefused for a peer known by its overlay address,
// for the other handlers that run before the filter and answer through the
// inject queue: a chained entry's relayed DNS, status queries.
func (e *Engine) peerAddrRefused(a netip.Addr) bool {
	f := e.filter
	if f == nil {
		return false
	}
	if f.Isolated() {
		return true
	}
	doc := e.cfg.Store.Document()
	if doc == nil {
		return false
	}
	for _, d := range doc.Devices {
		if d.IPv4 == a || d.IPv6 == a {
			return e.exitDNSRefused(d.Name)
		}
	}
	return false
}

// exitDNSRefused reports whether this device's own quarantine or lost mode
// (isolation) decision refuses peer. The exit DNS handlers run in
// intercept, before the packet filter, and answer through the inject
// queue, which the filter's outbound check does not see; so they must
// apply the same decision themselves (filter/g3_quarantine.go): a
// quarantined peer gets nothing from this exit node, and while isolated
// nothing is served to any peer. The query is dropped, not answered with
// REFUSED: an answer would itself be a packet to a refused peer.
func (e *Engine) exitDNSRefused(peer string) bool {
	f := e.filter
	if f == nil {
		return false
	}
	if f.Isolated() {
		return true
	}
	now := e.cfg.Now()
	for _, q := range f.Quarantined() {
		if q.Peer == peer && (q.Until.IsZero() || now.Before(q.Until)) {
			return true
		}
	}
	return false
}
