package filter

import (
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Subnet routing in the packet filter (ADR-0133). Traffic to and from an
// address behind a subnet router is decided by explicit CIDR or "host:"
// rules (trust.EvaluateRouted). On a client the filter admits flows to the
// routes of peers that a rule lets it reach; on the router it admits flows
// from peers to its own approved routes, and replies (or rule-allowed new
// flows) from those routes back to peers. Everything else stays refused.

// routeState is the filter's view of the approved routes.
type routeState struct {
	// own are the routes this device forwards.
	own []netip.Prefix
	// peer maps the routes of other devices that this device reaches
	// through them (trust.RoutesVia) to the router.
	peer []routeOwner
}

type routeOwner struct {
	prefix netip.Prefix
	device string
}

// updateRoutesLocked caches the routes of doc for self. Routes of devices
// whose membership has expired are left out: they are no longer peers.
func (f *Filter) updateRoutesLocked(doc *trust.Document, self trust.Device) {
	f.routing = routeState{}
	if doc == nil {
		return
	}
	now := f.now()
	if now.Before(self.ExpiresAt) {
		f.routing.own = append([]netip.Prefix(nil), self.Routes...)
	}
	for _, d := range doc.Devices {
		if d.Name == self.Name || len(d.Routes) == 0 || !now.Before(d.ExpiresAt) {
			continue
		}
		for _, p := range doc.RoutesVia(self.Name, d.Name) {
			f.routing.peer = append(f.routing.peer, routeOwner{p, d.Name})
		}
	}
}

func (f *Filter) ownRouteLocked(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range f.routing.own {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (f *Filter) peerRouteLocked(a netip.Addr) (string, bool) {
	a = a.Unmap()
	for _, r := range f.routing.peer {
		if r.prefix.Contains(a) {
			return r.device, true
		}
	}
	return "", false
}

// routedOutboundLocked handles a packet from the operating system into the
// tunnel that is routed traffic. handled is false for any other packet.
func (f *Filter) routedOutboundLocked(info packet.Info, peer string, isPeer bool) (verdict, handled bool) {
	if len(f.routing.own) == 0 && len(f.routing.peer) == 0 {
		return false, false
	}
	key := flowKey{info.Proto, info.Src, info.SrcPort, info.Dst, info.DstPort}
	if info.IsICMP() {
		key.localPort, key.remotePort = info.ICMPID, 0
	}
	switch {
	case !isPeer && f.selfIPs[info.Src]:
		if _, ok := f.peerRouteLocked(info.Dst); ok {
			// This device to a host behind a peer's route.
			return f.admitRouted(key, info, trust.DeviceEnd(f.self), trust.AddrEnd(info.Dst)), true
		}
	case isPeer && !f.selfIPs[info.Src] && f.ownRouteLocked(info.Src):
		// A host behind this router to a peer: the reply of a flow the peer
		// opened, or a new flow a rule allows from that address.
		return f.admitRouted(key, info, trust.AddrEnd(info.Src), trust.DeviceEnd(peer)), true
	}
	return false, false
}

// routedInboundLocked handles a packet from the tunnel to the operating
// system that is routed traffic.
func (f *Filter) routedInboundLocked(info packet.Info, peer string, isPeer bool) (verdict, handled bool) {
	if len(f.routing.own) == 0 && len(f.routing.peer) == 0 {
		return false, false
	}
	key := flowKey{info.Proto, info.Dst, info.DstPort, info.Src, info.SrcPort}
	if info.IsICMP() {
		key.localPort, key.remotePort = info.ICMPID, 0
	}
	switch {
	case !isPeer && f.selfIPs[info.Dst]:
		if _, ok := f.peerRouteLocked(info.Src); ok {
			// A host behind a peer's route to this device.
			if f.shields {
				return f.replyOnly(key, info), true
			}
			return f.admitRouted(key, info, trust.AddrEnd(info.Src), trust.DeviceEnd(f.self)), true
		}
	case isPeer && !f.selfIPs[info.Dst] && f.ownRouteLocked(info.Dst):
		// A peer to a host behind this router.
		if f.shields {
			return f.replyOnly(key, info), true
		}
		return f.admitRouted(key, info, trust.DeviceEnd(peer), trust.AddrEnd(info.Dst)), true
	}
	return false, false
}

// admitRouted is admit for routed traffic: packets of a tracked flow pass,
// a new flow opens only when a rule allows initiator to reach responder.
// Called with f.mu held.
func (f *Filter) admitRouted(key flowKey, info packet.Info, initiator, responder trust.TrafficEnd) bool {
	now := f.now()
	f.timeRulesTickLocked(now)
	tracked := false
	if exp, ok := f.flows[key]; ok && now.Before(exp) {
		tracked = true
	}
	switch {
	case info.IsEchoReply():
		if tracked {
			f.flows[key] = now.Add(f.timeout(info.Proto))
		}
		return tracked
	case tracked && !info.IsEchoRequest():
		f.flows[key] = now.Add(f.timeout(info.Proto))
		return true
	}
	if !f.doc.AllowsRoutedPacketAt(initiator, responder, ruleQuery(info, now)) {
		return false
	}
	return f.openFlowLocked(key, info.Proto, now)
}

// openFlowLocked records a new flow, refusing it when the table is full of
// live entries.
func (f *Filter) openFlowLocked(key flowKey, proto uint8, now time.Time) bool {
	if len(f.flows) >= f.limits.MaxFlows {
		f.pruneLocked(now)
		if len(f.flows) >= f.limits.MaxFlows {
			return false
		}
	}
	f.flows[key] = now.Add(f.timeout(proto))
	return true
}

// routedICMPErrorLocked reports whether an ICMP error belongs to routed
// traffic and may take the tracked-flow check of icmpErrorLocked: from a
// host behind this router to a peer (outbound), or from a peer about a
// reply of such a host (inbound).
func (f *Filter) routedICMPErrorLocked(info packet.Info, inbound, srcPeer, dstPeer bool) bool {
	if inbound {
		return srcPeer && f.ownRouteLocked(info.Dst)
	}
	return dstPeer && f.ownRouteLocked(info.Src)
}
