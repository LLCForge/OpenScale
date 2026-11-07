// Package filter is the default-deny, stateful packet filter that sits
// between the operating system and WireGuard on every device (ADR-0013).
// A packet passes only if a signed rule allows the connection or it belongs
// to a connection that a rule allowed earlier. Anything that cannot be
// parsed or attributed to a known peer is dropped.
package filter

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

const (
	tcpTimeout   = 5 * time.Minute
	udpTimeout   = 2 * time.Minute
	icmpTimeout  = 30 * time.Second
	otherTimeout = time.Minute
	// MaxFlows bounds the connection table by default; new flows are
	// refused when it is full of live entries.
	MaxFlows = 65536
	// fragTimeout is how long the verdict on a first fragment applies to
	// the rest of the packet; fragments of one packet arrive together.
	fragTimeout = 30 * time.Second
	// MaxFragments bounds the fragment table by default; a fragmented
	// packet is dropped when it is full of live entries.
	MaxFragments = 4096
)

// Limits tunes connection tracking (F-084). A zero field keeps its default
// (DefaultLimits); every set field must lie within its bounds, so a typo in
// a configuration file cannot turn tracking into "keep everything forever"
// or "forget replies at once".
type Limits struct {
	TCPTimeout   time.Duration `json:"tcp_timeout,omitempty"`
	UDPTimeout   time.Duration `json:"udp_timeout,omitempty"`
	ICMPTimeout  time.Duration `json:"icmp_timeout,omitempty"`
	OtherTimeout time.Duration `json:"other_timeout,omitempty"`
	MaxFlows     int           `json:"max_flows,omitempty"`
	MaxFragments int           `json:"max_fragments,omitempty"`
}

// Bounds for Limits.
const (
	MinTCPTimeout   = 30 * time.Second
	MaxTCPTimeout   = 24 * time.Hour
	MinUDPTimeout   = 10 * time.Second
	MaxUDPTimeout   = time.Hour
	MinICMPTimeout  = 5 * time.Second
	MaxICMPTimeout  = 10 * time.Minute
	MinOtherTimeout = 10 * time.Second
	MaxOtherTimeout = time.Hour
	MinFlowLimit    = 1024
	MaxFlowLimit    = 1 << 20
	MinFragLimit    = 64
	MaxFragLimit    = 65536
)

// DefaultLimits returns the limits used when none are configured.
func DefaultLimits() Limits {
	return Limits{TCPTimeout: tcpTimeout, UDPTimeout: udpTimeout, ICMPTimeout: icmpTimeout, OtherTimeout: otherTimeout,
		MaxFlows: MaxFlows, MaxFragments: MaxFragments}
}

// ErrLimits is wrapped by every Limits validation error.
var ErrLimits = errors.New("bağlantı takibi ayarı geçersiz")

// WithDefaults fills the zero fields of l with the defaults and validates
// the result.
func (l Limits) WithDefaults() (Limits, error) {
	d := DefaultLimits()
	durs := []struct {
		name     string
		v        *time.Duration
		def      time.Duration
		min, max time.Duration
	}{
		{"tcp_timeout", &l.TCPTimeout, d.TCPTimeout, MinTCPTimeout, MaxTCPTimeout},
		{"udp_timeout", &l.UDPTimeout, d.UDPTimeout, MinUDPTimeout, MaxUDPTimeout},
		{"icmp_timeout", &l.ICMPTimeout, d.ICMPTimeout, MinICMPTimeout, MaxICMPTimeout},
		{"other_timeout", &l.OtherTimeout, d.OtherTimeout, MinOtherTimeout, MaxOtherTimeout},
	}
	for _, x := range durs {
		if *x.v == 0 {
			*x.v = x.def
		}
		if *x.v < x.min || *x.v > x.max {
			return Limits{}, fmt.Errorf("%w: %s %s ile %s arasında olmalı", ErrLimits, x.name, x.min, x.max)
		}
	}
	ints := []struct {
		name          string
		v             *int
		def, min, max int
	}{
		{"max_flows", &l.MaxFlows, d.MaxFlows, MinFlowLimit, MaxFlowLimit},
		{"max_fragments", &l.MaxFragments, d.MaxFragments, MinFragLimit, MaxFragLimit},
	}
	for _, x := range ints {
		if *x.v == 0 {
			*x.v = x.def
		}
		if *x.v < x.min || *x.v > x.max {
			return Limits{}, fmt.Errorf("%w: %s %d ile %d arasında olmalı", ErrLimits, x.name, x.min, x.max)
		}
	}
	return l, nil
}

type flowKey struct {
	proto      uint8
	local      netip.Addr
	localPort  uint16
	remote     netip.Addr
	remotePort uint16
}

// fragKey identifies the fragments of one packet in one direction.
type fragKey struct {
	inbound bool
	src     netip.Addr
	dst     netip.Addr
	proto   uint8
	id      uint32
}

// Filter is safe for concurrent use.
type Filter struct {
	mu      sync.Mutex
	now     func() time.Time
	doc     *trust.Document
	self    string
	selfIPs map[netip.Addr]bool
	peers   map[netip.Addr]string
	flows   map[flowKey]time.Time
	// frags holds the packets whose first fragment passed; the later
	// fragments carry no ports and follow that verdict (F-128).
	frags   map[fragKey]time.Time
	overlay []netip.Prefix
	// useExit: this device sends internet traffic to an exit node.
	// isExit: this device forwards members' internet traffic (ADR-0018).
	useExit bool
	isExit  bool
	// exitAddr is the exit node's overlay IPv4, which also resolves DNS.
	exitAddr netip.Addr
	// shields refuses every connection other devices open to this one,
	// whatever the rules say; replies to its own connections pass (F-077).
	shields bool
	limits  Limits
	// exitUsers caches doc.MayUseExitNode for every device (ADR-0021): an
	// exit node opens a member's internet flow only for allowed devices.
	exitUsers map[string]bool
	// obs counts decisions, logs refusals and feeds captures (observe.go,
	// ADR-0105).
	obs observer
	// threats detects port scans and canary hits on refused packets
	// (threat.go, ADR-0102); nil is off.
	threats *threatState
	// timeRules forgets flows when a time-limited rule opens or closes
	// (policy_time.go, ADR-0120).
	timeRules timeRuleState
	// routing holds the approved subnet routes (routes.go, ADR-0133).
	routing routeState
	// g3 holds quarantine, decoy ports and isolation (g3_quarantine.go,
	// ADR-0189).
	g3  g3FilterState
	tap flowTapPtr // ADR-0221, w8_flowtap.go
}

// SetLimits changes the connection tracking limits (F-084). Existing
// entries keep their expiry; new and refreshed ones use the new timeouts.
func (f *Filter) SetLimits(l Limits) error {
	l, err := l.WithDefaults()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.limits = l
	f.mu.Unlock()
	return nil
}

// Limits returns the connection tracking limits in effect.
func (f *Filter) Limits() Limits {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.limits
}

// SetShields turns the shields on or off. Turning them on forgets the
// connection table, so connections other devices opened earlier end too.
func (f *Filter) SetShields(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if on && !f.shields {
		f.flows = map[flowKey]time.Time{}
		f.frags = map[fragKey]time.Time{}
	}
	f.shields = on
}

// SetExit sets the exit node modes: exit is the overlay address of the exit
// node in use (invalid for none), isExit whether this device is one. Flows
// are kept.
func (f *Filter) SetExit(exit netip.Addr, isExit bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.useExit, f.exitAddr, f.isExit = exit.IsValid(), exit, isExit
}

func (f *Filter) inOverlay(a netip.Addr) bool {
	for _, p := range f.overlay {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// internet reports whether a is a public destination an exit node may
// carry: not in the overlay, not private, loopback or link-local.
func (f *Filter) internet(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !sharedSpace.Contains(a) && !f.inOverlay(a)
}

// sharedSpace is RFC 6598 carrier-grade NAT space; never internet.
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// New returns a filter that drops everything until Update is called.
func New(now func() time.Time) *Filter {
	if now == nil {
		now = time.Now
	}
	return &Filter{now: now, flows: map[flowKey]time.Time{}, frags: map[fragKey]time.Time{}, limits: DefaultLimits()}
}

// Update installs a new document. The connection table is cleared so that
// revoked devices and removed rules take effect immediately.
func (f *Filter) Update(doc *trust.Document, self trust.Device) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doc = doc
	f.self = self.Name
	f.selfIPs = map[netip.Addr]bool{self.IPv4: true, self.IPv6: true}
	f.peers = map[netip.Addr]string{}
	f.exitUsers = map[string]bool{}
	f.overlay = nil
	if doc != nil {
		f.overlay = []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}
		for _, d := range doc.Devices {
			if d.Name != self.Name {
				f.peers[d.IPv4], f.peers[d.IPv6] = d.Name, d.Name
				f.exitUsers[d.Name] = doc.MayUseExitNode(d.Name)
			}
		}
	}
	f.flows = map[flowKey]time.Time{}
	f.frags = map[fragKey]time.Time{}
	f.resetTimeRulesLocked(f.now())
	f.updateRoutesLocked(doc, self) // ADR-0133
}

// Clear drops all state and blocks all traffic, for example when the
// document expires.
func (f *Filter) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doc, f.self, f.selfIPs, f.peers, f.exitUsers = nil, "", nil, nil, nil
	f.routing = routeState{}
	f.flows = map[flowKey]time.Time{}
	f.frags = map[fragKey]time.Time{}
}

// outbound is Outbound's decision (observe.go wraps it).
func (f *Filter) outbound(pkt []byte) bool {
	info, err := packet.Parse(pkt)
	if err != nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.doc == nil {
		return false
	}
	return f.fragmented(false, info, f.outboundLocked)
}

func (f *Filter) outboundLocked(info packet.Info) bool {
	if f.g3OutboundLocked(info) { // ADR-0189
		return false
	}
	if info.IsICMPError() {
		return f.icmpErrorLocked(info, false)
	}
	peer, ok := f.peers[info.Dst]
	switch {
	case f.useExit && info.Dst == f.exitAddr && f.selfIPs[info.Src] && info.DstPort == 53 &&
		(info.Proto == packet.ProtoUDP || info.Proto == packet.ProtoTCP):
		// DNS through the exit node, regardless of rules. The exit address
		// is a member's overlay address or the resolver of a plain
		// WireGuard exit node (ADR-0133, F-045).
		return f.track(flowKey{info.Proto, info.Src, info.SrcPort, info.Dst, info.DstPort}, info, true)
	case !ok && f.useExit && f.selfIPs[info.Src] && f.internet(info.Dst):
		// Internet traffic leaving through the exit node.
		return f.track(flowKey{info.Proto, info.Src, info.SrcPort, info.Dst, info.DstPort}, info, true)
	case ok && f.isExit && !f.selfIPs[info.Src] && f.internet(info.Src):
		// A reply the exit node forwards back to a member.
		return f.track(flowKey{info.Proto, info.Src, info.SrcPort, info.Dst, info.DstPort}, info, false)
	}
	if v, handled := f.routedOutboundLocked(info, peer, ok); handled { // ADR-0133
		if !v {
			f.noteOutboundRefusedLocked(peer, ok, info)
		}
		return v
	}
	if !ok || !f.selfIPs[info.Src] {
		f.noteOutboundRefusedLocked(peer, ok, info)
		return false
	}
	key := flowKey{info.Proto, info.Src, info.SrcPort, info.Dst, info.DstPort}
	if info.IsICMP() {
		key.localPort, key.remotePort = info.ICMPID, 0
	}
	if f.admit(key, info, f.self, peer) {
		return true
	}
	f.noteOutboundRefusedLocked(peer, true, info)
	return false
}

// inbound is Inbound's decision (observe.go wraps it).
func (f *Filter) inbound(pkt []byte) bool {
	info, err := packet.Parse(pkt)
	if err != nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.doc == nil {
		return false
	}
	return f.fragmented(true, info, f.inboundLocked)
}

func (f *Filter) inboundLocked(info packet.Info) bool {
	if f.g3InboundLocked(info) { // ADR-0189
		return false
	}
	if info.IsICMPError() {
		return f.icmpErrorLocked(info, true)
	}
	peer, ok := f.peers[info.Src]
	switch {
	case !ok && f.useExit && f.selfIPs[info.Dst] && (f.internet(info.Src) || info.Src == f.exitAddr):
		// Only replies to traffic this device sent through the exit node
		// (or DNS replies of a plain WireGuard exit's private resolver).
		return f.track(flowKey{info.Proto, info.Dst, info.DstPort, info.Src, info.SrcPort}, info, false)
	case ok && f.isExit && !f.selfIPs[info.Dst] && f.internet(info.Dst):
		// A member's internet traffic this exit node forwards. A new flow
		// opens only for devices the document lets use exit nodes
		// (exit_users, ADR-0021); peer configuration alone is no boundary.
		return f.track(flowKey{info.Proto, info.Dst, info.DstPort, info.Src, info.SrcPort}, info, f.exitUsers[peer])
	}
	if v, handled := f.routedInboundLocked(info, peer, ok); handled { // ADR-0133
		if !v {
			f.noteInboundRefusedLocked(peer, ok, info)
		}
		return v
	}
	if !ok || !f.selfIPs[info.Dst] {
		f.noteInboundRefusedLocked(peer, ok, info)
		return false
	}
	key := flowKey{info.Proto, info.Dst, info.DstPort, info.Src, info.SrcPort}
	if info.IsICMP() {
		key.localPort, key.remotePort = info.ICMPID, 0
	}
	if f.shields {
		return f.replyOnly(key, info)
	}
	if f.threatBlockedLocked(peer, key, info) {
		return false
	}
	if f.admit(key, info, peer, f.self) {
		return true
	}
	f.noteInboundRefusedLocked(peer, true, info)
	return false
}

// replyOnly passes packets of connections this device opened and refuses
// every new one (shields). Called with f.mu held.
func (f *Filter) replyOnly(key flowKey, info packet.Info) bool {
	now := f.now()
	exp, ok := f.flows[key]
	if !ok || !now.Before(exp) || info.IsEchoRequest() {
		return false
	}
	f.flows[key] = now.Add(f.timeout(info.Proto))
	return true
}

// admit allows packets of a tracked flow, or opens a new flow when a rule
// allows initiator to reach responder. Called with f.mu held.
//
// ICMP has no ports, so echo requests always need a rule (they can never
// pass as the "reply" of another flow) and echo replies pass only for a
// tracked request with the same identifier. Other ICMP needs a rule.
func (f *Filter) admit(key flowKey, info packet.Info, initiator, responder string) bool {
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
	// AllowsPacketAt evaluates deny, disabled, tag, group and numeric
	// protocol rules (ADR-0021) and the ICMP type, address and time
	// conditions of ADR-0120. Ports matter only for TCP and UDP.
	if !f.doc.AllowsPacketAt(initiator, responder, ruleQuery(info, now)) {
		return false
	}
	if len(f.flows) >= f.limits.MaxFlows {
		f.pruneLocked(now)
		if len(f.flows) >= f.limits.MaxFlows {
			return false
		}
	}
	f.flows[key] = now.Add(f.timeout(info.Proto))
	return true
}

// track handles exit node traffic. New flows may only be opened in the
// allowed direction; the other direction only matches existing flows.
func (f *Filter) track(key flowKey, info packet.Info, open bool) bool {
	if info.IsICMP() {
		key.localPort, key.remotePort = info.ICMPID, 0
	}
	now := f.now()
	if exp, ok := f.flows[key]; ok && now.Before(exp) {
		if !open && info.IsEchoRequest() {
			return false
		}
		f.flows[key] = now.Add(f.timeout(info.Proto))
		return true
	}
	if !open || info.IsEchoReply() {
		return false
	}
	if len(f.flows) >= f.limits.MaxFlows {
		f.pruneLocked(now)
		if len(f.flows) >= f.limits.MaxFlows {
			return false
		}
	}
	f.flows[key] = now.Add(f.timeout(info.Proto))
	return true
}

// fragmented applies decide to whole packets and first fragments, and the
// first fragment's verdict to the later fragments of the same packet. A
// later fragment whose first fragment was not seen (or was refused) is
// dropped. Called with f.mu held.
func (f *Filter) fragmented(inbound bool, info packet.Info, decide func(packet.Info) bool) bool {
	if !info.Fragment && !info.MoreFragments {
		return decide(info)
	}
	key := fragKey{inbound: inbound, src: info.Src, dst: info.Dst, proto: info.Proto, id: info.FragID}
	now := f.now()
	if info.Fragment {
		exp, ok := f.frags[key]
		if !ok || !now.Before(exp) {
			delete(f.frags, key)
			return false
		}
		if !info.MoreFragments {
			// The last fragment: the packet is complete.
			delete(f.frags, key)
		}
		return true
	}
	if !decide(info) {
		delete(f.frags, key)
		return false
	}
	if _, ok := f.frags[key]; !ok && len(f.frags) >= f.limits.MaxFragments {
		f.pruneFragsLocked(now)
		if len(f.frags) >= f.limits.MaxFragments {
			// The rest could not follow; do not send half a packet.
			return false
		}
	}
	f.frags[key] = now.Add(fragTimeout)
	return true
}

func (f *Filter) pruneFragsLocked(now time.Time) {
	for k, exp := range f.frags {
		if !now.Before(exp) {
			delete(f.frags, k)
		}
	}
}

// icmpErrorLocked passes a destination unreachable or packet too big
// message only when the packet it quotes belongs to a tracked flow, and
// only towards that packet's sender (F-083). Path MTU discovery then works
// through the tunnel, while errors cannot be used to probe or to reach
// devices no rule allows. The flow is not refreshed. Called with f.mu held.
func (f *Filter) icmpErrorLocked(info packet.Info, inbound bool) bool {
	orig, err := packet.ParseEmbedded(info.Embedded)
	if err != nil || orig.Fragment || orig.Src.Is4() != (info.Proto == packet.ProtoICMPv4) {
		return false
	}
	if orig.IsICMP() && !orig.IsEchoRequest() && !orig.IsEchoReply() {
		return false // no errors about errors
	}
	// The error goes back to whoever sent the quoted packet. It comes from
	// the quoted destination itself, from this device, or, for internet
	// traffic only, from a router on the internet path or the exit node.
	if info.Dst != orig.Src {
		return false
	}
	fromRouter := f.internet(orig.Dst) && (f.internet(info.Src) || (f.useExit && info.Src == f.exitAddr))
	if info.Src != orig.Dst && !f.selfIPs[info.Src] && !fromRouter {
		return false
	}
	_, srcPeer := f.peers[info.Src]
	_, dstPeer := f.peers[info.Dst]
	if inbound {
		switch {
		case f.selfIPs[info.Dst]:
			// To this device.
		case f.isExit && srcPeer && f.internet(info.Dst):
			// A member's error about a reply from the internet.
		case f.routedICMPErrorLocked(info, true, srcPeer, dstPeer):
			// A member's error about a reply from behind this router.
		default:
			return false
		}
	} else {
		switch {
		case f.selfIPs[info.Src] && (dstPeer || (f.useExit && f.internet(info.Dst))):
			// From this device to a peer, or to the internet via the exit.
		case f.isExit && dstPeer && !f.selfIPs[info.Src] && f.internet(info.Src):
			// An internet router's error the exit node forwards to a member.
		case f.routedICMPErrorLocked(info, false, srcPeer, dstPeer):
			// A host behind this router reports to a member (ADR-0133).
		default:
			return false
		}
	}
	now := f.now()
	for _, k := range []flowKey{
		{orig.Proto, orig.Src, orig.SrcPort, orig.Dst, orig.DstPort},
		{orig.Proto, orig.Dst, orig.DstPort, orig.Src, orig.SrcPort},
	} {
		if orig.IsICMP() {
			k.localPort, k.remotePort = orig.ICMPID, 0
		}
		if exp, ok := f.flows[k]; ok && now.Before(exp) {
			return true
		}
	}
	return false
}

func (f *Filter) pruneLocked(now time.Time) {
	for k, exp := range f.flows {
		if !now.Before(exp) {
			delete(f.flows, k)
		}
	}
}

// Flows returns the number of tracked connections.
func (f *Filter) Flows() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.flows)
}

func (f *Filter) timeout(proto uint8) time.Duration {
	switch proto {
	case packet.ProtoTCP:
		return f.limits.TCPTimeout
	case packet.ProtoUDP:
		return f.limits.UDPTimeout
	case packet.ProtoICMPv4, packet.ProtoICMPv6:
		return f.limits.ICMPTimeout
	default:
		return f.limits.OtherTimeout
	}
}
