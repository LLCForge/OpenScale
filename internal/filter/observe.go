package filter

import (
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Observation of the filter's decisions (ADR-0105): the refused connection
// log with the reason (F-199, #107), packet counters for the local metrics
// (F-198) and the debug packet capture (F-197, #193). Everything stays in
// memory; nothing here writes files or talks to the network.

// Reasons a packet was refused. DenyRules means the document's rules did
// not allow the connection; the service refines it into "no rule", "a deny
// rule" or "a disabled rule".
const (
	DenyNoDocument   = "no_document"
	DenyUnknownPeer  = "unknown_peer"
	DenyNotForDevice = "not_for_device"
	DenyShields      = "shields"
	DenyRules        = "rules"
	DenyExitUsers    = "exit_not_allowed"
	DenyUntracked    = "untracked"
	DenyFlowLimit    = "flow_limit"
	DenyMalformed    = "malformed"
	// DenyThreatBlocked: the peer scanned this device and its new
	// connections are refused for a while (ADR-0102).
	DenyThreatBlocked = "threat_blocked"
)

// MaxDenials bounds the refused connection log; the entry seen longest ago
// is dropped first.
const MaxDenials = 256

// Denial is one kind of refused traffic, counted: packets of the same
// direction, other side, protocol, port and reason share an entry.
type Denial struct {
	Inbound bool
	// Peer is the other side's device name, "" when it is not a device.
	Peer string
	// Remote is the other side's address; shown only masked.
	Remote netip.Addr
	// Self is this device's name when the packet was refused.
	Self  string
	Proto uint8
	// Port is the destination port of TCP and UDP packets.
	Port   uint16
	Reason string
	Count  uint64
	First  time.Time
	Last   time.Time
	// Document is the document the decision was made with.
	Document *trust.Document `json:"-"`
	// Shields is whether the shields were on.
	Shields bool
}

type denyKey struct {
	inbound bool
	remote  netip.Addr
	proto   uint8
	port    uint16
	reason  string
}

// DenyLog is the bounded log of refused traffic; safe for concurrent use.
type DenyLog struct {
	mu      sync.Mutex
	entries map[denyKey]*Denial
	totals  map[string]uint64
}

func newDenyLog() *DenyLog {
	return &DenyLog{entries: map[denyKey]*Denial{}, totals: map[string]uint64{}}
}

func (l *DenyLog) count(reason string) {
	l.mu.Lock()
	l.totals[reason]++
	l.mu.Unlock()
}

func (l *DenyLog) add(d Denial, now time.Time) {
	k := denyKey{inbound: d.Inbound, remote: d.Remote, proto: d.Proto, port: d.Port, reason: d.Reason}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.totals[d.Reason]++
	if e, ok := l.entries[k]; ok {
		e.Count++
		e.Last = now
		e.Peer, e.Self, e.Document, e.Shields = d.Peer, d.Self, d.Document, d.Shields
		return
	}
	if len(l.entries) >= MaxDenials {
		var oldest denyKey
		var at time.Time
		first := true
		for k, e := range l.entries {
			if first || e.Last.Before(at) {
				oldest, at, first = k, e.Last, false
			}
		}
		delete(l.entries, oldest)
	}
	d.Count, d.First, d.Last = 1, now, now
	l.entries[k] = &d
}

// List returns the entries, most recently seen first.
func (l *DenyLog) List() []Denial {
	l.mu.Lock()
	out := make([]Denial, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, *e)
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].Count > out[j].Count
	})
	return out
}

// Totals returns the refused packets per reason since the start.
func (l *DenyLog) Totals() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]uint64, len(l.totals))
	for k, v := range l.totals {
		out[k] = v
	}
	return out
}

// Clear empties the log; the totals stay.
func (l *DenyLog) Clear() {
	l.mu.Lock()
	l.entries = map[denyKey]*Denial{}
	l.mu.Unlock()
}

// Stats are the filter's packet counters since the start.
type Stats struct {
	PassedIn, PassedOut uint64
	BytesIn, BytesOut   uint64
	DeniedIn, DeniedOut uint64
	Flows               int
}

// observer is the Filter's observation state; the zero value is ready.
type observer struct {
	deny      atomic.Pointer[DenyLog]
	capture   atomic.Pointer[Capture]
	passedIn  atomic.Uint64
	passedOut atomic.Uint64
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	deniedIn  atomic.Uint64
	deniedOut atomic.Uint64
}

// DenyLog returns the filter's refused connection log.
func (f *Filter) DenyLog() *DenyLog {
	if l := f.obs.deny.Load(); l != nil {
		return l
	}
	f.obs.deny.CompareAndSwap(nil, newDenyLog())
	return f.obs.deny.Load()
}

// Stats returns the packet counters.
func (f *Filter) Stats() Stats {
	o := &f.obs
	return Stats{
		PassedIn: o.passedIn.Load(), PassedOut: o.passedOut.Load(),
		BytesIn: o.bytesIn.Load(), BytesOut: o.bytesOut.Load(),
		DeniedIn: o.deniedIn.Load(), DeniedOut: o.deniedOut.Load(),
		Flows: f.Flows(),
	}
}

// Outbound decides on a packet leaving this device into the tunnel.
func (f *Filter) Outbound(pkt []byte) bool {
	ok := f.outbound(pkt)
	f.observe(pkt, false, ok)
	return ok
}

// Inbound decides on a packet arriving from the tunnel.
func (f *Filter) Inbound(pkt []byte) bool {
	ok := f.inbound(pkt)
	f.observe(pkt, true, ok)
	return ok
}

// observe counts a decision, offers the packet to a running capture and
// records why a packet was refused. It runs after the decision, outside
// f.mu; passed packets cost two atomic additions when no capture runs.
func (f *Filter) observe(pkt []byte, inbound, ok bool) {
	o := &f.obs
	switch {
	case ok && inbound:
		o.passedIn.Add(1)
		o.bytesIn.Add(uint64(len(pkt)))
	case ok:
		o.passedOut.Add(1)
		o.bytesOut.Add(uint64(len(pkt)))
	case inbound:
		o.deniedIn.Add(1)
	default:
		o.deniedOut.Add(1)
	}
	f.tapFlow(pkt, inbound, ok) // ADR-0221, w8_flowtap.go
	c := o.capture.Load()
	if ok && c == nil {
		return
	}
	info, err := packet.Parse(pkt)
	if c != nil && err == nil {
		c.offer(pkt, info, inbound, ok, f.now())
	}
	if ok {
		return
	}
	dl := f.DenyLog()
	if err != nil {
		dl.count(DenyMalformed)
		return
	}
	if quiet(info.Dst) || quiet(info.Src) {
		// Multicast, broadcast and link-local chatter the system sends to
		// every interface; counted in the metrics only.
		return
	}
	f.mu.Lock()
	d := f.classifyLocked(info, inbound)
	f.mu.Unlock()
	dl.add(d, f.now())
}

var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

func quiet(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a == broadcast4
}

// classifyLocked explains a refused packet, following the order of the
// decision in inboundLocked and outboundLocked. Called with f.mu held.
func (f *Filter) classifyLocked(info packet.Info, inbound bool) Denial {
	d := Denial{Inbound: inbound, Self: f.self, Proto: info.Proto, Document: f.doc, Shields: f.shields}
	if info.Proto == packet.ProtoTCP || info.Proto == packet.ProtoUDP {
		d.Port = info.DstPort
	}
	remote := info.Dst
	local := info.Src
	if inbound {
		remote, local = info.Src, info.Dst
	}
	d.Remote = remote
	peer, known := f.peers[remote]
	d.Peer = peer
	reason := func() string {
		if f.doc == nil {
			return DenyNoDocument
		}
		if info.Fragment || info.IsICMPError() {
			return DenyUntracked
		}
		if !known {
			if f.useExit && f.selfIPs[local] && f.internet(remote) {
				// Internet traffic: only replies through the exit node.
				return DenyUntracked
			}
			return DenyUnknownPeer
		}
		if inbound && f.isExit && !f.selfIPs[info.Dst] && f.internet(info.Dst) {
			if !f.exitUsers[peer] {
				return DenyExitUsers
			}
			return DenyUntracked
		}
		if !f.selfIPs[local] {
			return DenyNotForDevice
		}
		if inbound && f.shields {
			return DenyShields
		}
		if inbound && f.threatBlockedPeerLocked(peer) {
			return DenyThreatBlocked
		}
		if info.IsEchoReply() {
			return DenyUntracked
		}
		initiator, responder := f.self, peer
		if inbound {
			initiator, responder = peer, f.self
		}
		if f.doc.AllowsPacketAt(initiator, responder, ruleQuery(info, f.now())) {
			return DenyFlowLimit
		}
		return DenyRules
	}
	d.Reason = reason()
	return d
}

// Capture limits.
const (
	// DefaultSnap keeps the IP and transport headers but not the content.
	DefaultSnap = 128
	// MaxSnap is the largest packet kept whole.
	MaxSnap = 65535
	// captureQueue bounds the packets waiting for the writer; a full queue
	// drops packets instead of slowing the tunnel.
	captureQueue = 4096
)

// ErrCaptureBusy is returned while another capture runs.
var ErrCaptureBusy = errors.New("başka bir paket yakalama sürüyor")

// CaptureOptions selects the packets of a capture. Zero values match all.
type CaptureOptions struct {
	// Addrs: one side of the packet must be one of these.
	Addrs []netip.Addr
	Proto uint8
	// Port: the source or destination port must be this (TCP, UDP).
	Port uint16
	// Inbound and Outbound select directions; both false means both.
	Inbound, Outbound bool
	// Denied also captures refused packets.
	Denied bool
	// Snap is how many bytes of each packet are kept (DefaultSnap when 0).
	Snap int
}

// CapturedPacket is one packet of a capture.
type CapturedPacket struct {
	At      time.Time
	Data    []byte
	Length  int
	Inbound bool
	Allowed bool
}

// Capture is a running capture.
type Capture struct {
	f       *Filter
	opts    CaptureOptions
	ch      chan CapturedPacket
	dropped atomic.Uint64
	stop    sync.Once
}

// StartCapture starts capturing tunnel packets at the filter. Only one
// capture runs at a time. The caller reads Packets until it calls Stop.
func (f *Filter) StartCapture(o CaptureOptions) (*Capture, error) {
	if o.Snap <= 0 {
		o.Snap = DefaultSnap
	}
	if o.Snap > MaxSnap {
		o.Snap = MaxSnap
	}
	if !o.Inbound && !o.Outbound {
		o.Inbound, o.Outbound = true, true
	}
	o.Addrs = append([]netip.Addr(nil), o.Addrs...)
	c := &Capture{f: f, opts: o, ch: make(chan CapturedPacket, captureQueue)}
	if !f.obs.capture.CompareAndSwap(nil, c) {
		return nil, ErrCaptureBusy
	}
	return c, nil
}

// Packets delivers the captured packets. It is never closed; stop reading
// after Stop.
func (c *Capture) Packets() <-chan CapturedPacket { return c.ch }

// Dropped is the number of matching packets lost because the reader was
// slower than the tunnel.
func (c *Capture) Dropped() uint64 { return c.dropped.Load() }

// Stop ends the capture.
func (c *Capture) Stop() {
	c.stop.Do(func() { c.f.obs.capture.CompareAndSwap(c, nil) })
}

func (c *Capture) matches(info packet.Info, inbound, allowed bool) bool {
	o := &c.opts
	if (inbound && !o.Inbound) || (!inbound && !o.Outbound) || (!allowed && !o.Denied) {
		return false
	}
	// ICMPv4 selects ICMPv6 as well ("icmp").
	if o.Proto != 0 && info.Proto != o.Proto && (o.Proto != packet.ProtoICMPv4 || info.Proto != packet.ProtoICMPv6) {
		return false
	}
	if o.Port != 0 && info.SrcPort != o.Port && info.DstPort != o.Port {
		return false
	}
	if len(o.Addrs) == 0 {
		return true
	}
	for _, a := range o.Addrs {
		if a == info.Src || a == info.Dst {
			return true
		}
	}
	return false
}

func (c *Capture) offer(pkt []byte, info packet.Info, inbound, allowed bool, now time.Time) {
	if !c.matches(info, inbound, allowed) {
		return
	}
	n := min(len(pkt), c.opts.Snap)
	p := CapturedPacket{At: now, Data: append([]byte(nil), pkt[:n]...), Length: len(pkt), Inbound: inbound, Allowed: allowed}
	select {
	case c.ch <- p:
	default:
		c.dropped.Add(1)
	}
}
