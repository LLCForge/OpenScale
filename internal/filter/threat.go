package filter

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/packet"
)

// Threat detection on refused connections (ADR-0102):
//
//   - Port scan (#106): a peer whose new connections to this device are
//     refused on many distinct ports within a short window is reported
//     and, unless turned off, refused every new connection for a while.
//     An honest peer's own filter never sends what the rules forbid, so
//     such packets mean a modified or compromised peer (or a document
//     version skew, hence a threshold rather than a single packet). A
//     local program sweeping peers or their ports is reported too.
//   - Canaries (#246): owner-chosen overlay addresses that belong to no
//     device and ports of this device that no rule opens. Any attempt to
//     reach them is reported at once: nothing legitimate uses them.
//
// Events carry device names, counts and the canary the owner chose; no
// internet address, no payload. Detection only looks at packets the filter
// refuses anyway, so allowed traffic never pays for it.

// ThreatConfig configures detection; the zero value is the default (scan
// detection and blocking on, no canaries).
type ThreatConfig struct {
	// DisableScan turns port scan detection off.
	DisableScan bool `json:"disable_scan,omitempty"`
	// ScanPorts is how many distinct refused ports from one peer within
	// ScanWindow count as a scan (default 20).
	ScanPorts int `json:"scan_ports,omitempty"`
	// ScanPeers is how many distinct peers a local program may be refused
	// at within ScanWindow before it counts as a sweep (default 12).
	ScanPeers int `json:"scan_peers,omitempty"`
	// ScanWindow is the counting window (default 1 min).
	ScanWindow time.Duration `json:"scan_window,omitempty"`
	// DisableBlock only reports scans; by default a scanning peer's new
	// connections are refused for BlockFor.
	DisableBlock bool `json:"disable_block,omitempty"`
	// BlockFor is how long a scanning peer stays blocked (default 10 min).
	BlockFor time.Duration `json:"block_for,omitempty"`
	// CanaryAddrs are overlay addresses no device has; touching them is
	// reported.
	CanaryAddrs []netip.Addr `json:"canary_addrs,omitempty"`
	// CanaryPorts are TCP/UDP ports of this device that no rule opens;
	// a peer's attempt to reach one is reported (and blocks the peer).
	CanaryPorts []uint16 `json:"canary_ports,omitempty"`
}

// Defaults and bounds of ThreatConfig.
const (
	DefaultScanPorts  = 20
	DefaultScanPeers  = 12
	DefaultScanWindow = time.Minute
	DefaultBlockFor   = 10 * time.Minute
	MinScanPorts      = 5
	MaxScanPorts      = 1000
	MinScanPeers      = 3
	MaxScanPeers      = 1000
	MinScanWindow     = 10 * time.Second
	MaxScanWindow     = 10 * time.Minute
	MinBlockFor       = time.Minute
	MaxBlockFor       = 24 * time.Hour
	MaxCanaryAddrs    = 16
	MaxCanaryPorts    = 64
	// maxThreatEvents is the number of recent events kept.
	maxThreatEvents = 64
	// maxTracked bounds the per-peer counting state.
	maxTracked = 4096
	// maxEventsPerWindow bounds notifications per ScanWindow.
	maxEventsPerWindow = 32
)

// ErrThreatConfig is wrapped by every ThreatConfig validation error.
var ErrThreatConfig = errors.New("tehdit algılama ayarı geçersiz")

// WithDefaults fills the zero fields and validates the result.
func (c ThreatConfig) WithDefaults() (ThreatConfig, error) {
	if c.ScanPorts == 0 {
		c.ScanPorts = DefaultScanPorts
	}
	if c.ScanPeers == 0 {
		c.ScanPeers = DefaultScanPeers
	}
	if c.ScanWindow == 0 {
		c.ScanWindow = DefaultScanWindow
	}
	if c.BlockFor == 0 {
		c.BlockFor = DefaultBlockFor
	}
	switch {
	case c.ScanPorts < MinScanPorts || c.ScanPorts > MaxScanPorts:
		return ThreatConfig{}, fmt.Errorf("%w: scan_ports %d ile %d arasında olmalı", ErrThreatConfig, MinScanPorts, MaxScanPorts)
	case c.ScanPeers < MinScanPeers || c.ScanPeers > MaxScanPeers:
		return ThreatConfig{}, fmt.Errorf("%w: scan_peers %d ile %d arasında olmalı", ErrThreatConfig, MinScanPeers, MaxScanPeers)
	case c.ScanWindow < MinScanWindow || c.ScanWindow > MaxScanWindow:
		return ThreatConfig{}, fmt.Errorf("%w: scan_window %s ile %s arasında olmalı", ErrThreatConfig, MinScanWindow, MaxScanWindow)
	case c.BlockFor < MinBlockFor || c.BlockFor > MaxBlockFor:
		return ThreatConfig{}, fmt.Errorf("%w: block_for %s ile %s arasında olmalı", ErrThreatConfig, MinBlockFor, MaxBlockFor)
	case len(c.CanaryAddrs) > MaxCanaryAddrs:
		return ThreatConfig{}, fmt.Errorf("%w: en fazla %d tuzak adres", ErrThreatConfig, MaxCanaryAddrs)
	case len(c.CanaryPorts) > MaxCanaryPorts:
		return ThreatConfig{}, fmt.Errorf("%w: en fazla %d tuzak port", ErrThreatConfig, MaxCanaryPorts)
	}
	for _, a := range c.CanaryAddrs {
		a = a.Unmap()
		if !a.IsValid() || a.Zone() != "" || !(a.IsPrivate() || sharedSpace.Contains(a)) {
			return ThreatConfig{}, fmt.Errorf("%w: tuzak adres %s ağ içi (özel) bir adres olmalı", ErrThreatConfig, a)
		}
	}
	for _, p := range c.CanaryPorts {
		if p == 0 {
			return ThreatConfig{}, fmt.Errorf("%w: tuzak port 0 olamaz", ErrThreatConfig)
		}
	}
	c.CanaryAddrs = slices.Clone(c.CanaryAddrs)
	c.CanaryPorts = slices.Clone(c.CanaryPorts)
	return c, nil
}

// ThreatKind names what was detected.
type ThreatKind string

const (
	// ThreatInboundScan: a peer tried many refused ports of this device.
	ThreatInboundScan ThreatKind = "inbound_scan"
	// ThreatOutboundScan: a program on this device tried many refused
	// ports of a peer (Peer set) or many peers (Peer empty).
	ThreatOutboundScan ThreatKind = "outbound_scan"
	// ThreatCanaryAddress: a canary address was contacted, by a peer (Peer
	// set) or by a program on this device (Peer empty).
	ThreatCanaryAddress ThreatKind = "canary_address"
	// ThreatCanaryPort: a peer tried a canary port of this device.
	ThreatCanaryPort ThreatKind = "canary_port"
)

// ThreatEvent is one detection.
type ThreatEvent struct {
	Kind ThreatKind `json:"kind"`
	// Peer is the other device's name; empty for this device's programs.
	Peer string `json:"peer,omitempty"`
	// Count is the number of distinct ports (or peers) seen.
	Count int `json:"count,omitempty"`
	// Port is the canary port tried.
	Port uint16 `json:"port,omitempty"`
	// Canary is the canary address contacted.
	Canary string `json:"canary,omitempty"`
	// At is the detection time, rounded down to the minute (ADR-0008).
	At time.Time `json:"at"`
	// BlockedUntil is set when the peer's new connections are refused.
	BlockedUntil time.Time `json:"blocked_until,omitzero"`
}

type portWindow struct {
	start time.Time
	ports map[uint16]struct{}
}

type threatState struct {
	cfg        ThreatConfig
	canaryAddr map[netip.Addr]bool
	canaryPort map[uint16]bool
	notify     func(ThreatEvent)

	in       map[string]*portWindow // peer -> refused ports to this device
	out      map[string]*portWindow // peer -> refused ports from this device
	outPeers map[string]time.Time   // peers refused to this device's programs
	outStart time.Time
	blocked  map[string]time.Time
	reported map[string]time.Time // kind+peer -> silent until
	events   []ThreatEvent
	sent     int
	sentFrom time.Time
}

// SetThreats installs threat detection (zero config: defaults). notify,
// when not nil, is called on its own goroutine for every event; it must
// not call back into the filter synchronously. Counting state starts over.
func (f *Filter) SetThreats(c ThreatConfig, notify func(ThreatEvent)) error {
	c, err := c.WithDefaults()
	if err != nil {
		return err
	}
	t := &threatState{
		cfg: c, notify: notify, canaryAddr: map[netip.Addr]bool{}, canaryPort: map[uint16]bool{},
		in: map[string]*portWindow{}, out: map[string]*portWindow{}, outPeers: map[string]time.Time{},
		blocked: map[string]time.Time{}, reported: map[string]time.Time{},
	}
	for _, a := range c.CanaryAddrs {
		t.canaryAddr[a.Unmap()] = true
	}
	for _, p := range c.CanaryPorts {
		t.canaryPort[p] = true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.threats != nil {
		t.events = f.threats.events
	}
	f.threats = t
	return nil
}

// ClearThreats turns detection off and lifts every block.
func (f *Filter) ClearThreats() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.threats = nil
}

// ThreatEvents returns the recent events, oldest first.
func (f *Filter) ThreatEvents() []ThreatEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.threats == nil {
		return nil
	}
	return slices.Clone(f.threats.events)
}

// BlockedPeers returns the peers whose new connections are refused, with
// the time the block ends.
func (f *Filter) BlockedPeers() map[string]time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]time.Time{}
	if f.threats == nil {
		return out
	}
	now := f.now()
	for p, until := range f.threats.blocked {
		if now.Before(until) {
			out[p] = until
		}
	}
	return out
}

// Unblock lifts a scan block on peer at once.
func (f *Filter) Unblock(peer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.threats != nil {
		delete(f.threats.blocked, peer)
		delete(f.threats.in, peer)
	}
}

// newAttempt reports a packet that opens a connection: a TCP SYN, any
// UDP datagram or an echo request.
func newAttempt(info packet.Info) bool {
	switch info.Proto {
	case packet.ProtoTCP:
		return info.TCPFlags&packet.TCPSyn != 0 && info.TCPFlags&packet.TCPAck == 0
	case packet.ProtoUDP:
		return true
	}
	return info.IsEchoRequest()
}

// hasPorts reports TCP and UDP, the protocols scans count ports of.
func hasPorts(info packet.Info) bool {
	return info.Proto == packet.ProtoTCP || info.Proto == packet.ProtoUDP
}

// canaryLocked reports whether a is a canary right now: still unused by
// any device or the coordinator. Called with f.mu held.
func (f *Filter) canaryLocked(a netip.Addr) bool {
	t := f.threats
	a = a.Unmap()
	if t == nil || !t.canaryAddr[a] || f.selfIPs[a] {
		return false
	}
	if _, ok := f.peers[a]; ok {
		return false
	}
	if f.doc != nil && f.doc.Coordinator != nil && (f.doc.Coordinator.IPv4 == a || f.doc.Coordinator.IPv6 == a) {
		return false
	}
	return true
}

// threatBlockedLocked reports whether a new inbound flow from peer must
// be refused because the peer was caught scanning. Packets of tracked
// flows still pass. Called with f.mu held.
func (f *Filter) threatBlockedLocked(peer string, key flowKey, info packet.Info) bool {
	t := f.threats
	if t == nil {
		return false
	}
	until, ok := t.blocked[peer]
	if !ok {
		return false
	}
	now := f.now()
	if !now.Before(until) {
		delete(t.blocked, peer)
		return false
	}
	if exp, ok := f.flows[key]; ok && now.Before(exp) && !info.IsEchoRequest() {
		return false
	}
	return true
}

// noteInboundRefusedLocked looks at an inbound packet the filter refused.
// Called with f.mu held.
func (f *Filter) noteInboundRefusedLocked(peer string, isPeer bool, info packet.Info) {
	t := f.threats
	if t == nil || !newAttempt(info) {
		return
	}
	now := f.now()
	if !f.selfIPs[info.Dst] {
		if isPeer && f.canaryLocked(info.Dst) {
			f.raiseLocked(ThreatEvent{Kind: ThreatCanaryAddress, Peer: peer, Canary: info.Dst.Unmap().String()}, now, true)
		}
		return
	}
	if !isPeer {
		return
	}
	if hasPorts(info) && t.canaryPort[info.DstPort] {
		f.raiseLocked(ThreatEvent{Kind: ThreatCanaryPort, Peer: peer, Port: info.DstPort}, now, true)
	}
	if t.cfg.DisableScan || !hasPorts(info) {
		return
	}
	if n := countPort(t.in, peer, info.DstPort, now, t.cfg.ScanWindow); n >= t.cfg.ScanPorts {
		f.raiseLocked(ThreatEvent{Kind: ThreatInboundScan, Peer: peer, Count: n}, now, true)
	}
}

// noteOutboundRefusedLocked looks at a packet from this device the filter
// refused. Called with f.mu held.
func (f *Filter) noteOutboundRefusedLocked(peer string, isPeer bool, info packet.Info) {
	t := f.threats
	if t == nil || !f.selfIPs[info.Src] || !newAttempt(info) {
		return
	}
	now := f.now()
	if !isPeer {
		if f.canaryLocked(info.Dst) {
			f.raiseLocked(ThreatEvent{Kind: ThreatCanaryAddress, Canary: info.Dst.Unmap().String()}, now, false)
		}
		return
	}
	if t.cfg.DisableScan {
		return
	}
	if hasPorts(info) {
		if n := countPort(t.out, peer, info.DstPort, now, t.cfg.ScanWindow); n >= t.cfg.ScanPorts {
			f.raiseLocked(ThreatEvent{Kind: ThreatOutboundScan, Peer: peer, Count: n}, now, false)
		}
	}
	if now.Sub(t.outStart) > t.cfg.ScanWindow {
		t.outStart = now
		clear(t.outPeers)
	}
	if len(t.outPeers) < maxTracked {
		t.outPeers[peer] = now
	}
	if n := len(t.outPeers); n >= t.cfg.ScanPeers {
		f.raiseLocked(ThreatEvent{Kind: ThreatOutboundScan, Count: n}, now, false)
	}
}

// countPort adds port to peer's window and returns the distinct ports in
// it. The window restarts after length.
func countPort(m map[string]*portWindow, peer string, port uint16, now time.Time, length time.Duration) int {
	w := m[peer]
	if w == nil || now.Sub(w.start) > length {
		if w == nil && len(m) >= maxTracked {
			for k, x := range m {
				if now.Sub(x.start) > length {
					delete(m, k)
				}
			}
			if len(m) >= maxTracked {
				return 0
			}
		}
		w = &portWindow{start: now, ports: map[uint16]struct{}{}}
		m[peer] = w
	}
	if len(w.ports) <= MaxScanPorts {
		w.ports[port] = struct{}{}
	}
	return len(w.ports)
}

// raiseLocked records an event once per kind and peer within the block
// period, blocks the peer when asked and allowed, and notifies. Called
// with f.mu held.
func (f *Filter) raiseLocked(ev ThreatEvent, now time.Time, block bool) {
	t := f.threats
	if block {
		f.scanQuarantineLocked(ev, now) // ADR-0189
	}
	if block && ev.Peer != "" && !t.cfg.DisableBlock {
		if until, ok := t.blocked[ev.Peer]; !ok || !now.Before(until) {
			t.blocked[ev.Peer] = now.Add(t.cfg.BlockFor)
		}
		ev.BlockedUntil = t.blocked[ev.Peer]
	}
	key := string(ev.Kind) + "\x00" + ev.Peer + "\x00" + ev.Canary
	if until, ok := t.reported[key]; ok && now.Before(until) {
		return
	}
	if len(t.reported) >= maxTracked {
		for k, u := range t.reported {
			if !now.Before(u) {
				delete(t.reported, k)
			}
		}
		if len(t.reported) >= maxTracked {
			return
		}
	}
	t.reported[key] = now.Add(t.cfg.BlockFor)
	if now.Sub(t.sentFrom) > t.cfg.ScanWindow {
		t.sentFrom, t.sent = now, 0
	}
	if t.sent >= maxEventsPerWindow {
		return
	}
	t.sent++
	ev.At = now.Truncate(time.Minute)
	if len(t.events) >= maxThreatEvents {
		t.events = slices.Delete(t.events, 0, len(t.events)-maxThreatEvents+1)
	}
	t.events = append(t.events, ev)
	if t.notify != nil {
		go t.notify(ev)
	}
}
