package coordinator

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Coordinator and relay scaling (ADR-0111): serving as any coordinator the
// document lists (#153, #152), control request limits (#145) and relay
// abuse protection with device-signed sessions, peer and total limits
// (#151, #145). All state is in memory only and never logged.

// Control request limits per sending address (devices and invites, which
// WireGuard authenticates) and for the whole coordinator. Requests over the
// limit are dropped without a reply, so the coordinator never amplifies.
// The defaults let a device download the largest document in one burst.
const (
	DefaultControlRate      = 200
	DefaultControlBurst     = 2000
	DefaultControlTotalRate = 20000
	MinControlRate          = 10
	MaxControlRate          = 100000
	MaxControlBurst         = 100000
)

// Relay session and peer limits.
const (
	// DefaultRelayMaxPeers bounds the distinct peers one device relays to
	// within relayPeerWindow; MaxRelayMaxPeers is the configurable maximum.
	DefaultRelayMaxPeers = 64
	MaxRelayMaxPeers     = trust.MaxDevices
	relayPeerWindow      = time.Minute
	p15PruneEvery        = time.Minute
)

// limitsConfig holds the validated P15 settings.
type limitsConfig struct {
	controlRate, controlBurst, controlTotal float64
	relayMaxPeers                           int
	relayTotal                              float64
	requireSessions                         bool
}

// validP15Limits checks and fills in the P15 settings of cfg.
func validP15Limits(cfg *Config) (limitsConfig, error) {
	var l limitsConfig
	pick := func(v, def, lo, hi int, name string) (float64, error) {
		if v == 0 {
			return float64(def), nil
		}
		if v < lo || v > hi {
			return 0, fmt.Errorf("%s %d ile %d arasında olmalı", name, lo, hi)
		}
		return float64(v), nil
	}
	var err error
	if l.controlRate, err = pick(cfg.ControlRate, DefaultControlRate, MinControlRate, MaxControlRate, "kontrol isteği hız sınırı (istek/sn)"); err != nil {
		return l, err
	}
	if l.controlBurst, err = pick(cfg.ControlBurst, DefaultControlBurst, MinControlRate, MaxControlBurst, "kontrol isteği ani yük sınırı"); err != nil {
		return l, err
	}
	if l.controlTotal, err = pick(cfg.ControlTotalRate, DefaultControlTotalRate, MinControlRate, MaxControlRate*10, "toplam kontrol isteği sınırı (istek/sn)"); err != nil {
		return l, err
	}
	peers, err := pick(cfg.RelayMaxPeers, DefaultRelayMaxPeers, 1, MaxRelayMaxPeers, "aktarıcıda cihaz başına eş sınırı")
	if err != nil {
		return l, err
	}
	l.relayMaxPeers = int(peers)
	if cfg.RelayTotalRate != 0 && (cfg.RelayTotalRate < MinRelayRate || cfg.RelayTotalRate > MaxRelayRate) {
		return l, fmt.Errorf("toplam aktarıcı hız sınırı %d ile %d bayt/sn arasında olmalı", MinRelayRate, int64(MaxRelayRate))
	}
	l.relayTotal = float64(cfg.RelayTotalRate)
	l.requireSessions = cfg.RelayRequireSessions
	return l, nil
}

// p15State is guarded by its own mutex; it is used on WireGuard's receive
// path and must never wait for the relayer's or the server's locks.
type p15State struct {
	cfg limitsConfig

	mu       sync.Mutex
	control  map[netip.Addr]*bucket
	total    bucket
	sessions map[string]time.Time // device id -> session end
	// strict holds devices that opened a session: from then on their
	// packets are relayed only under a valid session (no downgrade).
	strict      map[string]bool
	peers       map[string]map[string]time.Time // sender -> receiver -> last packet
	relayTotal  bucket
	lastPrune   time.Time
	dropControl uint64
}

func newP15State(cfg limitsConfig, now time.Time) *p15State {
	return &p15State{
		cfg:        cfg,
		control:    map[netip.Addr]*bucket{},
		total:      bucket{tokens: cfg.controlTotal, at: now},
		sessions:   map[string]time.Time{},
		strict:     map[string]bool{},
		peers:      map[string]map[string]time.Time{},
		relayTotal: bucket{tokens: cfg.relayTotal, at: now},
		lastPrune:  now,
	}
}

// takeBucket refills b at rate up to burst and takes n tokens.
func takeBucket(b *bucket, rate, burst, n float64, now time.Time) bool {
	if d := now.Sub(b.at); d > 0 {
		b.tokens += d.Seconds() * rate
	}
	if b.tokens > burst {
		b.tokens = burst
	}
	b.at = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// allowControl applies the per-address and total request limits.
func (p *p15State) allowControl(src netip.Addr, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	b := p.control[src]
	if b == nil {
		b = &bucket{tokens: p.cfg.controlBurst, at: now}
		p.control[src] = b
	}
	total := p.cfg.controlTotal
	if !takeBucket(&p.total, total, total, 1, now) || !takeBucket(b, p.cfg.controlRate, p.cfg.controlBurst, 1, now) {
		p.dropControl++
		return false
	}
	return true
}

// pruneLocked forgets idle limiter state and expired sessions.
func (p *p15State) pruneLocked(now time.Time) {
	if now.Sub(p.lastPrune) < p15PruneEvery {
		return
	}
	p.lastPrune = now
	for a, b := range p.control {
		if now.Sub(b.at) > p15PruneEvery {
			delete(p.control, a)
		}
	}
	for id, end := range p.sessions {
		if !now.Before(end) {
			delete(p.sessions, id)
		}
	}
	for from, set := range p.peers {
		for to, at := range set {
			if now.Sub(at) > relayPeerWindow {
				delete(set, to)
			}
		}
		if len(set) == 0 {
			delete(p.peers, from)
		}
	}
}

// relayGuard runs after the relayer authorized from -> to by the document.
// It enforces sessions, the per-sender peer limit and the total rate.
func (p *p15State) relayGuard(from, to trust.Device, n int, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	if p.cfg.requireSessions || p.strict[from.ID] {
		if end, ok := p.sessions[from.ID]; !ok || !now.Before(end) {
			return false
		}
	}
	set := p.peers[from.ID]
	if set == nil {
		set = map[string]time.Time{}
		p.peers[from.ID] = set
	}
	if _, ok := set[to.ID]; !ok && len(set) >= p.cfg.relayMaxPeers {
		for id, at := range set {
			if now.Sub(at) > relayPeerWindow {
				delete(set, id)
			}
		}
		if len(set) >= p.cfg.relayMaxPeers {
			return false
		}
	}
	set[to.ID] = now
	if p.cfg.relayTotal > 0 && !takeBucket(&p.relayTotal, p.cfg.relayTotal, max(p.cfg.relayTotal, float64(control.RelayMaxPayload)), float64(n), now) {
		return false
	}
	return true
}

// openSession records a verified session.
func (p *p15State) openSession(id string, end time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cur, ok := p.sessions[id]; !ok || end.After(cur) {
		p.sessions[id] = end
	}
	p.strict[id] = true
}

// relaySession verifies a device-signed relay session (#151).
func (s *Server) relaySession(req control.Message, self *trust.Device) control.Message {
	now := s.cfg.Now()
	if !now.Before(self.ExpiresAt) {
		return control.Message{T: control.TypeError, Error: "membership expired"}
	}
	sess, err := control.VerifyRelaySession(ed25519.PublicKey(self.SigningKey[:]), req.Data, req.Sig)
	if err != nil || hex.EncodeToString(sess.Device[:]) != self.ID || sess.Coordinator != [32]byte(s.wgKey) {
		return control.Message{T: control.TypeError, Error: "invalid session"}
	}
	if !sess.Expires.After(now) || sess.Expires.After(now.Add(control.RelaySessionMaxLife+control.RelaySessionSkew)) {
		return control.Message{T: control.TypeError, Error: "invalid session time"}
	}
	s.p15.openSession(self.ID, sess.Expires)
	return control.Message{T: control.TypeRelaySession, Complete: true}
}

// limitedHandle drops control requests over the limits (#145).
func (s *Server) limitedHandle(src netip.Addr, payload []byte) []byte {
	if !s.allowControlG2(src, payload) { // emergency priority (#681)
		return nil
	}
	return s.handle(src, payload)
}

// ControlDropped returns how many control requests the limits dropped.
func (s *Server) ControlDropped() uint64 {
	s.p15.mu.Lock()
	defer s.p15.mu.Unlock()
	return s.p15.dropControl
}

// listedCoordinator returns this coordinator's entry in doc: the primary or
// an additional coordinator with the same key (ADR-0111).
func listedCoordinator(doc *trust.Document, key trust.Key) (trust.Coordinator, bool) {
	return doc.CoordinatorByKey(key)
}

// checkListed refuses to start a coordinator that is not in the document or
// whose transition ended, unless it runs as a handoff.
func checkListed(doc *trust.Document, key trust.Key, handoff bool, now time.Time) error {
	if handoff {
		return nil
	}
	c, ok := listedCoordinator(doc, key)
	if !ok {
		return fmt.Errorf("this key is not the coordinator pinned in the network document; run 'openscale network set-coordinator'")
	}
	if c.Expired(now) {
		return fmt.Errorf("this coordinator's transition period ended at %s; it is no longer used", c.Until.UTC().Format(time.RFC3339))
	}
	return nil
}

// controlAddr is the overlay address this coordinator answers on: its own
// entry's, or the primary's for a handoff coordinator no longer listed.
func (s *Server) controlAddr(doc *trust.Document) netip.Addr {
	if c, ok := listedCoordinator(doc, s.wgKey); ok {
		return c.IPv4
	}
	return doc.Coordinator.IPv4
}

// initP15 wires the limits and sessions into a new server.
func (s *Server) initP15(l limitsConfig) {
	s.p15 = newP15State(l, s.cfg.Now())
	s.relay.guard = s.p15.relayGuard
}

func init() {
	coordFeatures = append(coordFeatures, control.FeatureRelaySession)
}
