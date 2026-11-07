package coordinator

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Relay limits per sending device: a token bucket in bytes. The defaults
// apply when Config leaves them zero (F-026).
const (
	DefaultRelayRate  = 20 << 20 // bytes per second
	DefaultRelayBurst = 4 << 20
	// MinRelayRate keeps a relay usable at all; MaxRelayRate and
	// MaxRelayBurst keep a typo from turning the limit off.
	MinRelayRate  = 64 << 10
	MaxRelayRate  = 10 << 30
	MaxRelayBurst = 1 << 30
)

// validRelayLimits checks configured relay limits; zero means default.
func validRelayLimits(rate, burst int64) error {
	if rate != 0 && (rate < MinRelayRate || rate > MaxRelayRate) {
		return fmt.Errorf("aktarıcı hız sınırı %d ile %d bayt/sn arasında olmalı", MinRelayRate, int64(MaxRelayRate))
	}
	if burst != 0 && (burst < control.RelayMaxPayload || burst > MaxRelayBurst) {
		return fmt.Errorf("aktarıcı ani yük sınırı %d ile %d bayt arasında olmalı", control.RelayMaxPayload, MaxRelayBurst)
	}
	return nil
}

// relayer forwards WireGuard packets between two devices that cannot reach
// each other directly (ADR-0017). Both legs run inside the devices' own
// tunnels to the coordinator, so the sender is already authenticated by
// WireGuard. The payload is the devices' end-to-end WireGuard ciphertext;
// the coordinator cannot read it.
type relayer struct {
	store interface{ Document() *trust.Document }
	now   func() time.Time
	// rate (bytes per second) and burst (bytes) size each sender's bucket.
	rate, burst float64

	mu      sync.Mutex
	version uint64
	byAddr  map[netip.Addr]trust.Device
	byID    map[string]trust.Device
	peers   map[string]map[string]bool // device id -> ids it may relay to
	buckets map[string]*bucket
	stats   map[string]*RelayStats
	// guard applies sessions and the peer and total limits after the
	// document allowed a packet (p15.go, ADR-0111); nil allows it. It
	// must not take mu.
	guard func(from, to trust.Device, n int, now time.Time) bool
	// admit is the owner's local admission check (admission.go, F-096,
	// ADR-0136); nil admits every pair the document allows. It must not
	// take mu.
	admit func(from, to trust.Device, now time.Time) bool
	// account adds relayed bytes to the monthly usage (ops.go, #482); nil
	// counts nothing. It must not take mu.
	account func(id string, n int, now time.Time)
	// blind, when it returns true, relays between all members because the
	// policy is sealed (g2_blind.go, #629); nil never.
	blind func(doc *trust.Document) bool
}

// RelayStats counts relayed traffic sent by one device.
type RelayStats struct {
	Packets, Bytes, Dropped uint64
	LastSeen                time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newRelayer(store interface{ Document() *trust.Document }, now func() time.Time, rate, burst int64) *relayer {
	if rate <= 0 {
		rate = DefaultRelayRate
	}
	if burst <= 0 {
		burst = DefaultRelayBurst
	}
	return &relayer{store: store, now: now, rate: float64(rate), burst: float64(burst), buckets: map[string]*bucket{}, stats: map[string]*RelayStats{}}
}

// refreshLocked rebuilds the lookup tables when the document changes.
func (r *relayer) refreshLocked() {
	doc := r.store.Document()
	if doc == nil || (r.byAddr != nil && doc.Version == r.version) {
		return
	}
	r.version = doc.Version
	r.byAddr = make(map[netip.Addr]trust.Device, len(doc.Devices))
	r.byID = make(map[string]trust.Device, len(doc.Devices))
	r.peers = make(map[string]map[string]bool, len(doc.Devices))
	for _, d := range doc.Devices {
		r.byAddr[d.IPv4] = d
		r.byID[d.ID] = d
		allowed := map[string]bool{}
		peersOf := doc.TunnelPeersOf(d.Name)
		if trust.IsMembersOnly(doc) || (r.blind != nil && r.blind(doc)) {
			// Sealed policy (#629, g2_blind.go): every member, devices
			// enforce their rules on the end-to-end traffic.
			peersOf = doc.Devices
		}
		for _, p := range peersOf {
			if p.ID != d.ID {
				allowed[p.ID] = true
			}
		}
		r.peers[d.ID] = allowed
	}
}

// forward turns a relay datagram from src into the datagram for the
// destination device. It returns ok=false for anything not allowed.
func (r *relayer) forward(src netip.Addr, payload []byte) (dst netip.Addr, out []byte, ok bool) {
	if len(payload) <= control.RelayIDLen || len(payload) > control.RelayMaxPayload {
		return netip.Addr{}, nil, false
	}
	dstID := hex.EncodeToString(payload[:control.RelayIDLen])
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshLocked()
	from, known := r.byAddr[src]
	if !known || !now.Before(from.ExpiresAt) {
		return netip.Addr{}, nil, false
	}
	to, known := r.byID[dstID]
	if !known || !now.Before(to.ExpiresAt) || !r.peers[from.ID][to.ID] {
		return netip.Addr{}, nil, false
	}
	st := r.stats[from.ID]
	if st == nil {
		st = &RelayStats{}
		r.stats[from.ID] = st
	}
	if (r.admit != nil && !r.admit(from, to, now)) || !r.takeLocked(from.ID, len(payload), now) || (r.guard != nil && !r.guard(from, to, len(payload), now)) {
		st.Dropped++
		return netip.Addr{}, nil, false
	}
	st.Packets++
	st.Bytes += uint64(len(payload))
	st.LastSeen = now
	if r.account != nil {
		r.account(from.ID, len(payload), now)
	}

	out = make([]byte, len(payload))
	srcID, err := hex.DecodeString(from.ID)
	if err != nil || len(srcID) != control.RelayIDLen {
		return netip.Addr{}, nil, false
	}
	copy(out, srcID)
	copy(out[control.RelayIDLen:], payload[control.RelayIDLen:])
	return to.IPv4, out, true
}

func (r *relayer) takeLocked(id string, n int, now time.Time) bool {
	b := r.buckets[id]
	if b == nil {
		b = &bucket{tokens: r.burst, at: now}
		r.buckets[id] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * r.rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	b.at = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Stats returns a copy of the per-device relay counters, keyed by device id.
func (r *relayer) Stats() map[string]RelayStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]RelayStats, len(r.stats))
	for k, v := range r.stats {
		out[k] = *v
	}
	return out
}
