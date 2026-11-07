package node

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Lazy peers (F-020, #170). With Config.LazyPeers a tunnel peer is added to
// WireGuard only when it is needed: this device sends it a packet the
// filter allows, the peer asks for us through the coordinator ("call",
// ADR-0025) or sends us relayed packets (ADR-0017). This device sends lazy
// peers no persistent keepalive. A lazy peer is removed again when neither
// data nor a handshake passed for LazyIdle: peers that are offline, and
// pairs of lazy devices that stopped talking, cost no handshakes and no
// keepalives. A peer that keeps its own keepalive towards us stays (its
// handshakes keep the session fresh). The coordinator and the exit node in
// use are always configured.
const (
	DefaultLazyIdle = 10 * time.Minute
	MinLazyIdle     = time.Minute
	MaxLazyIdle     = 24 * time.Hour
)

// lazyState is guarded by its own mutex: the packet path consults it.
type lazyState struct {
	mu sync.Mutex
	// want is the WireGuard configuration of every lazy peer; active the
	// configured ones with their last traffic; pending activations started
	// from the receive path.
	want    map[trust.Key]wgconf.Peer
	byIP    map[netip.Addr]trust.Key
	byID    map[string]trust.Key
	active  map[trust.Key]time.Time
	pending map[trust.Key]bool
}

// splitLazy takes the inactive lazy peers out of want (they are not
// configured) and remembers every lazy peer's configuration. always are
// the keys that must stay configured (coordinator, exit node).
func (e *Engine) splitLazy(want map[trust.Key]wgconf.Peer, peers []trust.Device, always map[trust.Key]bool) {
	if !e.cfg.LazyPeers {
		return
	}
	l := &e.lazy
	l.mu.Lock()
	defer l.mu.Unlock()
	l.want = map[trust.Key]wgconf.Peer{}
	l.byIP = map[netip.Addr]trust.Key{}
	l.byID = map[string]trust.Key{}
	if l.active == nil {
		l.active = map[trust.Key]time.Time{}
	}
	for _, d := range peers {
		p, ok := want[d.WireGuardKey]
		if !ok || always[d.WireGuardKey] {
			continue
		}
		p.Keepalive = 0
		want[d.WireGuardKey] = p
		l.want[d.WireGuardKey] = p
		l.byIP[d.IPv4] = d.WireGuardKey
		l.byIP[d.IPv6] = d.WireGuardKey
		l.byID[d.ID] = d.WireGuardKey
		if _, on := l.active[d.WireGuardKey]; !on {
			delete(want, d.WireGuardKey)
		}
	}
	for key := range l.active {
		if _, ok := l.want[key]; !ok {
			delete(l.active, key)
		}
	}
}

// lazyTouch notes traffic for a peer. Outbound traffic to an inactive lazy
// peer configures it before the packet goes on to WireGuard; inbound
// traffic only comes from configured peers and just refreshes the time.
func (e *Engine) lazyTouch(pkt []byte, outbound bool) {
	var a netip.Addr
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		off := 16
		if !outbound {
			off = 12
		}
		a = netip.AddrFrom4([4]byte(pkt[off : off+4]))
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		off := 24
		if !outbound {
			off = 8
		}
		a = netip.AddrFrom16([16]byte(pkt[off : off+16]))
	default:
		return
	}
	now := e.cfg.Now()
	l := &e.lazy
	l.mu.Lock()
	key, ok := l.byIP[a]
	if !ok {
		l.mu.Unlock()
		return
	}
	if _, on := l.active[key]; on || !outbound {
		if on {
			l.active[key] = now
		}
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	if e.activateLazy(key) {
		// Wake the peer too: if it is lazy as well it configures us when
		// the coordinator passes on the call (ADR-0025).
		e.lazyCall(key)
	}
}

// lazyCall asks the coordinator to make a freshly activated peer probe
// (and so configure) us, in the background.
func (e *Engine) lazyCall(key trust.Key) {
	l := &e.lazy
	l.mu.Lock()
	var id string
	for i, k := range l.byID {
		if k == key {
			id = i
			break
		}
	}
	l.mu.Unlock()
	if id == "" || !e.hasFeature(control.FeatureCall) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout*callRetries)
		defer cancel()
		if err := e.callPeer(ctx, id); err != nil {
			e.logger.Debug("call lazy peer", "error", err.Error())
		}
	}()
}

// lazyWake activates a peer by device id from the receive path (a pushed
// call or a relayed packet), without blocking WireGuard.
func (e *Engine) lazyWake(id string) {
	if !e.cfg.LazyPeers {
		return
	}
	l := &e.lazy
	l.mu.Lock()
	key, ok := l.byID[id]
	_, on := l.active[key]
	if !ok || on || l.pending[key] {
		if on {
			l.active[key] = e.cfg.Now()
		}
		l.mu.Unlock()
		return
	}
	if l.pending == nil {
		l.pending = map[trust.Key]bool{}
	}
	l.pending[key] = true
	l.mu.Unlock()
	go func() {
		if e.activateLazy(key) {
			// The peer wants to talk now: answer with a handshake instead
			// of waiting for its next retry (WireGuard retries every 5 s).
			e.mu.Lock()
			dev := e.dev
			e.mu.Unlock()
			if dev != nil {
				if p := dev.LookupPeer(device.NoisePublicKey(key)); p != nil {
					_ = p.SendHandshakeInitiation(false)
				}
			}
		}
		l.mu.Lock()
		delete(l.pending, key)
		l.mu.Unlock()
	}()
}

// activateLazy adds a lazy peer to WireGuard with the best endpoint known
// and the post-quantum PSK agreed earlier, if any. It reports whether it
// did.
func (e *Engine) activateLazy(key trust.Key) bool {
	now := e.cfg.Now()
	l := &e.lazy
	l.mu.Lock()
	p, ok := l.want[key]
	_, on := l.active[key]
	if !ok || on {
		l.mu.Unlock()
		return false
	}
	l.active[key] = now
	var id string
	for i, k := range l.byID {
		if k == key {
			id = i
			break
		}
	}
	l.mu.Unlock()
	e.mu.Lock()
	dev := e.dev
	pi := e.peerInfo[key]
	relayed := e.cfg.ForceRelay || (e.paths[key] != nil && e.paths[key].relayed)
	e.mu.Unlock()
	if dev == nil {
		return false
	}
	if !relayed {
		if vep, ok := e.probe.validated(key, probeFresh); ok {
			p.Endpoint = vep
		} else if pi.observed.IsValid() {
			p.Endpoint = pi.observed
		}
	}
	uapi := wgconf.AddOrUpdate(p)
	if !p.Endpoint.IsValid() {
		if ep, err := RelayEndpointString(id); err == nil {
			uapi += wgconf.SetEndpointString(key, ep)
		}
	}
	if e.pq != nil {
		if psk, ok := e.pq.current(key); ok {
			uapi += pskUAPI(key, psk)
		}
	}
	if err := dev.IpcSet(uapi); err != nil {
		e.logger.Warn("activate lazy peer", "error", err.Error())
		l.mu.Lock()
		delete(l.active, key)
		l.mu.Unlock()
		return false
	}
	e.logger.Debug("lazy peer configured")
	return true
}

// sweepLazy removes lazy peers without data and handshakes for LazyIdle.
func (e *Engine) sweepLazy() {
	if !e.cfg.LazyPeers {
		return
	}
	st, err := e.wgStatus()
	if err != nil {
		return
	}
	now := e.cfg.Now()
	l := &e.lazy
	var uapi string
	l.mu.Lock()
	for key, last := range l.active {
		if hs := st.Peers[key].LastHandshakeUnix; hs > 0 && now.Sub(time.Unix(hs, 0)) < e.cfg.LazyIdle {
			continue
		}
		if now.Sub(last) >= e.cfg.LazyIdle {
			delete(l.active, key)
			uapi += wgconf.Remove(key)
		}
	}
	l.mu.Unlock()
	if uapi == "" {
		return
	}
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil {
		return
	}
	if err := dev.IpcSet(uapi); err != nil {
		e.logger.Warn("remove idle lazy peers", "error", err.Error())
		return
	}
	e.logger.Debug("idle lazy peers removed")
}

// LazyActive reports whether a lazy peer is configured right now; peers
// that are not lazy always are.
func (e *Engine) LazyActive(key trust.Key) bool {
	if !e.cfg.LazyPeers {
		return true
	}
	l := &e.lazy
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, lazy := l.want[key]; !lazy {
		return true
	}
	_, on := l.active[key]
	return on
}

// isLazy reports whether a peer is managed lazily.
func (e *Engine) isLazy(key trust.Key) bool {
	if !e.cfg.LazyPeers {
		return false
	}
	l := &e.lazy
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.want[key]
	return ok
}
