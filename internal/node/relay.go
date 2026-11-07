package node

import (
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Path selection (ADR-0017).
const (
	// defaultRelayAfter: a peer without a direct handshake for this long is
	// reached through the coordinator.
	defaultRelayAfter = 30 * time.Second
	// defaultDirectRetry: how often a relayed peer is tried directly again.
	// Every failed try doubles the wait up to maxDirectRetry (F-006); a
	// direct handshake or a network change starts over.
	defaultDirectRetry = 5 * time.Minute
	maxDirectRetry     = time.Hour
	directRetryJitter  = 0.1
)

// pathState remembers how a peer is reached and since when.
type pathState struct {
	relayed bool
	probing bool
	since   time.Time
	// failures counts direct tries that ended back on the relay.
	failures int
	// retryAt is when a relayed peer is tried directly again; zero means
	// since plus the retry delay for failures.
	retryAt time.Time
}

// secondFloor truncates t to whole seconds: WireGuard reports handshakes
// in whole seconds, so a handshake right after t must not look older.
func secondFloor(t time.Time) time.Time { return t.Truncate(time.Second) }

// directRetryDelay is how long a relayed peer waits for its next direct try
// after failures failed ones.
func (e *Engine) directRetryDelay(failures int) time.Duration {
	base := e.cfg.DirectRetry
	return backoffDelay(base, max(base, maxDirectRetry), failures, directRetryJitter, e.rand())
}

// choosePaths returns the UAPI changes that move each tunnel peer between
// its direct endpoint and the relay. WireGuard's own roaming then keeps
// both sides consistent: a peer that receives relayed packets answers the
// same way.
func (e *Engine) choosePaths(peers []trust.Device, st wgconf.Status, direct map[trust.Key]netip.AddrPort) string {
	now := e.cfg.Now()
	relayAfter := e.cfg.RelayAfter
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.paths == nil {
		e.paths = map[trust.Key]*pathState{}
	}
	seen := map[trust.Key]bool{}
	var uapi string
	for _, d := range peers {
		key := d.WireGuardKey
		cur, configured := st.Peers[key]
		if !configured || !now.Before(d.ExpiresAt) {
			continue
		}
		seen[key] = true
		ps := e.paths[key]
		if ps == nil {
			ps = &pathState{since: now, relayed: cur.Relayed}
			e.paths[key] = ps
		}
		var last time.Time
		if cur.LastHandshakeUnix > 0 {
			last = time.Unix(cur.LastHandshakeUnix, 0)
		}
		ep, haveDirect := direct[key]
		// A path that answered a signed probe just now (ADR-0025) beats the
		// coordinator's observation: it may be a LAN or IPv6 address, and
		// it is known to work.
		validated := false
		if e.probe != nil && !e.cfg.ForceRelay {
			if vep, ok := e.probe.validated(key, probeFresh); ok {
				ep, haveDirect, validated = vep, true, true
			}
		}
		relayEP, err := RelayEndpointString(d.ID)
		if err != nil {
			continue
		}

		if e.cfg.ForceRelay {
			// F-022: the direct path is never tried.
			if !cur.Relayed {
				uapi += wgconf.SetEndpointString(key, relayEP)
			}
			*ps = pathState{relayed: true, since: now}
			continue
		}

		switch {
		case cur.Relayed:
			if !ps.relayed {
				// The peer moved us to the relay by roaming.
				*ps = pathState{relayed: true, since: now, failures: ps.failures}
			}
			if ps.retryAt.IsZero() {
				ps.retryAt = ps.since.Add(e.directRetryDelay(ps.failures))
			}
			// Every few minutes give the direct path another chance, and at
			// once when a probe proved one works (upgrade from the relay).
			if haveDirect && (validated || !now.Before(ps.retryAt)) {
				uapi += wgconf.SetEndpoint(key, ep)
				*ps = pathState{probing: true, since: secondFloor(now), failures: ps.failures}
			}
		case ps.probing:
			switch {
			case !last.IsZero() && !last.Before(ps.since):
				*ps = pathState{since: ps.since} // a direct handshake happened
			case now.Sub(ps.since) >= relayAfter:
				uapi += wgconf.SetEndpointString(key, relayEP)
				f := ps.failures + 1
				*ps = pathState{relayed: true, since: now, failures: f}
			}
		case validated && cur.Endpoint != ep &&
			(classify(ep) > classify(cur.Endpoint) || last.IsZero() || now.Sub(last) > staleHandshake):
			// A better (or the only working) direct path answered: move
			// there and watch for a handshake like any direct try.
			uapi += wgconf.SetEndpoint(key, ep)
			*ps = pathState{probing: true, since: secondFloor(now), failures: ps.failures}
		case (last.IsZero() || now.Sub(last) > staleHandshake) && now.Sub(ps.since) >= relayAfter:
			uapi += wgconf.SetEndpointString(key, relayEP)
			*ps = pathState{relayed: true, since: now, failures: ps.failures}
		case haveDirect && cur.Endpoint != ep && (!cur.Endpoint.IsValid() || last.IsZero() || now.Sub(last) >= staleHandshake):
			// Learn the endpoint the coordinator observed.
			uapi += wgconf.SetEndpoint(key, ep)
		}
	}
	for key := range e.paths {
		if !seen[key] {
			delete(e.paths, key)
		}
	}
	return uapi
}

// resetPaths restarts path selection after a network change (F-004).
// Direct peers get a fresh window to handshake before they fall back to
// the relay, so a dead path is noticed in RelayAfter instead of after a
// stale handshake. When the local addresses changed, relayed peers are
// tried directly at once and their retry backoff starts over: the new
// network may allow what the old one did not. A wake alone keeps relayed
// peers where they are.
func (e *Engine) resetPaths(addrChanged bool) {
	if e.cfg.ForceRelay {
		return
	}
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ps := range e.paths {
		switch {
		case ps.relayed:
			if addrChanged {
				ps.failures, ps.retryAt = 0, now
			}
		default:
			*ps = pathState{probing: true, since: secondFloor(now)}
		}
	}
}

// sendRelay wraps one WireGuard packet for the coordinator.
func (e *Engine) sendRelay(dst [control.RelayIDLen]byte, wg []byte) bool {
	e.client.mu.Lock()
	self, coord := e.client.self, e.client.coord
	e.client.mu.Unlock()
	coord = e.relayCoordinatorIPv4(coord) // #57: the fastest coordinator
	if !self.IsValid() || !coord.IsValid() || len(wg) > control.RelayMaxPayload-control.RelayIDLen {
		return false
	}
	payload := make([]byte, 0, control.RelayIDLen+len(wg))
	payload = append(payload, dst[:]...)
	payload = append(payload, wg...)
	pkt, err := packet.BuildUDP4(self, coord, control.RelayPort, control.RelayPort, payload)
	if err != nil {
		return false
	}
	return e.wrap.Inject(pkt)
}

// receiveRelay consumes relay datagrams from the coordinator and hands
// their WireGuard packet to the relay bind.
func (e *Engine) receiveRelay(pkt []byte) bool {
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoUDP || in.SrcPort != control.RelayPort || in.DstPort != control.RelayPort {
		return false
	}
	e.client.mu.Lock()
	self, coord := e.client.self, e.client.coord
	e.client.mu.Unlock()
	if (in.Src != coord && !e.client.isCoordinator(in.Src)) || in.Dst != self {
		return false
	}
	if in.Fragment || len(in.Payload) <= control.RelayIDLen || e.relay == nil {
		return true
	}
	var from [control.RelayIDLen]byte
	copy(from[:], in.Payload[:control.RelayIDLen])
	if e.cfg.LazyPeers {
		// A lazy peer that reaches us through the relay is configured;
		// WireGuard drops this first packet and the peer retries.
		e.lazyWake(hex.EncodeToString(from[:]))
	}
	e.relay.deliver(from, in.Payload[control.RelayIDLen:])
	return true
}
