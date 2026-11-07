package node

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Keepalive interval (F-021). WireGuard sends a keepalive to every peer
// this often so NAT mappings on the way stay open. 25 s fits nearly every
// NAT; the owner can set 10-120 s, and the adaptive mode shortens it per
// peer when handshakes keep getting lost (a NAT that forgets mappings
// sooner) and lets it grow back slowly.
const (
	DefaultKeepalive = 25 * time.Second
	MinKeepalive     = 10 * time.Second
	MaxKeepalive     = 120 * time.Second
	// keepaliveLost: a handshake older than this counts as lost
	// (WireGuard renews it every two minutes while traffic flows).
	keepaliveLost = staleHandshake + 30*time.Second
	// keepaliveBack: a lost handshake that comes back within this long was
	// a dropped mapping, not a peer that went away for a while.
	keepaliveBack = 10 * time.Minute
	// keepaliveGrow: after this long without a loss the interval grows by
	// keepaliveStep, up to the configured value.
	keepaliveGrow = time.Hour
	keepaliveStep = 5 * time.Second
)

// ValidateKeepalive checks a configured keepalive interval.
func ValidateKeepalive(d time.Duration) error {
	if d < MinKeepalive || d > MaxKeepalive || d%time.Second != 0 {
		return fmt.Errorf("keepalive aralığı %s ile %s arasında, tam saniye olmalı", MinKeepalive, MaxKeepalive)
	}
	return nil
}

// kaState is the adaptive keepalive of one peer, guarded by Engine.mu.
type kaState struct {
	interval time.Duration
	lostAt   time.Time
	changed  time.Time
	losses   int
}

// keepaliveFor returns the keepalive (seconds) to configure for a peer.
func (e *Engine) keepaliveFor(key trust.Key) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ks := e.keepalives[key]; ks != nil && e.cfg.AdaptiveKeepalive {
		return int(ks.interval / time.Second)
	}
	return int(e.cfg.Keepalive / time.Second)
}

// adaptKeepalive updates the adaptive keepalive from WireGuard's view and
// returns the UAPI changes. A loss shortens the interval by a third (not
// below MinKeepalive); an hour without one lengthens it by keepaliveStep.
func (e *Engine) adaptKeepalive(st wgconf.Status) string {
	if !e.cfg.AdaptiveKeepalive {
		return ""
	}
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.keepalives == nil {
		e.keepalives = map[trust.Key]*kaState{}
	}
	var uapi string
	for key, cur := range st.Peers {
		if e.isLazy(key) {
			continue // lazy peers get no keepalive from this device
		}
		ks := e.keepalives[key]
		if ks == nil {
			ks = &kaState{interval: e.cfg.Keepalive, changed: now}
			e.keepalives[key] = ks
		}
		if cur.LastHandshakeUnix <= 0 {
			continue
		}
		last := time.Unix(cur.LastHandshakeUnix, 0)
		healthy := now.Sub(last) < keepaliveLost
		next := ks.interval
		switch {
		case !healthy:
			if ks.lostAt.IsZero() {
				ks.lostAt = now
			}
		case !ks.lostAt.IsZero():
			if now.Sub(ks.lostAt) <= keepaliveBack {
				ks.losses++
				next = max(MinKeepalive, (ks.interval * 2 / 3).Truncate(time.Second))
			}
			ks.lostAt = time.Time{}
		case ks.interval < e.cfg.Keepalive && now.Sub(ks.changed) >= keepaliveGrow:
			next = min(e.cfg.Keepalive, ks.interval+keepaliveStep)
		}
		if next != ks.interval {
			e.logger.Debug("keepalive adapted", "from", ks.interval.String(), "to", next.String())
			ks.interval, ks.changed = next, now
			uapi += fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", hexKeyOf(key), int(next/time.Second))
		}
	}
	for key := range e.keepalives {
		if _, ok := st.Peers[key]; !ok {
			delete(e.keepalives, key)
		}
	}
	return uapi
}

// resetKeepalive starts adaptation over after a network change: the new
// network has other NATs.
func (e *Engine) resetKeepalive() string {
	if !e.cfg.AdaptiveKeepalive {
		return ""
	}
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	var uapi string
	for key, ks := range e.keepalives {
		if ks.interval != e.cfg.Keepalive {
			uapi += fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", hexKeyOf(key), int(e.cfg.Keepalive/time.Second))
		}
		*ks = kaState{interval: e.cfg.Keepalive, changed: now}
	}
	return uapi
}

func hexKeyOf(k trust.Key) string { return hex.EncodeToString(k[:]) }

// KeepaliveOf returns the keepalive interval in use for a peer.
func (e *Engine) KeepaliveOf(key trust.Key) time.Duration {
	return time.Duration(e.keepaliveFor(key)) * time.Second
}
