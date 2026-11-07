package node

import (
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/filter"
)

// Resolver and threat guards (ADR-0102): the exit node's block list and
// DNSSEC anchors (#89, #91) and the filter's port scan and canary
// detection (#106, #246).

// setupGuards applies the guard settings of the configuration (New).
func (e *Engine) setupGuards() error {
	if _, err := LoadExitDNSBlocklist(e.cfg.ExitDNSBlocklist); err != nil {
		return err
	}
	if err := ApplyExitDNSGuard(e.cfg.ExitDNSGuard, e.onThreat); err != nil { // P05
		return fmt.Errorf("çıkış DNS koruması: %w", err)
	}
	if e.cfg.DNSSECTrustAnchors != "" || dnssecAnchors.Load() != nil {
		if err := SetDNSSECTrustAnchors(e.cfg.DNSSECTrustAnchors); err != nil {
			return err
		}
	}
	if err := e.filter.SetThreats(e.cfg.Threats, e.onThreat); err != nil {
		return fmt.Errorf("tehdit algılama: %w", err)
	}
	return nil
}

// onThreat logs a detection by device name (ADR-0008: no addresses above
// debug) and passes it on.
func (e *Engine) onThreat(ev filter.ThreatEvent) {
	attrs := []any{"kind", string(ev.Kind)}
	if ev.Peer != "" {
		attrs = append(attrs, "peer", ev.Peer)
	}
	if ev.Count > 0 {
		attrs = append(attrs, "count", ev.Count)
	}
	if ev.Port != 0 {
		attrs = append(attrs, "port", int(ev.Port))
	}
	if !ev.BlockedUntil.IsZero() {
		attrs = append(attrs, "blocked_for", ev.BlockedUntil.Sub(ev.At).Round(time.Minute).String())
	}
	if e.logger != nil {
		e.logger.Warn("threat detected", attrs...)
	}
	if e.cfg.OnThreat != nil {
		e.cfg.OnThreat(ev)
	}
}

// ThreatEvents returns the recent port scan and canary detections.
func (e *Engine) ThreatEvents() []filter.ThreatEvent {
	return append(e.filter.ThreatEvents(), ExitDNSThreatEvents()...) // P05: resolver detections
}

// BlockedPeers returns the peers refused for scanning and until when.
func (e *Engine) BlockedPeers() map[string]time.Time { return e.filter.BlockedPeers() }

// UnblockPeer lifts a scan block at once.
func (e *Engine) UnblockPeer(name string) { e.filter.Unblock(name) }
