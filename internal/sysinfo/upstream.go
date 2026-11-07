package sysinfo

import (
	"sync"
	"unicode/utf8"
)

// Upstream exit (ADR-0142): an exit node that sends its members' internet
// traffic through an external WireGuard provider reports the provider's
// display label, the routing mode and the last handshake in its base
// report, so the owner's panel can show "Mullvad · İsveç" and whether
// traffic flows, is blocked or leaves directly. The provider's address and
// keys are never reported.

// Upstream modes, as upstream.Status.Mode.
const (
	UpstreamTunnel  = "tunnel"
	UpstreamBlocked = "blocked"
	UpstreamDirect  = "direct"
	UpstreamOff     = "off"
)

// UpstreamState is what the running upstream manager reports.
type UpstreamState struct {
	// Label is the profile's display label, or its name when it has none.
	Label string
	// Mode is one of the Upstream* modes.
	Mode string
	// LastHandshake is a Unix time, 0 before the first handshake.
	LastHandshake int64
	// Kind is one of the UpstreamKind* values; "" for an older reporter.
	Kind string
}

// Upstream kinds, as upstream.Status.Kind.
const (
	UpstreamKindTor       = "tor"
	UpstreamKindWARP      = "warp"
	UpstreamKindMullvad   = "mullvad"
	UpstreamKindWireGuard = "wireguard"
)

const maxUpstreamLabel = 48

var (
	upstreamMu sync.RWMutex
	upstreamFn func() (UpstreamState, bool)
)

// SetUpstream registers fn to report the upstream exit whenever a report
// is collected; fn returns false when no upstream exit is configured. nil
// removes it. It is separate from SetExtra because the upstream manager
// and the device services run in different parts of the process.
func SetUpstream(fn func() (UpstreamState, bool)) {
	upstreamMu.Lock()
	upstreamFn = fn
	upstreamMu.Unlock()
}

func applyUpstream(in *Info) {
	upstreamMu.RLock()
	fn := upstreamFn
	upstreamMu.RUnlock()
	if fn == nil {
		return
	}
	var (
		st UpstreamState
		ok bool
	)
	safely(func() { st, ok = fn() })
	if !ok {
		return
	}
	in.UpstreamLabel, in.UpstreamMode, in.UpstreamHandshake, in.UpstreamKind = st.Label, st.Mode, st.LastHandshake, st.Kind
}

// sanitizeUpstream keeps only a well-formed upstream statement: a known
// mode, a short label and a plausible handshake time. An unknown mode
// drops all three.
func (in *Info) sanitizeUpstream() {
	switch in.UpstreamMode {
	case UpstreamTunnel, UpstreamBlocked, UpstreamDirect, UpstreamOff:
	default:
		in.UpstreamLabel, in.UpstreamMode, in.UpstreamHandshake, in.UpstreamKind = "", "", 0, ""
		return
	}
	switch in.UpstreamKind {
	case "", UpstreamKindTor, UpstreamKindWARP, UpstreamKindMullvad, UpstreamKindWireGuard:
	default:
		// An unknown kind from a newer device is shown as a plain upstream.
		in.UpstreamKind = ""
	}
	in.UpstreamLabel = cleanText(in.UpstreamLabel)
	if len(in.UpstreamLabel) > maxUpstreamLabel {
		in.UpstreamLabel = truncateUTF8(in.UpstreamLabel, maxUpstreamLabel)
	}
	in.UpstreamHandshake = clampTime(in.UpstreamHandshake)
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
