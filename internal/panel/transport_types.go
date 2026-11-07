package panel

// Faz 4 engine and coordinator options shown in the panel's Gelişmiş card
// (ADR-0032 TCP transport, ADR-0033 post-quantum PSK, F-020 lazy peers,
// F-021 keepalive). Durations travel as whole seconds; 0 means the
// built-in default.

// TransportSettings are the saved Faz 4 options of this computer's tunnel.
type TransportSettings struct {
	PostQuantum        bool   `json:"postQuantum"`
	PSKRotationSec     int64  `json:"pskRotationSec"`
	TCPFallback        string `json:"tcpFallback"`
	DisableTCPFallback bool   `json:"disableTcpFallback"`
	KeepaliveSec       int64  `json:"keepaliveSec"`
	AdaptiveKeepalive  bool   `json:"adaptiveKeepalive"`
	LazyPeers          bool   `json:"lazyPeers"`
	LazyIdleSec        int64  `json:"lazyIdleSec"`
}

// Post-quantum states of a peer as PeerInfo.PostQuantum reports them; the
// same strings as node.PQState*.
const (
	PostQuantumActive      = "pq"
	PostQuantumNegotiating = "negotiating"
	PostQuantumClassical   = "classical"
	PostQuantumUnsupported = "unsupported"
	PostQuantumOff         = "off"
)

// Bounds checked by the HTTP handler before the service checks the exact
// limits again.
const (
	maxAdvancedSeconds = 7 * 24 * 60 * 60
	maxAdvancedAddr    = 255
	maxAdvancedConns   = 1 << 16
)

// hasChange reports whether a request changes anything.
func (a AdvancedSettings) hasChange() bool {
	return a.MTU != nil || a.ForceRelay != nil || a.RelayRate != nil || a.RelayBurst != nil ||
		a.PostQuantum != nil || a.PSKRotationSec != nil || a.TCPFallback != nil || a.DisableTCPFallback != nil ||
		a.KeepaliveSec != nil || a.AdaptiveKeepalive != nil || a.LazyPeers != nil || a.LazyIdleSec != nil ||
		a.CoordinatorTCPListen != nil || a.CoordinatorTCPMaxConns != nil || a.CoordinatorTCPMaxConnsPerIP != nil
}

// transportInRange applies the coarse bounds of the Faz 4 fields.
func (a AdvancedSettings) transportInRange() bool {
	sec := func(p *int64) bool { return p == nil || (*p >= 0 && *p <= maxAdvancedSeconds) }
	str := func(p *string) bool { return p == nil || len(*p) <= maxAdvancedAddr }
	conns := func(p *int) bool { return p == nil || (*p >= 0 && *p <= maxAdvancedConns) }
	return sec(a.PSKRotationSec) && sec(a.KeepaliveSec) && sec(a.LazyIdleSec) &&
		str(a.TCPFallback) && str(a.CoordinatorTCPListen) &&
		conns(a.CoordinatorTCPMaxConns) && conns(a.CoordinatorTCPMaxConnsPerIP)
}
