package openscale

import (
	"time"

	"github.com/openscale/openscale/internal/node"
)

// Battery-friendly keepalive (#178, ADR-0101): on a phone the radio wakes
// for every packet, so the connection is kept alive only while there is
// traffic and no push service is used. Peers are added to WireGuard only
// when this device sends them something the rules allow and removed after
// they idle (lazy peers, F-020); the coordinator and the exit node in use
// stay configured, with the longest keepalive the engine allows and the
// adaptive keepalive shortening it only for paths that keep losing their
// NAT mapping. The document is polled less often; pushed updates
// (ADR-0026) still arrive while the coordinator path is up.

// batteryPollInterval is the coordinator poll interval of the battery
// profile.
const batteryPollInterval = 60 * time.Second

// engineProfile is the part of node.Config the profile sets.
type engineProfile struct {
	Keepalive         time.Duration
	AdaptiveKeepalive bool
	LazyPeers         bool
	PollInterval      time.Duration
}

func profileFor(batterySaver bool) engineProfile {
	if !batterySaver {
		// The desktop defaults (25 s keepalive, every peer configured),
		// still adaptive so a lossy mobile NAT is handled.
		return engineProfile{AdaptiveKeepalive: true}
	}
	return engineProfile{
		Keepalive:         node.MaxKeepalive,
		AdaptiveKeepalive: true,
		LazyPeers:         true,
		PollInterval:      batteryPollInterval,
	}
}

func (p engineProfile) apply(cfg *node.Config) {
	cfg.Keepalive = p.Keepalive
	cfg.AdaptiveKeepalive = p.AdaptiveKeepalive
	cfg.LazyPeers = p.LazyPeers
	cfg.PollInterval = p.PollInterval
}
