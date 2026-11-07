package node

import (
	"sync"

	"github.com/openscale/openscale/internal/osnet"
)

// p03State holds the connection package P03 state: the UDP block memory
// (#393), static endpoints given by name (#387) and the NAT64 prefix used
// to reach an IPv4 coordinator from an IPv6-only network (#384, ADR-0152).
type p03State struct {
	udpMem *udpMemory
	names  *staticNames
	nat64  nat64Cache

	mu sync.Mutex
	// lastFP is the current network's fingerprint at the last check.
	lastFP string
}

func (s *p03State) setFingerprint(fp string) {
	s.mu.Lock()
	s.lastFP = fp
	s.mu.Unlock()
}

func (s *p03State) fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFP
}

// initP03 sets up the P03 state; New calls it once the TCP transport exists.
func (e *Engine) initP03() {
	if e.tcp != nil {
		e.tcp.onUp = e.onTCPUp
		e.tcp.onUDP = e.onTCPDown
		if p := e.udpMemoryPath(); p != "" && !e.tcp.forced {
			ident := e.cfg.NetworkIdentity
			if ident == nil {
				ident = osnet.CurrentNetworks
			}
			e.p03.udpMem = newUDPMemory(p, e.cfg.Now, ident)
		}
	}
	if len(e.cfg.StaticEndpointNames) > 0 {
		e.p03.names = newStaticNames(e.cfg.StaticEndpointNames, e.cfg.Resolve, e.cfg.Now, e.logger)
	}
}

// p03NetworkChanged runs after a network change: the NAT64 prefix and the
// resolved static names are found again, and the UDP block memory is
// consulted for the new network.
func (e *Engine) p03NetworkChanged() {
	e.p03.nat64.reset()
	if e.p03.names != nil {
		e.p03.names.invalidate()
	}
	go e.recallUDPBlock()
}

// NetworkIdentityFunc lists the networks this computer is connected to
// (Config.NetworkIdentity, #393).
type NetworkIdentityFunc = func() ([]osnet.CurrentNetwork, error)
