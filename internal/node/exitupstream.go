package node

import (
	"errors"
	"net/netip"
)

// Upstream exit DNS (ADR-0142). While the exit node sends members' traffic
// through a provider tunnel, their DNS goes to the provider's resolver
// through the same tunnel, whatever ExitDNSUpstream says: a DoH, DoT or
// recursive resolver asked from this host would show the host's own
// address to the resolver or to every authoritative server.

// errUpstreamDNSDown drops members' queries while a fail-closed upstream
// has no tunnel.
var errUpstreamDNSDown = errors.New("upstream exit tunnel is down")

// exitDNSForwarder returns the forwarder for members' queries.
func (e *Engine) exitDNSForwarder() (*dnsForwarder, error) {
	if via := e.cfg.ExitDNSVia; via != nil {
		if server, source, ok := via(); ok {
			if !server.IsValid() || !source.IsValid() {
				return nil, errUpstreamDNSDown
			}
			return viaForwarder(server, source)
		}
	}
	return e.g3ExitForwarder() // SPKI pins, #624
}

// viaForwarder returns the shared forwarder that asks server from source.
// It shares the forwarders map: the key cannot collide with an
// ExitDNSUpstream value, which never contains "|".
func viaForwarder(server netip.AddrPort, source netip.Addr) (*dnsForwarder, error) {
	if server.Port() == 0 || server.Addr().Zone() != "" || source.Zone() != "" || server.Addr().Is4() != source.Is4() {
		return nil, errors.New("invalid upstream exit resolver")
	}
	key := "via|" + server.String() + "|" + source.String()
	forwardersMu.Lock()
	defer forwardersMu.Unlock()
	if f, ok := forwarders[key]; ok {
		return f, nil
	}
	f := newDNSForwarder(dnsUpstream{kind: upstreamUDP, addr: server.String(), local: source}, nil)
	if len(forwarders) >= maxForwarders {
		clear(forwarders)
	}
	forwarders[key] = f
	return f, nil
}

// logExitDNSUpstream reports a forwarder that could not be chosen. A
// fail-closed upstream without a tunnel drops every query on purpose; that
// is logged at debug level so a long outage does not flood the log.
func (e *Engine) logExitDNSUpstream(err error) {
	if errors.Is(err, errUpstreamDNSDown) {
		e.logger.Debug("exit DNS dropped", "error", err.Error())
		return
	}
	e.logger.Warn("exit DNS upstream", "error", err.Error())
}
