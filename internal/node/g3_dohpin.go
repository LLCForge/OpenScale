package node

import (
	"crypto/tls"
	"errors"
	"strings"

	"github.com/openscale/openscale/internal/obfs"
)

// DoH/DoT SPKI pinning for the exit node resolver (#624, ADR-0188). The
// exit node already verifies the resolver's certificate against the
// system CAs; with pins the certificate chain must also contain one of
// the owner's keys, so a mis-issued or compromised CA certificate (or a
// TLS-inspecting middlebox with its own root installed) is refused.

// errExitDNSUnpinned drops members' queries when pins are required but
// the upstream cannot carry them.
var errExitDNSUnpinned = errors.New("exit DNS upstream is not pinned")

// validateExitDNSPins checks the pin options against ExitDNSUpstream.
func (e *Engine) validateExitDNSPins() error {
	g := e.cfg.G3
	if len(g.ExitDNSPins) == 0 && !g.ExitDNSRequirePins {
		return nil
	}
	pins, err := obfs.ParsePins(g.ExitDNSPins)
	if err != nil {
		return err
	}
	up, err := parseDNSUpstream(e.cfg.ExitDNSUpstream)
	if err != nil {
		return err
	}
	if up.kind != upstreamDoH && up.kind != upstreamDoT {
		return errors.New("SPKI sabitleme yalnızca https:// (DoH) veya tls:// (DoT) üst çözücüyle kullanılabilir")
	}
	if g.ExitDNSRequirePins && len(pins) == 0 {
		return errors.New("sabitleme zorunluyken en az bir SPKI sabitlemesi verilmeli")
	}
	return nil
}

// pinnedTLS returns client settings that verify against the system CAs
// and then require a pinned key in the verified chain.
func pinnedTLS(pins []obfs.Pin) func(serverName string) *tls.Config {
	return func(serverName string) *tls.Config {
		cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
		// RequirePins only fails with InsecureSkipVerify, which is off.
		_ = obfs.RequirePins(cfg, pins)
		return cfg
	}
}

// pinnedForwarder returns the shared forwarder for spec with pins. The key
// cannot collide with a plain ExitDNSUpstream value (it holds "|").
func pinnedForwarder(spec string, pinSpecs []string, tlsFor func([]obfs.Pin) func(string) *tls.Config) (*dnsForwarder, error) {
	pins, err := obfs.ParsePins(pinSpecs)
	if err != nil {
		return nil, err
	}
	up, err := parseDNSUpstream(spec)
	if err != nil {
		return nil, err
	}
	if up.kind != upstreamDoH && up.kind != upstreamDoT {
		return nil, errExitDNSUnpinned
	}
	key := "pin|" + spec + "|" + strings.Join(pinSpecs, ",")
	forwardersMu.Lock()
	defer forwardersMu.Unlock()
	if f, ok := forwarders[key]; ok {
		return f, nil
	}
	f := newDNSForwarder(up, tlsFor(pins))
	if len(forwarders) >= maxForwarders {
		clear(forwarders)
	}
	forwarders[key] = f
	return f, nil
}

// g3ExitForwarder chooses the forwarder for ExitDNSUpstream, honouring the
// pin options.
func (e *Engine) g3ExitForwarder() (*dnsForwarder, error) {
	g := e.cfg.G3
	if len(g.ExitDNSPins) > 0 {
		return pinnedForwarder(e.cfg.ExitDNSUpstream, g.ExitDNSPins, pinnedTLS)
	}
	if g.ExitDNSRequirePins {
		return nil, errExitDNSUnpinned
	}
	return exitForwarder(e.cfg.ExitDNSUpstream)
}
