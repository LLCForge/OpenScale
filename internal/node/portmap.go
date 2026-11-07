package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/portmap"
)

// Router port mapping (ADR-0042, #55, F-003): with PortMap.Enabled the
// device asks its default gateway, and only it, to forward the WireGuard
// UDP port (PCP, NAT-PMP, UPnP-IGD) and reports the mapped public address
// as a candidate.

// portMapRecheck is how often the gateway, local address and WireGuard
// port are read again.
const portMapRecheck = 30 * time.Second

// PortMapConfig turns router port mapping on and single protocols off.
type PortMapConfig struct {
	// Enabled asks the gateway for a mapping. Off by default (#55).
	Enabled bool
	// DisablePCP, DisableNATPMP and DisableUPnP turn single protocols off.
	DisablePCP    bool
	DisableNATPMP bool
	DisableUPnP   bool
}

// PortMapStatus is the state of router port mapping, for the panel and
// diagnostics.
type PortMapStatus struct {
	Enabled bool
	// Active is true while a mapping is in effect.
	Active bool
	// Protocol is "PCP", "NAT-PMP" or "UPnP-IGD" while active.
	Protocol string
	// External is the public address other devices use.
	External netip.AddrPort
	// Gateway and Local are the gateway asked and this device's address.
	Gateway netip.Addr
	Local   netip.AddrPort
	// RenewAt is the next renewal.
	RenewAt time.Time
	// LastError is the last failure, in Turkish.
	LastError string
}

// portMapState is guarded by its own mutex.
type portMapState struct {
	mu     sync.Mutex
	status PortMapStatus
}

// portMapTarget is what a mapping depends on.
type portMapTarget struct {
	gw, local netip.Addr
	port      uint16
}

// localAddrToward returns the local address the system would use to reach
// gw. Connecting a UDP socket sends nothing. Replaced in tests.
var localAddrToward = func(gw netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(gw, 5351)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return ap.Addr().Unmap(), nil
}

// portMapOptions builds the client options from the configuration.
func (e *Engine) portMapOptions() portmap.Options {
	pm := e.cfg.PortMap
	return portmap.Options{DisablePCP: pm.DisablePCP, DisableNATPMP: pm.DisableNATPMP, DisableUPnP: pm.DisableUPnP,
		Logger: e.logger, Now: e.cfg.Now}
}

// portMapTarget finds the gateway, the local address toward it and the
// WireGuard port.
func (e *Engine) portMapTarget() (portMapTarget, error) {
	st, err := e.wgStatus()
	if err != nil {
		return portMapTarget{}, err
	}
	if st.ListenPort <= 0 || st.ListenPort > 65535 {
		return portMapTarget{}, errors.New("WireGuard portu bilinmiyor")
	}
	gws, err := gatewaysFunc()
	if err != nil {
		return portMapTarget{}, errors.New("varsayılan ağ geçidi okunamadı")
	}
	var gw netip.Addr
	for _, g := range gws {
		if gatewayAllowed(g) {
			gw = g.Unmap()
			break
		}
	}
	if !gw.IsValid() {
		return portMapTarget{}, errors.New("yerel ağda bir ağ geçidi yok")
	}
	local, err := localAddrToward(gw)
	if err != nil {
		return portMapTarget{}, err
	}
	doc := e.cfg.Store.Document()
	if inAny([]netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, local) {
		return portMapTarget{}, errors.New("ağ geçidine giden yol tünelden geçiyor (çıkış düğümü); port eşleme yapılmadı")
	}
	if !gatewayAllowed(local) {
		return portMapTarget{}, errors.New("yerel adres yerel ağda değil")
	}
	return portMapTarget{gw: gw, local: local, port: uint16(st.ListenPort)}, nil
}

// runPortMap keeps a mapping on the current gateway until ctx ends; a new
// gateway, local address or WireGuard port replaces the client (the old
// mapping is deleted first).
func (e *Engine) runPortMap(ctx context.Context) {
	pm := &e.extras.portMap
	pm.mu.Lock()
	pm.status = PortMapStatus{Enabled: true}
	pm.mu.Unlock()
	var (
		cur    portMapTarget
		cancel context.CancelFunc
		done   chan struct{}
	)
	stopClient := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel, done = nil, nil
		}
	}
	defer stopClient()
	ticker := time.NewTicker(portMapRecheck)
	defer ticker.Stop()
	for {
		t, err := e.portMapTarget()
		switch {
		case err != nil:
			stopClient()
			cur = portMapTarget{}
			e.setPortMapError(err)
		case t != cur || cancel == nil:
			stopClient()
			c, err := portmap.New(t.gw, t.local, t.port, e.portMapOptions())
			if err != nil {
				e.setPortMapError(err)
				break
			}
			cur = t
			pm.mu.Lock()
			pm.status.Gateway, pm.status.Local, pm.status.LastError = t.gw, netip.AddrPortFrom(t.local, t.port), ""
			pm.mu.Unlock()
			cctx, cc := context.WithCancel(ctx)
			cancel, done = cc, make(chan struct{})
			go func(d chan struct{}) {
				defer close(d)
				c.Run(cctx, e.onPortMap)
			}(done)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-e.extras.netWake:
		}
	}
}

func (e *Engine) setPortMapError(err error) {
	pm := &e.extras.portMap
	pm.mu.Lock()
	pm.status.LastError = err.Error()
	pm.mu.Unlock()
}

// onPortMap records a mapping change and reports candidates soon.
func (e *Engine) onPortMap(m portmap.Mapping, ok bool) {
	pm := &e.extras.portMap
	pm.mu.Lock()
	before := pm.status.External
	pm.status.Active = ok
	if ok {
		pm.status.Protocol, pm.status.External, pm.status.RenewAt, pm.status.LastError = m.Protocol.String(), m.External, m.RenewAt(), ""
	} else {
		pm.status.Protocol, pm.status.External, pm.status.RenewAt = "", netip.AddrPort{}, time.Time{}
	}
	after := pm.status.External
	pm.mu.Unlock()
	if before != after {
		select {
		case e.syncWake <- struct{}{}:
		default:
		}
	}
}

// mappedCandidate returns the router-mapped public address, if any.
func (e *Engine) mappedCandidate() (netip.AddrPort, bool) {
	pm := &e.extras.portMap
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.status.External, pm.status.Active && pm.status.External.IsValid()
}

// PortMapStatus returns the state of router port mapping (ADR-0042).
func (e *Engine) PortMapStatus() PortMapStatus {
	pm := &e.extras.portMap
	pm.mu.Lock()
	defer pm.mu.Unlock()
	st := pm.status
	st.Enabled = e.cfg.PortMap.Enabled && !e.cfg.ForceRelay
	return st
}
