package service

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"time"

	"github.com/openscale/openscale/internal/leaktest"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// Leak test (#77) and captive portal exception (#85) of the desktop
// service, for the panel (ADR-0023).

// LeakInput builds the leak test's input from the diagnostics status, the
// coordinator-observed endpoint of this device ("" if unknown) and the
// signed document. The caller adds what only the operating system knows:
// kill switch, leak guard, resolvers and local addresses.
func LeakInput(st panel.DiagStatus, mapped string, doc *trust.Document) (leaktest.Input, error) {
	if doc == nil || doc.Coordinator == nil {
		return leaktest.Input{}, errors.New("ağ belgesinde koordinatör yok")
	}
	in := leaktest.Input{
		ExitNode:            st.ExitNode,
		CoordinatorEndpoint: doc.Coordinator.Endpoint,
		Overlay4:            doc.IPv4Prefix,
		Overlay6:            doc.IPv6Prefix,
		TunnelLink:          st.Interface,
	}
	if ap, err := netip.ParseAddrPort(mapped); err == nil {
		in.OwnPublic = ap.Addr().Unmap()
	}
	for _, p := range st.Peers {
		if !p.ActiveExit {
			continue
		}
		if a, err := netip.ParseAddr(p.IPv4); err == nil {
			in.ExitDNS = a
		}
		if ap, err := netip.ParseAddrPort(p.Endpoint); err == nil && p.Path == panel.PathDirect {
			in.ExitPublic = ap.Addr().Unmap()
		}
	}
	return in, nil
}

var _ panel.LeakApp = (*Runtime)(nil)

// leakProber is the network side of the service's leak test; tests
// replace it.
var leakProber leaktest.Prober = leaktest.NetProber{}

// ExitLeakTest implements panel.LeakApp: it checks, through this
// network's coordinator and the exit node's resolver only, whether the
// internet traffic really leaves through the exit node.
func (r *Runtime) ExitLeakTest(ctx context.Context) (leaktest.Report, error) {
	e := r.currentEngine()
	if e == nil {
		return leaktest.Report{}, ErrTunnelNotRunning
	}
	st, err := r.engineDiag().BaseStatus()
	if err != nil {
		return leaktest.Report{}, err
	}
	if st.ExitNode == "" {
		return leaktest.Report{}, leaktest.ErrNoExitNode
	}
	mapped := ""
	if nr, err := e.NetCheck(ctx); err == nil {
		mapped = nr.MappedEndpoint
	}
	in, err := LeakInput(st, mapped, e.Document())
	if err != nil {
		return leaktest.Report{}, err
	}
	ks := r.killSwitchSnapshot()
	in.KillSwitch, in.KillSwitchKnown = ks.installed, true
	guard, _ := osnet.LeakGuardInstalled()
	// On Windows the WFP kill switch holds DNS and IPv6 to the tunnel.
	in.DNSGuard, in.IPv6Guard = ks.installed || guard, ks.installed || guard
	if res, err := osnet.SystemResolvers(); err == nil && res != nil {
		in.Resolvers = []leaktest.Resolver{}
		for _, x := range res {
			in.Resolvers = append(in.Resolvers, leaktest.Resolver{Link: x.Link, Addr: x.Addr})
		}
	}
	in.LocalAddrs = leaktest.LocalAddrs(st.Interface)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rep, err := leaktest.Run(ctx, in, leakProber, r.cfg.Now())
	if err != nil {
		return leaktest.Report{}, err
	}
	leaktest.AddLocation(&rep, serviceLocale()) // #404: information only
	r.logger.Info("exit leak test", "leak", rep.Leak)
	return rep, nil
}

// captiveOps are the system calls of the captive portal exception; tests
// replace them.
var captiveOps = struct {
	allow    func([]netip.Addr, time.Duration) error
	revoke   func() error
	gateways func() ([]netip.Addr, error)
}{osnet.AllowCaptivePortal, osnet.RevokeCaptivePortal, osnet.DefaultGateways4}

// AllowCaptivePortal implements panel.LeakApp: the owner opens the kill
// switch for the local gateway's login page (and the page the gateway
// redirects to, when that is a local address) for d (#85). The exception
// closes by itself when d ends or the service stops.
func (r *Runtime) AllowCaptivePortal(d time.Duration) (panel.CaptiveGrant, error) {
	if !r.killSwitchSnapshot().installed {
		return panel.CaptiveGrant{}, osnet.ErrKillSwitchNotInstalled
	}
	var addrs []netip.Addr
	if gws, err := captiveOps.gateways(); err == nil {
		for _, g := range gws {
			if osnet.CaptiveAddressAllowed(g) && len(addrs) < 2 {
				addrs = append(addrs, g)
			}
		}
	}
	if e := r.currentEngine(); e != nil {
		if a, ok := captiveLocationAddr(e.CaptivePortal().Location); ok && !containsAddr(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return panel.CaptiveGrant{}, errors.New("yerel ağ geçidi bulunamadı")
	}
	if err := captiveOps.allow(addrs, d); err != nil {
		return panel.CaptiveGrant{}, err
	}
	g := panel.CaptiveGrant{Until: r.cfg.Now().Add(d)}
	for _, a := range addrs {
		g.Addrs = append(g.Addrs, a.String())
	}
	r.logger.Info("captive portal exception opened", "minutes", int(d.Minutes()), "addresses", len(addrs))
	return g, nil
}

// RevokeCaptivePortal implements panel.LeakApp.
func (r *Runtime) RevokeCaptivePortal() error {
	if err := captiveOps.revoke(); err != nil {
		return err
	}
	r.logger.Info("captive portal exception closed")
	return nil
}

// captiveLocationAddr returns the host of a portal redirect when it is a
// literal local IPv4 address; names are never resolved here (that would
// be DNS outside the tunnel).
func captiveLocationAddr(loc string) (netip.Addr, bool) {
	u, err := url.Parse(loc)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil || !osnet.CaptiveAddressAllowed(a) {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
