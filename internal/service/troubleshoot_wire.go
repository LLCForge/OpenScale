package service

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/troubleshoot"
)

// The layered troubleshooter (#835) on this computer's tunnel. Every probe
// reuses a diagnostic the service already has; the only outside traffic
// is the system resolver asked for the coordinator's name and the
// coordinator check itself (both to the owner's own coordinator).

var _ panel.TroubleshootControl = (*Runtime)(nil)

// Troubleshoot implements panel.TroubleshootControl.
func (r *Runtime) Troubleshoot(ctx context.Context) troubleshoot.Report {
	return troubleshoot.Run(ctx, &serviceProbe{r: r}, r.cfg.Now)
}

type serviceProbe struct {
	r *Runtime
	// status is read once per run.
	status *panel.DiagStatus
}

func (p *serviceProbe) diagStatus() (panel.DiagStatus, bool) {
	if p.status != nil {
		return *p.status, true
	}
	st, err := p.r.DiagStatus()
	if err != nil {
		return panel.DiagStatus{}, false
	}
	p.status = &st
	return st, true
}

func (p *serviceProbe) Interface(context.Context) troubleshoot.Interface {
	var in troubleshoot.Interface
	if st, err := p.r.currentSettings(); err == nil {
		in.Disconnected = st.Disconnected
	}
	st, ok := p.diagStatus()
	if !ok {
		in.Err = "durum okunamadı"
		return in
	}
	in.Running = st.Running
	in.Name = st.Interface
	if in.Name == "" {
		in.Name = p.r.tunnelInterface()
	}
	if in.Name != "" {
		if ifc, err := net.InterfaceByName(in.Name); err == nil {
			in.Up = ifc.Flags&net.FlagUp != 0
		} else {
			// Userspace tunnels have no OS interface to look up.
			in.Up = in.Running
		}
	}
	p.r.mu.Lock()
	in.Err = p.r.engineErr
	p.r.mu.Unlock()
	return in
}

func (p *serviceProbe) Gateways(context.Context) ([]netip.Addr, error) {
	return osnet.DefaultGateways4()
}

func (p *serviceProbe) CoordinatorEndpoint() string {
	store, err := member.Open(p.r.path(DeviceDir))
	if err != nil {
		return ""
	}
	if c := store.Document().Coordinator; c != nil {
		return c.Endpoint
	}
	return ""
}

func (p *serviceProbe) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (p *serviceProbe) MagicDNSError() string {
	st, err := p.r.DiagDNS()
	if err != nil {
		return ""
	}
	return st.MagicDNSError
}

func (p *serviceProbe) Coordinator(ctx context.Context) troubleshoot.Coordinator {
	rep, err := p.r.DiagNetCheck(ctx)
	if err != nil {
		return troubleshoot.Coordinator{Err: err.Error()}
	}
	return troubleshoot.Coordinator{Reachable: rep.CoordinatorReachable || rep.CoordinatorOverTCP, RTT: rep.CoordinatorRTT,
		OverTCP: rep.CoordinatorOverTCP, Captive: rep.CaptivePortal.Detected, Err: rep.CoordinatorError}
}

func (p *serviceProbe) Peers(context.Context) ([]troubleshoot.Peer, error) {
	st, ok := p.diagStatus()
	if !ok {
		return nil, troubleshoot.ErrNoProbe
	}
	reasons := map[string]string{}
	if paths, err := p.r.DiagPaths(); err == nil {
		for _, pp := range paths {
			reasons[pp.Name] = pp.RelayReason
		}
	}
	out := make([]troubleshoot.Peer, 0, len(st.Peers))
	for _, peer := range st.Peers {
		var last time.Time
		if peer.LastHandshake != nil {
			last = *peer.LastHandshake
		}
		out = append(out, troubleshoot.Peer{Name: peer.Name, Online: peer.Online, Path: peer.Path, LastHandshake: last, RelayReason: reasons[peer.Name]})
	}
	return out, nil
}

func (p *serviceProbe) RelayTest(ctx context.Context, peer string) (time.Duration, error) {
	return p.r.DiagRelayTest(ctx, peer)
}
