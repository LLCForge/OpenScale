package node

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/sysinfo"
)

// infoInterval is the minimum time between two answers to the same admin.
const infoInterval = 200 * time.Millisecond

// intercept consumes control traffic before the packet filter: replies from
// the coordinator or to this admin's status queries, and status queries
// from admin devices.
func (e *Engine) intercept(pkt []byte) bool {
	if e.chainIntercept(pkt) { // #618, g8_chain_relay.go
		return true
	}
	if e.receiveRelay(pkt) || e.client.intercept(pkt) || e.receivePQ(pkt) {
		return true
	}
	return e.serveInfo(pkt) || e.serveGossip(pkt) || e.serveExitDNS(pkt) || e.serveExitDNSTCP(pkt)
}

// serveInfo answers a status query from an admin device. WireGuard already
// authenticated the source address; anything else falls through to the
// filter, which denies it unless a rule allows it.
func (e *Engine) serveInfo(pkt []byte) bool {
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoUDP || in.Fragment || in.DstPort != control.InfoPort {
		return false
	}
	if req, err := control.Decode(in.Payload); err == nil && req.T == control.TypeInfoDetail {
		return e.serveInfoDetail(in, req) // ADR-0143, info_detail.go
	}
	now := e.cfg.Now()
	e.mu.Lock()
	self := e.self.IPv4
	allowed := e.admins[in.Src]
	recent := now.Sub(e.lastInfo[in.Src]) < infoInterval
	if allowed && !recent {
		if e.lastInfo == nil {
			e.lastInfo = map[netip.Addr]time.Time{}
		}
		e.lastInfo[in.Src] = now
	}
	e.mu.Unlock()
	if in.Dst != self || !allowed {
		return false
	}
	if e.peerAddrRefused(in.Src) {
		return true // quarantine and lost mode, exitdns_g3.go
	}
	if recent {
		return true
	}
	req, err := control.Decode(in.Payload)
	if err != nil || req.T != control.TypeInfo {
		return true
	}
	data, err := e.SelfInfo().Encode()
	if err != nil {
		return true
	}
	out, err := control.Encode(control.Message{T: control.TypeInfo, ID: req.ID, Data: data})
	if err != nil {
		return true
	}
	reply, err := packet.BuildUDP4(self, in.Src, control.InfoPort, in.SrcPort, out)
	if err == nil {
		e.wrap.Inject(reply)
	}
	return true
}

// SelfInfo is this computer's own report.
func (e *Engine) SelfInfo() sysinfo.Info {
	in := sysinfo.Collect(e.cfg.Now())
	e.mu.Lock()
	in.PublicIP = e.publicIP
	in.Synced = !e.status.LastSync.IsZero() && e.status.LastSyncError == ""
	e.mu.Unlock()
	return in
}

// QueryInfo asks the device at addr for its system report. Only answered
// when this device has the admin role.
func (e *Engine) QueryInfo(ctx context.Context, addr netip.Addr) (sysinfo.Info, error) {
	resp, err := e.client.callTo(ctx, addr, control.InfoPort, control.Message{T: control.TypeInfo})
	if err != nil {
		return sysinfo.Info{}, err
	}
	if resp.T != control.TypeInfo {
		return sysinfo.Info{}, errors.New("unexpected reply")
	}
	in, err := sysinfo.Decode(resp.Data)
	if err == nil {
		e.attachDetail(ctx, &in, "dev/"+addr.String(), func(c context.Context, m control.Message) (control.Message, error) {
			return e.client.callTo(c, addr, control.InfoPort, m)
		})
	}
	return in, err
}

// CoordinatorInfo asks the coordinator for its system report.
func (e *Engine) CoordinatorInfo(ctx context.Context) (sysinfo.Info, error) {
	resp, err := e.client.call(ctx, control.Message{T: control.TypeInfo})
	if err != nil {
		return sysinfo.Info{}, err
	}
	if resp.T != control.TypeInfo {
		return sysinfo.Info{}, errors.New("unexpected reply")
	}
	in, err := sysinfo.Decode(resp.Data)
	if err == nil {
		e.attachDetail(ctx, &in, "coordinator", e.client.call)
	}
	return in, err
}
