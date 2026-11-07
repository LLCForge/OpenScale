package service

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/speedtest"
	"github.com/openscale/openscale/internal/trust"
)

// AppsStatus implements panel.RemoteApps.
func (a *Apps) AppsStatus() panel.AppsStatus {
	doc, self, ok := a.current()
	a.mu.Lock()
	defer a.mu.Unlock()
	state := func(svc trust.RuleService) panel.ServiceState {
		st := panel.ServiceState{Hosted: ok && doc.HostsService(self.Name, svc)}
		if r := a.runners[svc]; r != nil {
			st.Running, st.Error = r.running, r.err
			if r.running {
				st.Address = r.bound.String()
			}
		}
		return st
	}
	out := panel.AppsStatus{
		SSH:            state(trust.ServiceSSH),
		Files:          state(trust.ServiceFiles),
		Wake:           state(trust.ServiceWake),
		Speedtest:      state(trust.ServiceSpeedtest),
		SSHFingerprint: a.fingerprint,
		PendingOffers:  len(a.pending),
	}
	if a.sshSrv != nil {
		out.SSHSessions = a.sshSrv.ActiveConnections()
	}
	return out
}

// RemoteDevice implements panel.RemoteApps.
func (a *Apps) RemoteDevice(name string) (panel.RemoteDeviceView, error) {
	doc, self, ok := a.current()
	if !ok {
		return panel.RemoteDeviceView{}, errNoTunnel()
	}
	return remoteView(doc, self.Name, normalizeDevice(name), a.cfg.Dir, a.reportFingerprint)
}

func (a *Apps) reportFingerprint(name string) string {
	if a.cfg.Reports == nil {
		return ""
	}
	return a.cfg.Reports()[name].SSHHostKey
}

// remoteView computes what device self may do with device name.
func remoteView(doc *trust.Document, self, name, dir string, fingerprint func(string) string) (panel.RemoteDeviceView, error) {
	dev, ok := doc.DeviceByName(name)
	if !ok {
		return panel.RemoteDeviceView{}, errors.New("böyle bir cihaz yok")
	}
	v := panel.RemoteDeviceView{
		Name: dev.Name, IPv4: dev.IPv4.String(), FQDN: dev.Name + "." + doc.DNSDomain,
		SSHUsers: []string{}, WakeRelays: []string{}, SSHPort: int(trust.SSHPort),
	}
	if name == self {
		return v, nil
	}
	seen := map[string]bool{}
	for _, r := range doc.Rules {
		if r.Service != trust.ServiceSSH {
			continue
		}
		for _, u := range r.Users {
			if !seen[u] && doc.AllowsSSH(self, name, u) {
				seen[u] = true
				v.SSHUsers = append(v.SSHUsers, u)
				if doc.AllowsSSHForward(self, name, u) {
					v.SSHForward = true
				}
			}
		}
	}
	slices.Sort(v.SSHUsers)
	v.SSHRoot = doc.AllowsSSH(self, name, trust.SSHRootUser)
	if v.SSHRoot && doc.AllowsSSHForward(self, name, trust.SSHRootUser) {
		v.SSHForward = true
	}
	v.CanSend = doc.AllowsFileSend(self, name)
	v.CanSpeed = doc.AllowsSpeedtest(self, name)
	if relays := doc.WakeRelays(self, name); relays != nil {
		v.WakeRelays = relays
	}
	if macs, err := LoadWakeMACs(dir); err == nil {
		v.WakeMAC = WakeMACFor(macs, name)
	}
	if fingerprint != nil {
		v.SSHFingerprint = fingerprint(name)
	}
	return v, nil
}

// SpeedTest implements panel.RemoteApps.
func (a *Apps) SpeedTest(ctx context.Context, device string, upload bool, seconds int) (panel.SpeedResult, error) {
	doc, self, ok := a.current()
	if !ok {
		return panel.SpeedResult{}, errNoTunnel()
	}
	target, ok := doc.DeviceByName(normalizeDevice(device))
	if !ok {
		return panel.SpeedResult{}, errors.New("böyle bir cihaz yok")
	}
	if !doc.AllowsSpeedtest(self.Name, target.Name) {
		return panel.SpeedResult{}, errors.New("bu cihazla hız testine izin veren bir kural yok")
	}
	if seconds < 1 || seconds > speedtestMaxPanel {
		seconds = int(speedtest.DefaultDuration / time.Second)
	}
	dir := speedtest.Download
	if upload {
		dir = speedtest.Upload
	}
	res, err := speedtest.Run(ctx, netip.AddrPortFrom(target.IPv4, trust.SpeedtestPort), dir, time.Duration(seconds)*time.Second)
	if err != nil {
		return panel.SpeedResult{}, err
	}
	return panel.SpeedResult{
		Device: target.Name, Direction: dir.String(), Bytes: res.Bytes,
		Seconds: res.Elapsed.Seconds(), Mbps: res.Mbps(),
	}, nil
}

// RemoteViewFor is remoteView for the command line, which has no reports.
func RemoteViewFor(doc *trust.Document, self, name, dir string) (panel.RemoteDeviceView, error) {
	return remoteView(doc, self, name, dir, nil)
}
