package coordinator

import (
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Clone detection, coordinator side (#603, ADR-0183). observeClone
// (membership.go) samples a device's endpoint when it sends a request; the
// sweep here samples every device from WireGuard's peer table every
// cloneSweepEvery, so two copies of one identity are caught even when one
// of them only keeps the tunnel up and never asks the coordinator anything.
// The alert goes to admin devices (TypeAlerts) and to the node side through
// CloneReporter. With clone quarantine on (hardening file), the identity
// gets no answers for cloneQuarantineFor after the last alternation: the
// coordinator may always refuse service, it can never remove a member.

const cloneQuarantineFor = time.Hour

// CloneReporter is implemented by the device side (G3) to show a clone
// alert received from the coordinator (TypeAlerts) to the owner and to
// apply a local quarantine of the identity's peer entry.
type CloneReporter interface {
	ReportClone(alert control.CloneAlert)
}

// cloneSweep samples the endpoints of all devices.
func (s *Server) cloneSweep() {
	if s.dev == nil {
		// Not running (tests): use the cached peer table if it is fresh.
		s.mu.Lock()
		fresh := time.Since(s.statAt) < statusCacheTTL
		s.mu.Unlock()
		if !fresh {
			return
		}
	}
	st, err := s.wgStatus(false)
	if err != nil {
		return
	}
	doc := s.cfg.Store.Document()
	for i := range doc.Devices {
		d := &doc.Devices[i]
		if p, ok := st.Peers[d.WireGuardKey]; ok && p.Endpoint.IsValid() {
			s.observeCloneAt(d, p.Endpoint)
		}
	}
}

// observeCloneAt records one endpoint sample of d (rate limited per device
// by cloneSample) and raises or extends its alert.
func (s *Server) observeCloneAt(d *trust.Device, ep netip.AddrPort) {
	now := s.cfg.Now()
	m := s.memberState()
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.clones[d.ID]
	if t != nil && now.Sub(t.sampled) < cloneSample {
		return
	}
	if t == nil {
		t = &cloneTrack{}
		m.clones[d.ID] = t
	}
	if !observeEndpoint(t, ep.String(), now) {
		return
	}
	a := m.alerts[d.ID]
	if a.DeviceID == "" {
		a = control.CloneAlert{DeviceID: d.ID, First: now}
		s.logger.Warn("one device identity is used at two places at once; it may have been copied", "device", d.Name)
	}
	a.Name, a.Flips, a.Last = d.Name, a.Flips+1, now
	a.Endpoints = slices.Clone(t.seen[max(0, len(t.seen)-2):])
	m.alerts[d.ID] = a
}

// cloneQuarantined reports whether id had a clone alert recently.
func (s *Server) cloneQuarantined(id string) bool {
	m := s.memberState()
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.alerts[id]
	return ok && s.cfg.Now().Sub(a.Last) < cloneQuarantineFor
}

// CloneAlerts returns the current clone alerts (panel and tests).
func (s *Server) CloneAlerts() []control.CloneAlert {
	m := s.memberState()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]control.CloneAlert, 0, len(m.alerts))
	for _, a := range m.alerts {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b control.CloneAlert) int {
		switch {
		case a.DeviceID < b.DeviceID:
			return -1
		case a.DeviceID > b.DeviceID:
			return 1
		}
		return 0
	})
	return out
}
