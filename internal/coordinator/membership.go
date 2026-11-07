package coordinator

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Membership extensions on the coordinator (ADR-0027, ADR-0028): root
// transitions, leave requests, rejecting a pending enrollment, the minimum
// client version and clone detection. The coordinator stays untrusted: it
// only stores and forwards signed objects, drops things on request and
// reports what it observes; it never adds or removes a member.

const (
	// cloneWindow is how long endpoint returns are counted.
	cloneWindow = 10 * time.Minute
	// cloneReturns is how many returns to an earlier endpoint within
	// cloneWindow raise an alert. One roaming device (Wi-Fi to mobile)
	// changes once; two copies of one identity keep alternating.
	cloneReturns = 3
	// cloneSample rate-limits endpoint samples per device.
	cloneSample = 2 * time.Second
	// cloneMemory is how many distinct endpoints are remembered.
	cloneMemory = 4
	// alertLife keeps an alert after the last flip.
	alertLife = 24 * time.Hour
	// maxPendingPerInvite bounds pending enrollments of one multi-use
	// invite; maxPendingTotal bounds all of them.
	maxPendingPerInvite = 8
	maxPendingTotal     = 4 * trust.MaxInvites
)

// membershipFeatures are announced in the caps reply.
var membershipFeatures = []string{control.FeatureRoot, control.FeatureLeave, control.FeatureReject, control.FeatureAlerts, control.FeatureVersion}

type cloneTrack struct {
	last    string
	seen    []string
	returns []time.Time
	sampled time.Time
}

type leaveEntry struct {
	signed trust.SignedLeave
	at     time.Time
}

// memState is guarded by its own mutex, like extState.
type memState struct {
	mu       sync.Mutex
	versions map[string]string // device id -> reported version
	leaves   map[string]leaveEntry
	rejected map[string]time.Time // pending key -> until
	clones   map[string]*cloneTrack
	alerts   map[string]control.CloneAlert
}

func newMemState() *memState {
	return &memState{versions: map[string]string{}, leaves: map[string]leaveEntry{}, rejected: map[string]time.Time{},
		clones: map[string]*cloneTrack{}, alerts: map[string]control.CloneAlert{}}
}

// memberState returns the membership state created by New.
func (s *Server) memberState() *memState { return s.mem }

// pendingKeyFor identifies a pending enrollment: one per single-use invite,
// one per device of a multi-use invite.
func pendingKeyFor(inv trust.Invite, deviceID string) string {
	if inv.MultiUse() {
		return inv.ID + "/" + deviceID
	}
	return inv.ID
}

// enrollRejected reports whether the owner rejected this enrollment.
func (s *Server) enrollRejected(key string) bool {
	m := s.memberState()
	now := s.cfg.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.rejected[key]
	if ok && !now.Before(until) {
		delete(m.rejected, key)
		return false
	}
	return ok
}

// pendingRoom reports whether another pending enrollment fits for inv.
// Called with s.mu held.
func (s *Server) pendingRoomLocked(inv trust.Invite, key string) bool {
	if _, exists := s.pending[key]; exists {
		return true
	}
	if len(s.pending) >= maxPendingTotal {
		return false
	}
	n := 0
	for _, p := range s.pending {
		if p.inviteID == inv.ID {
			n++
		}
	}
	return n < min(maxPendingPerInvite, max(inv.Remaining(), 1))
}

// versionGate refuses a device whose reported version is below the
// network's minimum (F-027). Admin devices are never refused, so the owner
// cannot lock themselves out of publishing a document that lowers it.
func (s *Server) versionGate(req control.Message, doc *trust.Document, self *trust.Device) string {
	min := doc.MinClientVersion
	if min == "" || self.HasRole(trust.RoleAdmin) {
		return ""
	}
	switch req.T {
	case control.TypeClientVersion, control.TypeCaps, control.TypeLeave,
		// A device below the minimum must still be able to fetch the update
		// that lifts it (ADR-0225).
		control.TypeRelease, control.TypeReleaseFile:
		return ""
	}
	m := s.memberState()
	m.mu.Lock()
	v, ok := m.versions[self.ID]
	m.mu.Unlock()
	switch {
	case !ok:
		return fmt.Sprintf("%s; bu ağ en az OpenScale %s istiyor, güncelleyin", control.ErrVersionNotReported, min)
	case !trust.ClientVersionAtLeast(v, min):
		return fmt.Sprintf("istemci sürümü (%s) ağın asgari sürümünün (%s) altında; OpenScale'i güncelleyin", v, min)
	}
	return ""
}

// handleMembership answers the membership extension types for a member.
func (s *Server) handleMembership(req control.Message, doc *trust.Document, self *trust.Device) (control.Message, bool) {
	now := s.cfg.Now()
	m := s.memberState()
	switch req.T {
	case control.TypeClientVersion:
		if len(req.Data) == 0 || len(req.Data) > control.MaxClientVersionLen {
			return control.Message{T: control.TypeError, Error: "invalid version"}, true
		}
		m.mu.Lock()
		m.versions[self.ID] = string(req.Data)
		m.mu.Unlock()
		return control.Message{T: control.TypeClientVersion, Complete: true}, true
	case control.TypeRoot:
		ts := s.cfg.Store.Transitions()
		if req.Offset > len(ts) {
			return control.Message{T: control.TypeError, Error: "offset out of range"}, true
		}
		resp := control.Message{T: control.TypeRoot, Version: s.cfg.Store.Epoch(), Total: len(ts), Next: min(req.Offset+1, len(ts))}
		if req.Offset < len(ts) {
			resp.Offset, resp.Data, resp.Sig = req.Offset, ts[req.Offset].Payload, ts[req.Offset].Signature
		}
		return resp, true
	case control.TypeRootPut:
		st := trust.SignedRootTransition{Payload: req.Data, Signature: req.Sig}
		if err := s.cfg.Store.OfferTransition(st, now); err != nil {
			s.rejected(RejectTransition, self.IPv4, err) // #187
			return control.Message{T: control.TypeError, Error: "transition rejected"}, true
		}
		return control.Message{T: control.TypeRootPut, Complete: true}, true
	case control.TypeLeave:
		sl := trust.SignedLeave{DeviceID: self.ID, Payload: req.Data, Signature: req.Sig}
		if _, _, err := trust.OpenLeaveRequest(doc, sl, now); err != nil {
			s.rejected(RejectLeave, self.IPv4, err) // #187
			return control.Message{T: control.TypeError, Error: "leave rejected"}, true
		}
		m.mu.Lock()
		m.leaves[self.ID] = leaveEntry{signed: sl, at: now}
		m.mu.Unlock()
		s.logger.Info("device asked to leave the network", "device", self.Name)
		return control.Message{T: control.TypeLeave, Complete: true}, true
	case control.TypeLeaves, control.TypeReject, control.TypeAlerts:
		if !self.HasRole(trust.RoleAdmin) {
			return control.Message{T: control.TypeError, Error: "not allowed"}, true
		}
	default:
		return control.Message{}, false
	}
	switch req.T {
	case control.TypeLeaves:
		return s.listLeaves(req, doc), true
	case control.TypeReject:
		return s.rejectPending(req, doc), true
	default:
		return s.listAlerts(req, doc), true
	}
}

func (s *Server) listLeaves(req control.Message, doc *trust.Document) control.Message {
	m := s.memberState()
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.leaves))
	for id := range m.leaves {
		if slices.ContainsFunc(doc.Devices, func(d trust.Device) bool { return d.ID == id }) {
			ids = append(ids, id)
		} else {
			delete(m.leaves, id)
		}
	}
	slices.Sort(ids)
	if req.Offset > len(ids) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	resp := control.Message{T: control.TypeLeaves, Total: len(ids), Next: min(req.Offset+1, len(ids))}
	if req.Offset < len(ids) {
		e := m.leaves[ids[req.Offset]]
		resp.Offset, resp.Target, resp.Data, resp.Sig = req.Offset, e.signed.DeviceID, e.signed.Payload, e.signed.Signature
	}
	return resp
}

// rejectPending drops a pending enrollment and refuses it until the invite
// expires (F-107). Dropping is harmless: the coordinator can always refuse.
func (s *Server) rejectPending(req control.Message, doc *trust.Document) control.Message {
	deviceID := string(req.Data)
	inv, ok := doc.InviteByID(req.Target)
	if !ok || len(deviceID) != 32 {
		return control.Message{T: control.TypeError, Error: "unknown enrollment"}
	}
	key := pendingKeyFor(inv, deviceID)
	s.mu.Lock()
	if p, ok := s.pending[key]; ok && p.deviceID == deviceID {
		delete(s.pending, key)
	}
	s.mu.Unlock()
	m := s.memberState()
	m.mu.Lock()
	m.rejected[inv.ID+"/"+deviceID] = inv.ExpiresAt
	m.mu.Unlock()
	return control.Message{T: control.TypeReject, Complete: true}
}

func (s *Server) listAlerts(req control.Message, doc *trust.Document) control.Message {
	now := s.cfg.Now()
	m := s.memberState()
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.alerts))
	for id, a := range m.alerts {
		if now.Sub(a.Last) > alertLife || !slices.ContainsFunc(doc.Devices, func(d trust.Device) bool { return d.ID == id }) {
			delete(m.alerts, id)
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if req.Offset > len(ids) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	resp := control.Message{T: control.TypeAlerts, Total: len(ids), Next: min(req.Offset+1, len(ids))}
	if req.Offset < len(ids) {
		data, err := control.EncodeCloneAlert(m.alerts[ids[req.Offset]])
		if err != nil {
			return control.Message{T: control.TypeError, Error: "alert unavailable"}
		}
		resp.Offset, resp.Data = req.Offset, data
	}
	return resp
}

// observeClone samples the endpoint WireGuard last saw the device at. Two
// computers with one identity make it alternate between their endpoints;
// that is reported to admin devices only, never acted upon.
func (s *Server) observeClone(self *trust.Device) {
	now := s.cfg.Now()
	m := s.memberState()
	m.mu.Lock()
	t := m.clones[self.ID]
	if t != nil && now.Sub(t.sampled) < cloneSample {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	if ep := s.observed(self); ep.IsValid() {
		s.observeCloneAt(self, ep) // g2_clone.go
	}
}

// observeEndpoint records one sample and reports whether the device keeps
// returning to endpoints it left (the clone pattern).
func observeEndpoint(t *cloneTrack, ep string, now time.Time) bool {
	t.sampled = now
	t.returns = slices.DeleteFunc(t.returns, func(at time.Time) bool { return now.Sub(at) > cloneWindow })
	if ep == t.last {
		return false
	}
	if t.last != "" && slices.Contains(t.seen, ep) {
		t.returns = append(t.returns, now)
	}
	if i := slices.Index(t.seen, ep); i >= 0 {
		t.seen = slices.Delete(t.seen, i, i+1)
	}
	t.seen = append(t.seen, ep)
	if len(t.seen) > cloneMemory {
		t.seen = t.seen[len(t.seen)-cloneMemory:]
	}
	t.last = ep
	return len(t.returns) >= cloneReturns
}

// pruneMembership forgets state of devices that left the document.
func (s *Server) pruneMembership(doc *trust.Document) {
	m := s.memberState()
	known := map[string]bool{}
	for _, d := range doc.Devices {
		known[d.ID] = true
	}
	now := s.cfg.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.versions {
		if !known[id] {
			delete(m.versions, id)
		}
	}
	for id := range m.clones {
		if !known[id] {
			delete(m.clones, id)
		}
	}
	for k, until := range m.rejected {
		if !now.Before(until) {
			delete(m.rejected, k)
		}
	}
}
