package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Membership endpoints (ADR-0027, ADR-0028): inactive devices and removing
// several at once, leave requests, clone alerts, the minimum client
// version, ephemeral devices, preauthorized enrollment keys, invite notes
// and rejecting a pending enrollment, and leaving the network from this
// computer.

// MembershipApp is implemented by the desktop service when its tunnel can
// reach the coordinator's membership extensions. The panel works without
// it: the related lists then stay empty with an explanation.
type MembershipApp interface {
	Leaves(ctx context.Context) ([]trust.SignedLeave, error)
	CloneAlerts(ctx context.Context) ([]control.CloneAlert, error)
	RejectPending(ctx context.Context, inviteID, deviceID string) error
	// LeaveNetwork sends this computer's signed leave request and forgets
	// its membership; it returns the request line for the owner.
	LeaveNetwork(ctx context.Context) (string, error)
}

const (
	maxRemoveAtOnce   = 64
	maxPreauthHours   = int(trust.MaxDeviceLife / time.Hour)
	maxMinVersionLen  = 32
	membershipTimeout = 10 * time.Second
)

func (s *Server) membershipRoutes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	appWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	mux.HandleFunc("GET /api/membership", owner(s.handleMembership))
	mux.HandleFunc("POST /api/membership/remove", ownerWrite(s.handleRemoveDevices))
	mux.HandleFunc("POST /api/membership/leave-apply", ownerWrite(s.handleApplyLeave))
	mux.HandleFunc("POST /api/membership/min-version", ownerWrite(s.handleMinVersion))
	mux.HandleFunc("POST /api/membership/ephemeral", ownerWrite(s.handleEphemeral))
	mux.HandleFunc("POST /api/membership/preauth", ownerWrite(s.handlePreauth))
	mux.HandleFunc("POST /api/invites/reject", ownerWrite(s.handleRejectPending))
	mux.HandleFunc("POST /api/invites/note", ownerWrite(s.handleInviteNote))
	mux.HandleFunc("POST /api/app/leave", appWrite(s.handleAppLeave))
}

func (s *Server) membershipApp() (MembershipApp, bool) {
	if s.app == nil {
		return nil, false
	}
	m, ok := s.app.(MembershipApp)
	return m, ok
}

type inactiveView struct {
	Name      string     `json:"name"`
	LastSeen  *time.Time `json:"lastSeen"`
	AddedAt   time.Time  `json:"addedAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	Days      int        `json:"days"`
	Ephemeral bool       `json:"ephemeral"`
	Admin     bool       `json:"admin"`
}

type leaveView struct {
	DeviceID    string    `json:"deviceId"`
	Name        string    `json:"name"`
	RequestedAt time.Time `json:"requestedAt"`
}

type alertView struct {
	Name      string    `json:"name"`
	Flips     int       `json:"flips"`
	Endpoints []string  `json:"endpoints"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
}

type membershipResponse struct {
	InactiveDays     int            `json:"inactiveDays"`
	Inactive         []inactiveView `json:"inactive"`
	Ephemeral        []string       `json:"ephemeral"`
	Leaves           []leaveView    `json:"leaves"`
	Alerts           []alertView    `json:"alerts"`
	LiveError        string         `json:"liveError"`
	MinClientVersion string         `json:"minClientVersion"`
	RecoveryKeys     int            `json:"recoveryKeys"`
	RootEpoch        uint64         `json:"rootEpoch"`
}

var errNoLive = errors.New("Ayrılma istekleri ve kopya kimlik uyarıları yalnızca masaüstü uygulamasında ve tünel açıkken görünür.")

func (s *Server) handleMembership(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &days); err != nil || days < 1 || days > 3650 {
			writeError(w, http.StatusBadRequest, "Gün sayısı 1 ile 3650 arasında olmalı.")
			return
		}
	}
	now := s.now()
	resp := membershipResponse{InactiveDays: days, Inactive: []inactiveView{}, Ephemeral: []string{}, Leaves: []leaveView{}, Alerts: []alertView{},
		MinClientVersion: doc.MinClientVersion, RecoveryKeys: len(doc.RecoveryKeys), RootEpoch: doc.RootEpoch}
	live := map[string]time.Time{}
	if s.app != nil {
		stats := s.app.LiveStats()
		for _, d := range doc.Devices {
			for _, m := range []map[trust.Key]PeerTraffic{stats.Direct, stats.ViaCoordinator} {
				if p, ok := m[d.WireGuardKey]; ok && p.LastHandshake.After(live[d.ID]) {
					live[d.ID] = p.LastHandshake
				}
			}
		}
		// Remembered so the list survives restarts; best effort.
		_ = s.network().RecordSeen(live)
	}
	for _, d := range s.network().InactiveDevices(live, time.Duration(days)*24*time.Hour, now) {
		v := inactiveView{Name: d.Name, AddedAt: d.AddedAt, ExpiresAt: d.ExpiresAt, Days: d.Days, Ephemeral: d.Ephemeral, Admin: d.Admin}
		if !d.LastSeen.IsZero() {
			t := d.LastSeen
			v.LastSeen = &t
		}
		resp.Inactive = append(resp.Inactive, v)
	}
	for _, d := range doc.Devices {
		if d.Ephemeral {
			resp.Ephemeral = append(resp.Ephemeral, d.Name)
		}
	}
	m, ok := s.membershipApp()
	if !ok {
		resp.LiveError = errNoLive.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), membershipTimeout)
	defer cancel()
	if list, err := m.Leaves(ctx); err == nil {
		for _, l := range s.network().VerifyLeaves(list, now) {
			resp.Leaves = append(resp.Leaves, leaveView{DeviceID: l.DeviceID, Name: l.Name, RequestedAt: l.CreatedAt})
		}
	} else {
		resp.LiveError = "Koordinatöre ulaşılamadı; tünelin açık olduğundan emin olun."
	}
	if alerts, err := m.CloneAlerts(ctx); err == nil {
		for _, a := range alerts {
			// Only devices of the owner's own document are shown.
			if d, ok := doc.DeviceByName(a.Name); ok && d.ID == a.DeviceID {
				resp.Alerts = append(resp.Alerts, alertView{Name: a.Name, Flips: a.Flips, Endpoints: a.Endpoints, First: a.First, Last: a.Last})
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type removeDevicesRequest struct {
	Passphrase string   `json:"passphrase"`
	Names      []string `json:"names"`
}

func (s *Server) handleRemoveDevices(w http.ResponseWriter, r *http.Request) {
	var req removeDevicesRequest
	if !decodeBody(w, r, &req) {
		return
	}
	names, ok := cleanList(req.Names, maxRemoveAtOnce, 63)
	if !ok || len(names) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("1 ile %d arasında cihaz seçin.", maxRemoveAtOnce))
		return
	}
	s.signWith(w, req.Passphrase, func(p []byte) (*admin.Plan, error) { return s.network().RemoveDevices(p, names, s.now()) })
}

type applyLeaveRequest struct {
	Passphrase string `json:"passphrase"`
	DeviceID   string `json:"deviceId"`
}

// handleApplyLeave re-fetches the leave requests, so the signed removal is
// exactly the request that verifies now.
func (s *Server) handleApplyLeave(w http.ResponseWriter, r *http.Request) {
	var req applyLeaveRequest
	if !decodeBody(w, r, &req) {
		return
	}
	m, ok := s.membershipApp()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, errNoLive.Error())
		return
	}
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), membershipTimeout)
	defer cancel()
	list, err := m.Leaves(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Koordinatöre ulaşılamadı; tünelin açık olduğundan emin olun.")
		return
	}
	var match *admin.PendingLeave
	verified := s.network().VerifyLeaves(list, s.now())
	for i := range verified {
		if verified[i].DeviceID == req.DeviceID {
			match = &verified[i]
		}
	}
	if match == nil {
		writeError(w, http.StatusConflict, "Ayrılma isteği artık yok; listeyi yenileyin.")
		return
	}
	s.signWith(w, req.Passphrase, func(p []byte) (*admin.Plan, error) { return s.network().ApplyLeave(p, match.Signed, s.now()) })
}

type minVersionRequest struct {
	Passphrase string `json:"passphrase"`
	Version    string `json:"version"`
}

func (s *Server) handleMinVersion(w http.ResponseWriter, r *http.Request) {
	var req minVersionRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Version) > maxMinVersionLen {
		writeError(w, http.StatusBadRequest, admin.Describe(trust.ErrInvalidClientVersion))
		return
	}
	v := strings.TrimSpace(req.Version)
	s.signWith(w, req.Passphrase, func(p []byte) (*admin.Plan, error) { return s.network().SetMinClientVersion(p, v, s.now()) })
}

type ephemeralRequest struct {
	Passphrase string `json:"passphrase"`
	Name       string `json:"name"`
	Ephemeral  bool   `json:"ephemeral"`
}

func (s *Server) handleEphemeral(w http.ResponseWriter, r *http.Request) {
	var req ephemeralRequest
	if !decodeBody(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	s.signWith(w, req.Passphrase, func(p []byte) (*admin.Plan, error) {
		return s.network().SetDeviceEphemeral(p, name, req.Ephemeral, s.now())
	})
}

type preauthRequest struct {
	Passphrase string   `json:"passphrase"`
	Name       string   `json:"name"`
	Tags       []string `json:"tags"`
	Hours      int      `json:"hours"`
	Ephemeral  bool     `json:"ephemeral"`
	ExitNode   bool     `json:"exitNode"`
}

type preauthResponse struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	IPv4      string    `json:"ipv4"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Server) handlePreauth(w http.ResponseWriter, r *http.Request) {
	var req preauthRequest
	if !decodeBody(w, r, &req) {
		return
	}
	limit := maxPreauthHours
	if req.Ephemeral {
		limit = int(trust.MaxEphemeralLife / time.Hour)
	}
	if req.Hours < 0 || req.Hours > limit {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Üyelik süresi 1 ile %d saat arasında olmalı.", limit))
		return
	}
	tags, ok := cleanList(req.Tags, maxTagsPerDevice, maxReferenceLen)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("En fazla %d etiket verilebilir.", maxTagsPerDevice))
		return
	}
	if !s.checkLock(w) {
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	key, dev, err := s.network().CreatePreauthKey(passphrase, trust.PreauthOptions{
		Name: strings.TrimSpace(req.Name), Tags: tags, Lifetime: time.Duration(req.Hours) * time.Hour, Ephemeral: req.Ephemeral, ExitNode: req.ExitNode,
	}, s.now())
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("preauthorized device created", "device", dev.Name)
	writeJSON(w, http.StatusOK, preauthResponse{Key: key, Name: dev.Name, IPv4: dev.IPv4.String(), ExpiresAt: dev.ExpiresAt})
}

type rejectPendingRequest struct {
	InviteID string `json:"inviteId"`
	DeviceID string `json:"deviceId"`
}

// handleRejectPending records the rejection locally (what counts) and asks
// the coordinator to drop the request (best effort).
func (s *Server) handleRejectPending(w http.ResponseWriter, r *http.Request) {
	var req rejectPendingRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.network().RejectPending(req.InviteID, req.DeviceID, s.now()); err != nil {
		s.fail(w, err)
		return
	}
	resp := map[string]any{"ok": true, "coordinator": false}
	if m, ok := s.membershipApp(); ok {
		ctx, cancel := context.WithTimeout(r.Context(), membershipTimeout)
		defer cancel()
		resp["coordinator"] = m.RejectPending(ctx, req.InviteID, req.DeviceID) == nil
	}
	s.logger.Info("pending enrollment rejected")
	writeJSON(w, http.StatusOK, resp)
}

type inviteNoteRequest struct {
	InviteID string `json:"inviteId"`
	Note     string `json:"note"`
}

func (s *Server) handleInviteNote(w http.ResponseWriter, r *http.Request) {
	var req inviteNoteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.network().SetInviteNote(req.InviteID, req.Note); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAppLeave(w http.ResponseWriter, r *http.Request) {
	m, ok := s.membershipApp()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "Bu sürüm ağdan ayrılmayı desteklemiyor.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), membershipTimeout)
	defer cancel()
	line, err := m.LeaveNetwork(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, admin.Describe(err))
		return
	}
	s.logger.Info("left the network on request")
	writeJSON(w, http.StatusOK, map[string]string{"request": line})
}

// signWith runs a passphrase-signed change with the panel's usual lock,
// reload and error handling and answers with the new version.
func (s *Server) signWith(w http.ResponseWriter, pass string, sign func([]byte) (*admin.Plan, error)) {
	if !s.checkLock(w) {
		return
	}
	passphrase := []byte(pass)
	defer wipe(passphrase)
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	plan, err := sign(passphrase)
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("network document signed", "version", plan.Next.Version)
	writeJSON(w, http.StatusOK, map[string]any{"version": plan.Next.Version, "changes": plan.Diff.Lines()})
}
