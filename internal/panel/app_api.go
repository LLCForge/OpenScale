package panel

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

const (
	pendingTimeout     = 10 * time.Second
	createTimeout      = 2 * time.Minute
	maxInviteLifeHours = int(trust.MaxInviteLife / time.Hour)
)

type appInfoResponse struct {
	App        bool   `json:"app"`
	HasNetwork bool   `json:"hasNetwork"`
	Version    string `json:"version"`
}

// handleAppInfo tells the sign-in page whether a passphrase sign-in is
// possible here. It reveals nothing else.
func (s *Server) handleAppInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, appInfoResponse{App: s.app != nil, HasNetwork: s.network() != nil, Version: version.String()})
}

// trayAuthorized checks the app token (readable only by administrators on
// this computer). Browsers cannot pass it: it needs the token in a header,
// and requests carrying an Origin are refused.
func (s *Server) trayAuthorized(w http.ResponseWriter, r *http.Request) bool {
	if s.token == "" || r.Header.Get("Origin") != "" {
		writeError(w, http.StatusForbidden, "İzin verilmedi.")
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		s.logger.Warn("panel request with a wrong app token")
		writeError(w, http.StatusUnauthorized, "İzin verilmedi.")
		return false
	}
	if !callerAllowed(s.peerCheck, r, s.logger) {
		writeError(w, http.StatusForbidden, "İzin verilmedi: bu işlem yönetici olarak çalışan bir programdan yapılmalı.")
		return false
	}
	return true
}

// handleTicket exchanges the app token for a one-time sign-in ticket.
func (s *Server) handleTicket(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	t, err := s.auth.issueTicket()
	if err != nil {
		writeError(w, http.StatusTooManyRequests, "Çok fazla açılış isteği; biraz sonra tekrar dene.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ticket": t})
}

// handleTrayStatus gives the tray icon its status line.
func (s *Server) handleTrayStatus(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

// handleTicketSignIn turns a ticket into a session cookie and goes to the
// panel. The ticket is single use, lives 30 seconds and is accepted only
// from this computer; the redirect drops it from the address (and from
// the window's history). The session is bound to the window (#646).
func (s *Server) handleTicketSignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	t := r.URL.Query().Get("t")
	if !loopbackRemote(r) || t == "" || len(t) > 64 || !s.auth.redeemTicket(t) {
		http.Redirect(w, r, "/login/", http.StatusSeeOther)
		return
	}
	if !s.startTicketSession(w, r) { // desk_session.go
		return
	}
	s.logger.Info("panel sign-in from the tray")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) requireApp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.app == nil {
			writeError(w, http.StatusNotFound, "Bu işlem yalnızca masaüstü uygulamasında var.")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAppStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Status())
}

type appCreateRequest struct {
	Passphrase   string `json:"passphrase"`
	DeviceName   string `json:"deviceName"`
	EndpointHost string `json:"endpointHost"`
	// AllowAll adds the "every device to every device" rule. Absent or
	// false starts with no rules (F-087, #286).
	AllowAll bool `json:"allowAll"`
}

func (s *Server) handleAppCreate(w http.ResponseWriter, r *http.Request) {
	var req appCreateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if s.network() != nil {
		writeError(w, http.StatusConflict, "Bu bilgisayarda zaten bir ağ var.")
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	ctx, cancel := context.WithTimeout(r.Context(), createTimeout)
	defer cancel()
	n, err := s.app.CreateNetwork(ctx, CreateNetworkInput{
		Passphrase:   passphrase,
		DeviceName:   strings.TrimSpace(req.DeviceName),
		EndpointHost: strings.TrimSpace(req.EndpointHost),
		EmptyPolicy:  !req.AllowAll,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.SetNetwork(n)
	s.logger.Info("network created from the panel")
	writeJSON(w, http.StatusOK, s.app.Status())
}

type appJoinRequest struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func (s *Server) handleAppJoin(w http.ResponseWriter, r *http.Request) {
	var req appJoinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := s.app.JoinNetwork(req.Code, strings.TrimSpace(req.Name)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

func (s *Server) handleAppCancelJoin(w http.ResponseWriter, _ *http.Request) {
	s.app.CancelJoin()
	writeJSON(w, http.StatusOK, s.app.Status())
}

// --- invites ---

type inviteView struct {
	ID        string    `json:"id"`
	IPv4      string    `json:"ipv4"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Used      bool      `json:"used"`
	UsedBy    string    `json:"usedBy"`
	// Tags are given to the device that joins with this invite (F-133).
	Tags []string `json:"tags"`
	// Note, MaxUses and UseCount (ADR-0028, F-132, F-184); the note is
	// kept on this computer only.
	Note     string `json:"note"`
	MaxUses  int    `json:"maxUses"`
	UseCount int    `json:"useCount"`
}

type pendingView struct {
	// DeviceID tells the requests of a multi-use invite apart (ADR-0028).
	DeviceID    string    `json:"deviceId"`
	InviteID    string    `json:"inviteId"`
	Hostname    string    `json:"hostname"`
	ShortCode   string    `json:"shortCode"`
	Fingerprint string    `json:"fingerprint"`
	RequestedAt time.Time `json:"requestedAt"`
	// Tags are the invite's tags, proposed for the joining device.
	Tags []string `json:"tags"`
}

type invitesResponse struct {
	Invites []inviteView  `json:"invites"`
	Pending []pendingView `json:"pending"`
	// PendingError explains why pending requests could not be fetched
	// (e.g. the tunnel is down); invites are still listed.
	PendingError string `json:"pendingError"`
}

func (s *Server) handleInvites(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	now := s.now()
	resp := invitesResponse{Invites: []inviteView{}, Pending: []pendingView{}}
	notes := s.network().InviteNotes()
	for _, inv := range doc.Invites {
		if !inv.ActiveAt(now) {
			continue
		}
		v := inviteView{ID: inv.ID, IPv4: inv.IPv4.String(), CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt, Used: inv.Exhausted(), Tags: append([]string{}, inv.Tags...),
			Note: notes[inv.ID], MaxUses: max(inv.MaxUses, 1), UseCount: len(inv.Uses)}
		if inv.UsedBy != "" {
			v.UseCount = 1
		}
		if inv.UsedBy != "" {
			for _, d := range doc.Devices {
				if d.ID == inv.UsedBy {
					v.UsedBy = d.Name
				}
			}
		}
		resp.Invites = append(resp.Invites, v)
	}
	pending, err := s.pending(r.Context())
	if err != nil {
		resp.PendingError = err.Error()
	}
	for _, p := range pending {
		pv := pendingView{
			DeviceID:    p.Request.DeviceID,
			InviteID:    p.InviteID,
			Hostname:    p.Request.Hostname,
			ShortCode:   p.ShortCode,
			Fingerprint: p.Fingerprint,
			RequestedAt: p.Request.CreatedAt,
			Tags:        []string{},
		}
		if inv, ok := doc.InviteByID(p.InviteID); ok {
			pv.Tags = append(pv.Tags, inv.Tags...)
		}
		resp.Pending = append(resp.Pending, pv)
	}
	writeJSON(w, http.StatusOK, resp)
}

var errNoApp = errors.New("Onay bekleyen cihazlar yalnızca masaüstü uygulamasında görünür.")

// pending fetches enrollments from the coordinator through this device's
// tunnel and keeps only those that verify against the owner's document.
func (s *Server) pending(ctx context.Context) ([]admin.PendingInvite, error) {
	if s.app == nil {
		return nil, errNoApp
	}
	ctx, cancel := context.WithTimeout(ctx, pendingTimeout)
	defer cancel()
	list, err := s.app.Pending(ctx)
	if err != nil {
		return nil, errors.New("Koordinatöre ulaşılamadı; tünelin açık olduğundan emin olun.")
	}
	return s.network().VerifyPending(list, s.now()), nil
}

type createInviteRequest struct {
	Passphrase    string `json:"passphrase"`
	LifetimeHours int    `json:"lifetimeHours"`
	// Tags are given to the device that joins with the invite (F-133).
	Tags []string `json:"tags"`
	// MaxUses above 1 makes a multi-use invite; Note is a local
	// description (ADR-0028, F-184, F-132).
	MaxUses int    `json:"maxUses"`
	Note    string `json:"note"`
}

type createInviteResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req createInviteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	hours := req.LifetimeHours
	if hours == 0 {
		hours = int(trust.DefaultInviteLife / time.Hour)
	}
	if hours < 1 || hours > maxInviteLifeHours {
		writeError(w, http.StatusBadRequest, "Davet süresi 1 saat ile 7 gün arasında olmalı.")
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
	if req.MaxUses < 0 || req.MaxUses > trust.MaxInviteUses {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Bir davetle en fazla %d cihaz katılabilir.", trust.MaxInviteUses))
		return
	}
	created, err := s.network().CreateInviteWith(passphrase, s.now(), admin.InviteRequest{Life: time.Duration(hours) * time.Hour, Tags: tags, MaxUses: req.MaxUses, Note: req.Note})
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("invite created")
	writeJSON(w, http.StatusOK, createInviteResponse{Code: created.Code, ExpiresAt: created.Invite.ExpiresAt})
}

type approveInviteRequest struct {
	Passphrase string `json:"passphrase"`
	InviteID   string `json:"inviteId"`
	ShortCode  string `json:"shortCode"`
	Name       string `json:"name"`
	ExitNode   bool   `json:"exitNode"`
	// Tags, when present, replace the tags the invite proposes (an empty
	// list removes them). Absent keeps the invite's tags (F-133).
	Tags *[]string `json:"tags"`
	// DeviceID picks one request of a multi-use invite; Ephemeral and
	// LifetimeHours add a temporary device (ADR-0028).
	DeviceID      string `json:"deviceId"`
	Ephemeral     bool   `json:"ephemeral"`
	LifetimeHours int    `json:"lifetimeHours"`
}

// handleApproveInvite re-fetches the pending enrollment, so the approved
// keys are exactly the ones whose short code the owner compared.
func (s *Server) handleApproveInvite(w http.ResponseWriter, r *http.Request) {
	var req approveInviteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var opts admin.ApproveOptions
	if req.Tags != nil {
		tags, ok := cleanList(*req.Tags, maxTagsPerDevice, maxReferenceLen)
		if !ok {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("En fazla %d etiket verilebilir.", maxTagsPerDevice))
			return
		}
		opts = admin.ApproveOptions{OverrideTags: true, Tags: tags}
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
	pending, err := s.pending(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	var match *admin.PendingInvite
	for i := range pending {
		if pending[i].InviteID == req.InviteID && (req.DeviceID == "" || pending[i].Request.DeviceID == req.DeviceID) {
			match = &pending[i]
		}
	}
	if req.LifetimeHours < 0 || (req.Ephemeral && req.LifetimeHours > int(trust.MaxEphemeralLife.Hours())) {
		writeError(w, http.StatusBadRequest, "Geçici bir cihazın üyeliği en fazla 30 gün olabilir.")
		return
	}
	opts.Ephemeral, opts.Lifetime = req.Ephemeral, time.Duration(req.LifetimeHours)*time.Hour
	if match == nil || !trust.SameShortCode(match.ShortCode, req.ShortCode) {
		writeError(w, http.StatusConflict, "Bekleyen istek değişti; listeyi yenileyip kodu yeniden karşılaştırın.")
		return
	}
	var roles []trust.Role
	if req.ExitNode {
		roles = append(roles, trust.RoleExitNode)
	}
	dev, err := s.network().ApproveInviteWith(passphrase, match.Signed, strings.TrimSpace(req.Name), roles, opts, s.now())
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("invite approved", "device", dev.Name)
	writeJSON(w, http.StatusOK, map[string]string{"name": dev.Name, "ipv4": dev.IPv4.String()})
}

type revokeInviteRequest struct {
	Passphrase string `json:"passphrase"`
	InviteID   string `json:"inviteId"`
}

func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	var req revokeInviteRequest
	if !decodeBody(w, r, &req) {
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
	if err := s.network().RevokeInvite(passphrase, req.InviteID, s.now()); err != nil {
		s.failPassphrase(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) checkLock(w http.ResponseWriter) bool {
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return false
	}
	return true
}

func (s *Server) handleAppReset(w http.ResponseWriter, _ *http.Request) {
	if err := s.app.ResetDevice(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("device reset from the panel")
	writeJSON(w, http.StatusOK, s.app.Status())
}

type exitRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleAppExit(w http.ResponseWriter, r *http.Request) {
	s.setExit(w, r)
}

func (s *Server) handleTrayExit(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	s.setExit(w, r)
}

func (s *Server) setExit(w http.ResponseWriter, r *http.Request) {
	var req exitRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Name) > 63 {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	if err := s.app.SetExitNode(req.Name); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

// exitOptionsRequest uses pointers so a missing field is refused instead
// of silently turning the kill switch off.
type exitOptionsRequest struct {
	KillSwitch   *bool `json:"killSwitch"`
	ExitAllowLAN *bool `json:"exitAllowLan"`
}

func (s *Server) handleAppExitOptions(w http.ResponseWriter, r *http.Request) {
	s.setExitOptions(w, r)
}

func (s *Server) handleTrayExitOptions(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	s.setExitOptions(w, r)
}

func (s *Server) setExitOptions(w http.ResponseWriter, r *http.Request) {
	var req exitOptionsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.KillSwitch == nil || req.ExitAllowLAN == nil {
		writeError(w, http.StatusBadRequest, "Kill switch ve yerel ağ seçeneklerinin ikisi de gönderilmeli.")
		return
	}
	if err := s.app.SetExitOptions(*req.KillSwitch, *req.ExitAllowLAN); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("exit options changed", "kill_switch", *req.KillSwitch, "allow_lan", *req.ExitAllowLAN)
	writeJSON(w, http.StatusOK, s.app.Status())
}

type shieldsRequest struct {
	Shields *bool `json:"shields"`
}

// handleAppShields turns the shields on or off from the panel.
func (s *Server) handleAppShields(w http.ResponseWriter, r *http.Request) {
	var req shieldsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Shields == nil {
		writeError(w, http.StatusBadRequest, "Kalkan seçeneği gönderilmeli.")
		return
	}
	if err := s.app.SetShields(*req.Shields); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("shields changed from the panel", "on", *req.Shields)
	writeJSON(w, http.StatusOK, s.app.Status())
}

type networkDNSRequest struct {
	// Accept applies the network's DNS settings on this computer; false
	// ignores them (F-065).
	Accept *bool `json:"accept"`
}

// handleAppNetworkDNS lets this computer ignore the network's DNS
// settings (F-065). MagicDNS names keep working either way.
func (s *Server) handleAppNetworkDNS(w http.ResponseWriter, r *http.Request) {
	var req networkDNSRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Accept == nil {
		writeError(w, http.StatusBadRequest, "DNS seçeneği gönderilmeli.")
		return
	}
	if err := s.app.SetAcceptNetworkDNS(*req.Accept); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("network DNS choice changed from the panel", "accept", *req.Accept)
	writeJSON(w, http.StatusOK, s.app.Status())
}

// Bounds of the advanced settings accepted from the panel; the service
// checks the exact limits again.
const (
	maxAdvancedMTU   = 9000
	maxAdvancedRelay = 1 << 40
)

// handleAppAdvanced changes the tunnel MTU, forced relay and the local
// coordinator's relay limits. Fields left out keep their value.
func (s *Server) handleAppAdvanced(w http.ResponseWriter, r *http.Request) {
	var req AdvancedSettings
	if !decodeBody(w, r, &req) {
		return
	}
	if !req.hasChange() {
		writeError(w, http.StatusBadRequest, "Değiştirilecek bir ayar gönderilmeli.")
		return
	}
	if (req.MTU != nil && (*req.MTU < 0 || *req.MTU > maxAdvancedMTU)) ||
		(req.RelayRate != nil && (*req.RelayRate < 0 || *req.RelayRate > maxAdvancedRelay)) ||
		(req.RelayBurst != nil && (*req.RelayBurst < 0 || *req.RelayBurst > maxAdvancedRelay)) ||
		!req.transportInRange() {
		writeError(w, http.StatusBadRequest, "Ayar değeri geçersiz.")
		return
	}
	if err := s.app.SetAdvanced(req); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("advanced settings changed from the panel")
	writeJSON(w, http.StatusOK, s.app.Status())
}

type connectRequest struct {
	Connected bool `json:"connected"`
	// For turns the tunnel off for a while: Disconnect5Min,
	// Disconnect1Hour or DisconnectMorning (F-121). Empty means until the
	// owner turns it on again.
	For string `json:"for"`
}

// validDisconnect is the allowlist of timed disconnect choices.
func validDisconnect(choice string) bool {
	switch choice {
	case Disconnect5Min, Disconnect1Hour, DisconnectMorning:
		return true
	}
	return false
}

// handleTrayConnect turns the tunnel on or off from the tray icon.
func (s *Server) handleTrayConnect(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	s.setConnected(w, r)
}

// handleAppConnect turns the tunnel on or off from the panel.
func (s *Server) handleAppConnect(w http.ResponseWriter, r *http.Request) {
	s.setConnected(w, r)
}

func (s *Server) setConnected(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var err error
	switch {
	case req.For == "":
		err = s.app.SetConnected(req.Connected)
	case req.Connected || !validDisconnect(req.For):
		writeError(w, http.StatusBadRequest, "Geçersiz bağlantı kesme süresi.")
		return
	default:
		err = s.app.DisconnectFor(req.For)
	}
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

type trayDisconnectRequest struct {
	For string `json:"for"`
}

// handleTrayDisconnect turns the tunnel off for a while from the tray.
func (s *Server) handleTrayDisconnect(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	var req trayDisconnectRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDisconnect(req.For) {
		writeError(w, http.StatusBadRequest, "Geçersiz bağlantı kesme süresi.")
		return
	}
	if err := s.app.DisconnectFor(req.For); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

// handleTrayReleaseOnStop is sent by the tray right before it stops the
// service for a full exit: that stop removes the kill switch instead of
// keeping it (ADR-0023). Only the tray can ask, with the app token.
func (s *Server) handleTrayReleaseOnStop(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	s.app.ReleaseKillSwitchOnStop()
	s.logger.Info("full exit from the tray: kill switch is released on stop")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type pinRequest struct {
	Name   string `json:"name"`
	Pinned *bool  `json:"pinned"`
}

// handleAppPin pins a device to the top of the lists (F-159).
func (s *Server) handleAppPin(w http.ResponseWriter, r *http.Request) {
	var req pinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Pinned == nil || !validDeviceName(req.Name) {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	if err := s.app.SetPinned(req.Name, *req.Pinned); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

// validDeviceName accepts only names trust gives devices, so nothing else
// reaches the settings file.
func validDeviceName(name string) bool {
	return name != "" && len(name) <= 63 && trust.SanitizeHostname(name) == name
}
