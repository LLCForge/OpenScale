package panel

import (
	"net/http"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/version"
	"github.com/openscale/openscale/internal/winapp"
)

// Panel-A endpoints for the G4 handover (panel-devir-G4.md): the About
// page's version and channel, the autostart state and the discreet name
// mode. None of them signs anything; the discreet setting is a local,
// unsigned file that only the service (administrator) can write, and the
// G5 gate (#678) already demands the administrator mode for every change.
//
// The risk summary of every signed change (G1, ADR-0177) is added to the
// dry run answer by riskOf, called from Server.change.

// paDiscreetDir and paUpdateStateDir are variables so tests never touch
// the machine's real ProgramData folder.
var (
	paDiscreetDir    = winapp.DataDir
	paUpdateStateDir = func() string {
		p, err := updater.DefaultPlatform()
		if err != nil {
			return ""
		}
		return p.StateDir
	}
	paAutostartState = svcmgr.AutostartState
)

// AboutInfo is GET /api/about.
type AboutInfo struct {
	Schema        int    `json:"schema"`
	Version       string `json:"version"`
	Label         string `json:"label"`
	Channel       string `json:"channel"`
	Build         string `json:"build"`
	UpdateChannel string `json:"update_channel"`
}

// AutostartInfo is GET /api/desktop/autostart. The service runs as
// SYSTEM, so the per-user entry it sees is not the signed-in user's; the
// panel shows the all-users entry and points to the CLI for the rest.
type AutostartInfo struct {
	Schema  int                     `json:"schema"`
	Entries []svcmgr.AutostartEntry `json:"entries"`
}

// DiscreetInfo is GET /api/desktop/discreet.
type DiscreetInfo struct {
	Schema    int    `json:"schema"`
	Supported bool   `json:"supported"`
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name"`
}

// DiscreetRequest is POST /api/desktop/discreet.
type DiscreetRequest struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
}

func (s *Server) paRoutes(mux *http.ServeMux) {
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.paLocal(h))))
	}
	mux.HandleFunc("GET /api/about", s.requireSession(s.handleAbout))
	mux.HandleFunc("GET /api/desktop/autostart", s.requireSession(s.paLocal(s.handleAutostartInfo)))
	mux.HandleFunc("GET /api/desktop/discreet", s.requireSession(s.handleDiscreetInfo))
	mux.HandleFunc("POST /api/desktop/discreet", write(s.handleDiscreetSave))
}

func (s *Server) handleAbout(w http.ResponseWriter, _ *http.Request) {
	ch := updater.ChannelStable
	if dir := paUpdateStateDir(); dir != "" {
		// A damaged file means stable, like the updater itself.
		if c, err := updater.ReadChannel(dir); err == nil {
			ch = c
		}
	}
	writeJSON(w, http.StatusOK, AboutInfo{Schema: 1, Version: version.Version, Label: version.Label(version.Version),
		Channel: version.Channel(), Build: version.Build, UpdateChannel: ch})
}

func (s *Server) handleAutostartInfo(w http.ResponseWriter, _ *http.Request) {
	out := AutostartInfo{Schema: 1, Entries: []svcmgr.AutostartEntry{}}
	for _, scope := range []svcmgr.Scope{svcmgr.ScopeAllUsers, svcmgr.ScopeUser} {
		e, err := paAutostartState(scope)
		if err != nil {
			continue // unsupported or unreadable: the entry is simply not listed
		}
		e.Program = "" // a path of this computer; the page does not need it
		out.Entries = append(out.Entries, e)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDiscreetInfo(w http.ResponseWriter, _ *http.Request) {
	dir := paDiscreetDir()
	out := DiscreetInfo{Schema: 1, Supported: dir != "", Name: winapp.DefaultNeutralName}
	if dir != "" {
		d, err := winapp.LoadDiscreet(dir)
		if err == nil {
			out.Enabled = d.Enabled
			out.Name = d.NeutralName()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDiscreetSave(w http.ResponseWriter, r *http.Request) {
	var req DiscreetRequest
	if !decodeBody(w, r, &req) {
		return
	}
	dir := paDiscreetDir()
	if dir == "" {
		writeError(w, http.StatusNotImplemented, "Göze çarpmayan ad kipi bu işletim sisteminde panelden değiştirilemez.")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == winapp.DefaultNeutralName {
		name = ""
	}
	if name != "" {
		if err := winapp.ValidNeutralName(name); err != nil {
			writeError(w, http.StatusBadRequest, "Ad 1-40 karakter olmalı; OpenScale, VPN, WireGuard, tünel ve mesh sözcüklerini içeremez.")
			return
		}
	}
	d := winapp.Discreet{Enabled: req.Enabled, Name: name}
	if err := winapp.SaveDiscreet(dir, d); err != nil {
		s.logger.Error("discreet setting not saved", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "Ayar kaydedilemedi.")
		return
	}
	s.logger.Info("discreet name mode changed", "enabled", d.Enabled)
	writeJSON(w, http.StatusOK, DiscreetInfo{Schema: 1, Supported: true, Enabled: d.Enabled, Name: d.NeutralName()})
}

// riskOf is the G1 risk summary (ADR-0177) of a prepared change, shown
// above the diff in every signing dialog. A document that cannot be read
// leaves the summary out rather than failing the dry run.
func (s *Server) riskOf(plan *admin.Plan) *admin.RiskReport {
	cur, err := s.network().Document()
	if err != nil || plan == nil || plan.Next == nil {
		return nil
	}
	r := admin.AssessRisk(cur, plan.Next)
	return &r
}

// paLocal refuses a request from the remote panel (ADR-0107): these
// settings belong to the computer the panel runs on.
func (s *Server) paLocal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, remote := remoteDevice(r); remote {
			writeError(w, http.StatusForbidden, "Bu ayar uzaktan değiştirilemez; bu bilgisayarın panelini kullanın.")
			return
		}
		next(w, r)
	}
}
