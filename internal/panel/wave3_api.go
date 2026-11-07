package panel

import (
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Connection wave 3 endpoints: the sign-in page's remote flag (ADR-0107),
// the automatic exit node (ADR-0133), the coordinator list (ADR-0111), the
// approval policy (ADR-0121) and network profiles (ADR-0135).

func (s *Server) wave3Routes(mux *http.ServeMux) {
	appWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	mux.HandleFunc("GET /api/login-info", s.handleLoginInfo)
	mux.HandleFunc("GET /api/app/exit-auto", s.requireSession(s.requireApp(s.handleExitAuto)))
	mux.HandleFunc("POST /api/app/exit-auto", appWrite(s.handleSetExitAuto))
	mux.HandleFunc("POST /api/app/profile", appWrite(s.handleSwitchProfile))
	mux.HandleFunc("POST /api/app/tray/profile", s.handleTrayProfile)
	mux.HandleFunc("GET /api/network/coordinators", s.requireSession(s.requireNetwork(s.handleCoordinators)))
	mux.HandleFunc("GET /api/security/approval", s.requireSession(s.requireNetwork(s.handleApproval)))
}

// loginInfo tells the sign-in page which password to ask for. It is
// public: it reveals only whether the panel was opened from another device.
type loginInfo struct {
	Remote bool `json:"remote"`
}

func (s *Server) handleLoginInfo(w http.ResponseWriter, r *http.Request) {
	_, remote := remoteDevice(r)
	writeJSON(w, http.StatusOK, loginInfo{Remote: remote})
}

func (s *Server) wave3App(w http.ResponseWriter) (Wave3App, bool) {
	a, ok := s.app.(Wave3App)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem bu sürümde yok.")
	}
	return a, ok
}

func (s *Server) handleExitAuto(w http.ResponseWriter, _ *http.Request) {
	a, ok := s.wave3App(w)
	if !ok {
		return
	}
	st, err := a.ExitAuto()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSetExitAuto(w http.ResponseWriter, r *http.Request) {
	a, ok := s.wave3App(w)
	if !ok {
		return
	}
	var req ExitAutoSettings
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Candidates) > MaxExitCandidates || len(req.TrustedWiFi) > MaxTrustedWiFi || len(req.Except) > MaxExitExceptions {
		writeError(w, http.StatusBadRequest, "Listelerden biri çok uzun.")
		return
	}
	if err := a.SetExitAuto(req); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	st, err := a.ExitAuto()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type profileRequest struct {
	Name string `json:"name"`
}

func (s *Server) switchProfile(w http.ResponseWriter, r *http.Request) {
	a, ok := s.wave3App(w)
	if !ok {
		return
	}
	var req profileRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Name) == 0 || len(req.Name) > 32 {
		writeError(w, http.StatusBadRequest, "Ağ profili adı geçersiz.")
		return
	}
	if err := a.SwitchProfile(req.Name); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

func (s *Server) handleSwitchProfile(w http.ResponseWriter, r *http.Request) { s.switchProfile(w, r) }

// handleTrayProfile is the tray's profile switch (app token, like the
// tray's exit node choice).
func (s *Server) handleTrayProfile(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	if s.app == nil {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return
	}
	s.switchProfile(w, r)
}

// coordinatorEntry is one coordinator of the signed document.
type coordinatorEntry struct {
	Name        string     `json:"name"`
	Region      string     `json:"region"`
	Endpoint    string     `json:"endpoint"`
	Fingerprint string     `json:"fingerprint"`
	Primary     bool       `json:"primary"`
	Until       *time.Time `json:"until,omitempty"`
	Expired     bool       `json:"expired"`
}

type coordinatorsResponse struct {
	Coordinators []coordinatorEntry `json:"coordinators"`
	// Device is this computer's live view (active coordinator, relay,
	// integrity); nil without the desktop service or a running tunnel.
	Device *Wave3Status `json:"device"`
}

func (s *Server) handleCoordinators(w http.ResponseWriter, _ *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	now := s.now()
	out := coordinatorsResponse{Coordinators: []coordinatorEntry{}}
	for i, c := range doc.AllCoordinators() {
		e := coordinatorEntry{Name: c.Name, Region: c.Region, Endpoint: c.Endpoint, Fingerprint: trust.CoordinatorFingerprint(c.WireGuardKey), Primary: i == 0}
		if !c.Until.IsZero() {
			t := c.Until
			e.Until = &t
			e.Expired = c.Expired(now)
		}
		out.Coordinators = append(out.Coordinators, e)
	}
	if s.app != nil {
		if ds := s.app.Status().Device; ds != nil {
			out.Device = ds.Wave3
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// approvalResponse is the k-of-n approval policy (read only here; it is
// set with "openscale network approval set") and the local hardware key
// state reported by the service.
type approvalResponse struct {
	Threshold int             `json:"threshold"`
	Approvers []approverEntry `json:"approvers"`
	// Hardware is filled by the desktop service; nil otherwise.
	Hardware *HardwareKeys `json:"hardware"`
}

type approverEntry struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

// HardwareKeys is the read-only TPM and PIV state of this computer.
type HardwareKeys struct {
	TPM     string   `json:"tpm"`
	TPMNote string   `json:"tpmNote"`
	PIV     []string `json:"piv"`
	PIVNote string   `json:"pivNote"`
}

// HardwareApp is implemented by the desktop service.
type HardwareApp interface {
	HardwareKeys() HardwareKeys
}

func (s *Server) handleApproval(w http.ResponseWriter, _ *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	out := approvalResponse{Approvers: []approverEntry{}}
	if p := doc.Approval; p != nil {
		out.Threshold = p.Threshold
		for _, a := range p.Approvers {
			out.Approvers = append(out.Approvers, approverEntry{Name: a.Name, Fingerprint: a.Key.String()})
		}
	}
	if h, ok := s.app.(HardwareApp); ok {
		hk := h.HardwareKeys()
		out.Hardware = &hk
	}
	writeJSON(w, http.StatusOK, out)
}
