package panel

import (
	"net/http"
	"net/netip"
	"strings"
)

// Connection wave 2 endpoints (ADR-0110): remote desktop service, folder
// sync and backup, traffic shaping, key hardening and threat detection.
func (s *Server) wave2Routes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	mux.HandleFunc("GET /api/app/rdesk", read(s.handleRDeskStatus))
	mux.HandleFunc("POST /api/app/rdesk/settings", write(s.handleRDeskSettings))
	// The desktop helper the service starts in the user's session (its
	// own token and process check, never a session).
	mux.HandleFunc("POST /api/app/rdesk-helper/authorize", s.handleRDeskHelperAuthorize)
	mux.HandleFunc("GET /api/app/rdesk-helper/state", s.handleRDeskHelperState)
	mux.HandleFunc("POST /api/app/rdesk-helper/event", s.handleRDeskHelperEvent)
	mux.HandleFunc("POST /api/app/rdesk-helper/power", s.handleRDeskHelperPower)
	s.syncRoutes(mux, read, write)
	s.trafficRoutes(mux, read, write)
	s.keyRoutes(mux)
	s.guardRoutes(mux, read, write)
}

func (s *Server) rdeskControl(w http.ResponseWriter) (RemoteDesktopControl, bool) {
	c, ok := s.app.(RemoteDesktopControl)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem yalnızca masaüstü uygulamasında var.")
	}
	return c, ok
}

func (s *Server) handleRDeskStatus(w http.ResponseWriter, _ *http.Request) {
	c, ok := s.rdeskControl(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, c.RDeskStatus())
}

func (s *Server) handleRDeskSettings(w http.ResponseWriter, r *http.Request) {
	c, ok := s.rdeskControl(w)
	if !ok {
		return
	}
	var req RDeskSettingsChange
	if !decodeBody(w, r, &req) {
		return
	}
	if err := c.SetRDeskSettings(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.RDeskStatus())
}

// rdeskHelper checks the helper's own token and process (ADR-0050): the
// service gave the token only to the process it started and also checks
// that the connection comes from that process.
func (s *Server) rdeskHelper(w http.ResponseWriter, r *http.Request) (RemoteDesktopHelperAPI, bool) {
	h, ok := s.app.(RemoteDesktopHelperAPI)
	if !ok || r.Header.Get("Origin") != "" {
		writeError(w, http.StatusForbidden, "İzin verilmedi.")
		return nil, false
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	local := ""
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(interface{ String() string }); ok && a != nil {
		local = a.String()
	}
	if !ok || token == "" || len(token) > 128 || local == "" || !h.RDeskHelperAllowed(token, r.RemoteAddr, local) {
		s.logger.Warn("remote desktop helper request refused")
		writeError(w, http.StatusUnauthorized, "İzin verilmedi.")
		return nil, false
	}
	return h, true
}

type rdeskAuthorizeRequest struct {
	Remote string `json:"remote"`
	Mode   string `json:"mode"`
}

func (s *Server) handleRDeskHelperAuthorize(w http.ResponseWriter, r *http.Request) {
	h, ok := s.rdeskHelper(w, r)
	if !ok {
		return
	}
	var req rdeskAuthorizeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	addr, err := netip.ParseAddr(req.Remote)
	if err != nil || (req.Mode != "view" && req.Mode != "control") {
		writeJSON(w, http.StatusOK, RDeskHelperDecision{Reason: "geçersiz istek"})
		return
	}
	writeJSON(w, http.StatusOK, h.RDeskHelperAuthorize(addr, req.Mode))
}

func (s *Server) handleRDeskHelperState(w http.ResponseWriter, r *http.Request) {
	h, ok := s.rdeskHelper(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.RDeskHelperState())
}

func (s *Server) handleRDeskHelperEvent(w http.ResponseWriter, r *http.Request) {
	h, ok := s.rdeskHelper(w, r)
	if !ok {
		return
	}
	var ev RDeskHelperEvent
	if !decodeBody(w, r, &ev) {
		return
	}
	if len(ev.Peer) > 64 || len(ev.Code) > 16 || len(ev.Reason) > 256 {
		writeError(w, http.StatusBadRequest, "Geçersiz olay.")
		return
	}
	h.RDeskHelperEvent(ev)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRDeskHelperPower(w http.ResponseWriter, r *http.Request) {
	h, ok := s.rdeskHelper(w, r)
	if !ok {
		return
	}
	var req RDeskHelperPower
	if !decodeBody(w, r, &req) {
		return
	}
	if err := h.RDeskHelperPower(req); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
