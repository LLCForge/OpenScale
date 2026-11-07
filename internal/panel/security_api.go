package panel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/winapp"
)

const securityTimeout = 90 * time.Second

func (s *Server) handleLocalSecurity(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), securityTimeout)
	defer cancel()
	sec, err := s.app.LocalSecurity(ctx, r.URL.Query().Get("refresh") == "1")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sec)
}

type remoteAccessRequest struct {
	Service     string `json:"service"`
	OverlayOnly bool   `json:"overlayOnly"`
}

// handleSetRemoteAccess changes this computer's firewall. It needs a signed
// in session and the CSRF token like every other change.
func (s *Server) handleSetRemoteAccess(w http.ResponseWriter, r *http.Request) {
	var req remoteAccessRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Service != "rdp" && req.Service != "ssh" {
		writeError(w, http.StatusBadRequest, "Bilinmeyen servis.")
		return
	}
	if err := s.app.SetRemoteAccess(req.Service, req.OverlayOnly); err != nil {
		status := http.StatusConflict
		if errors.Is(err, winapp.ErrUnsupported) {
			status = http.StatusNotImplemented
		}
		writeError(w, status, err.Error())
		return
	}
	s.logger.Info("remote access changed from the panel", "service", req.Service, "openscale_only", req.OverlayOnly)
	ctx, cancel := context.WithTimeout(r.Context(), securityTimeout)
	defer cancel()
	sec, err := s.app.LocalSecurity(ctx, true)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sec)
}
