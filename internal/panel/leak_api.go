package panel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/leaktest"
)

// Leak test (#77) and captive portal exception (#85) of the desktop
// application (ADR-0023). The desktop service implements LeakApp; an App
// without it answers 404, so other App implementations need no change.

// CaptiveGrant is an open captive portal exception.
type CaptiveGrant struct {
	Addrs []string  `json:"addrs"`
	Until time.Time `json:"until"`
}

// LeakApp is the optional part of App behind the leak routes.
type LeakApp interface {
	ExitLeakTest(ctx context.Context) (leaktest.Report, error)
	AllowCaptivePortal(d time.Duration) (CaptiveGrant, error)
	RevokeCaptivePortal() error
}

// Captive portal exception bounds in minutes (osnet.CaptiveMaxDuration).
const (
	captiveMinMinutes = 1
	captiveMaxMinutes = 15
)

func (s *Server) leakApp(w http.ResponseWriter) (LeakApp, bool) {
	a, ok := s.app.(LeakApp)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem bu sürümde yok.")
	}
	return a, ok
}

// handleAppLeakTest runs the exit node leak test. It changes nothing but
// sends probes, so it is a POST behind the CSRF check.
func (s *Server) handleAppLeakTest(w http.ResponseWriter, r *http.Request) {
	a, ok := s.leakApp(w)
	if !ok {
		return
	}
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	rep, err := a.ExitLeakTest(r.Context())
	if err != nil {
		if errors.Is(err, leaktest.ErrNoExitNode) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.logger.Warn("leak test", "error", err.Error())
		writeError(w, http.StatusConflict, "Sızıntı testi yapılamadı: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

type captiveRequest struct {
	Minutes *int `json:"minutes"`
	Off     bool `json:"off"`
}

// handleAppCaptive opens or closes the captive portal exception. The
// owner asks for it explicitly; it is short and closes by itself.
func (s *Server) handleAppCaptive(w http.ResponseWriter, r *http.Request) {
	a, ok := s.leakApp(w)
	if !ok {
		return
	}
	var req captiveRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Off {
		if err := a.RevokeCaptivePortal(); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, CaptiveGrant{Addrs: []string{}})
		return
	}
	if req.Minutes == nil || *req.Minutes < captiveMinMinutes || *req.Minutes > captiveMaxMinutes {
		writeError(w, http.StatusBadRequest, "Süre 1 ile 15 dakika arasında olmalı.")
		return
	}
	g, err := a.AllowCaptivePortal(time.Duration(*req.Minutes) * time.Minute)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("captive portal exception", "minutes", *req.Minutes)
	writeJSON(w, http.StatusOK, g)
}
