package panel

import (
	"context"
	"crypto/ecdh"
	"errors"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/flightrec"
	"github.com/openscale/openscale/internal/troubleshoot"
)

// Diagnostics and observability, phase 2: the flight recorder (#836), the
// layered troubleshooter (#835) and the settings that restart the
// connection (#799). The panel reaches them under /api/app/..., the
// command line under /api/local/... with the app token.

const (
	// troubleshootTimeout bounds one troubleshooter run.
	troubleshootTimeout = 60 * time.Second
	// maxExportBytes bounds one exported flight recording.
	maxExportBytes = bundlecrypt.MaxPlaintext + 1<<10
)

// FlightRecStatus is the reply of GET .../flightrec.
type FlightRecStatus struct {
	Schema int `json:"schema"`
	// Enabled is false where the recorder could not start.
	Enabled bool             `json:"enabled"`
	Stats   flightrec.Stats  `json:"stats"`
	Stored  []flightrec.Info `json:"stored"`
	// AutoFreeze: a dropout freezes the ring by itself (thinned out).
	AutoFreeze bool   `json:"auto_freeze"`
	AutoEvery  int    `json:"auto_every_s"`
	Error      string `json:"error,omitempty"`
}

// FlightRecFreezeReply is the reply of POST .../flightrec/freeze.
type FlightRecFreezeReply struct {
	Schema int            `json:"schema"`
	Saved  flightrec.Info `json:"saved"`
}

// FlightRecExportRequest seals a recording to a helper's public key. An
// empty ID freezes the ring now.
type FlightRecExportRequest struct {
	ID string `json:"id"`
	To string `json:"to"`
}

// FlightRecorderControl is implemented by the desktop service.
type FlightRecorderControl interface {
	FlightRecStatus() FlightRecStatus
	FlightRecFreeze(reason string) (flightrec.Info, error)
	FlightRecExport(id string, to *ecdh.PublicKey) ([]byte, error)
}

// TroubleshootControl is implemented by the desktop service.
type TroubleshootControl interface {
	Troubleshoot(ctx context.Context) troubleshoot.Report
}

// PrefMeta describes one setting that restarts the connection.
type PrefMeta struct {
	Key                string `json:"key"`
	Description        string `json:"description"`
	RestartsConnection bool   `json:"restarts_connection"`
}

// PrefMetaReply is the reply of GET /api/app/prefs/meta.
type PrefMetaReply struct {
	Schema int        `json:"schema"`
	Prefs  []PrefMeta `json:"prefs"`
	// RemoteSession: the person using the panel may be reaching this
	// computer through OpenScale (a remote panel or an active remote
	// desktop session), so restarting the connection may cut them off.
	RemoteSession bool `json:"remote_session"`
}

// PrefMetaSource is implemented by the desktop service.
type PrefMetaSource interface {
	PrefMeta() []PrefMeta
}

func (s *Server) p2DiagRoutes(mux *http.ServeMux) {
	session := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	// Actions that change no setting: they need CSRF but work read-only.
	act := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireCSRF(s.requireApp(h))) }
	token := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.trayAuthorized(w, r) {
				h(w, r)
			}
		}
	}
	for _, p := range []struct {
		prefix    string
		read, act func(http.HandlerFunc) http.HandlerFunc
	}{{"/api/app/diag", session, act}, {LocalAPIPrefix, token, token}} {
		mux.HandleFunc("GET "+p.prefix+"/flightrec", p.read(s.handleFlightRecStatus))
		mux.HandleFunc("POST "+p.prefix+"/flightrec/freeze", p.act(s.handleFlightRecFreeze))
		mux.HandleFunc("POST "+p.prefix+"/flightrec/export", p.act(s.handleFlightRecExport))
		mux.HandleFunc("POST "+p.prefix+"/troubleshoot", p.act(s.handleTroubleshoot))
	}
	mux.HandleFunc("GET /api/app/prefs/meta", session(s.handlePrefMeta))
}

func (s *Server) flightRec(w http.ResponseWriter) (FlightRecorderControl, bool) {
	c, ok := s.app.(FlightRecorderControl)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
	}
	return c, ok
}

func (s *Server) handleFlightRecStatus(w http.ResponseWriter, _ *http.Request) {
	if c, ok := s.flightRec(w); ok {
		writeJSON(w, http.StatusOK, c.FlightRecStatus())
	}
}

func (s *Server) handleFlightRecFreeze(w http.ResponseWriter, r *http.Request) {
	c, ok := s.flightRec(w)
	if !ok {
		return
	}
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	info, err := c.FlightRecFreeze(flightrec.ReasonManual)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, flightrec.ErrEmpty) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, FlightRecFreezeReply{Schema: DiagSchema, Saved: info})
}

func (s *Server) handleFlightRecExport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.flightRec(w)
	if !ok {
		return
	}
	var req FlightRecExportRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ID != "" && !flightrec.ValidID(req.ID) {
		writeError(w, http.StatusBadRequest, flightrec.ErrBadID.Error())
		return
	}
	if len(req.To) > 256 {
		writeError(w, http.StatusBadRequest, bundlecrypt.ErrBadKey.Error())
		return
	}
	to, err := bundlecrypt.ParsePublic(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, bundlecrypt.ErrBadKey.Error())
		return
	}
	sealed, err := c.FlightRecExport(req.ID, to)
	switch {
	case errors.Is(err, flightrec.ErrNotFound), errors.Is(err, flightrec.ErrEmpty):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusConflict, err.Error())
		return
	case len(sealed) > maxExportBytes:
		writeError(w, http.StatusConflict, bundlecrypt.ErrTooLarge.Error())
		return
	}
	name := "openscale-ucus-kaydi.osb"
	if req.ID != "" {
		name = "openscale-" + req.ID + ".osb"
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("X-Bundle-Fingerprint", bundlecrypt.Fingerprint(to))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (s *Server) handleTroubleshoot(w http.ResponseWriter, r *http.Request) {
	c, ok := s.app.(TroubleshootControl)
	if !ok {
		writeError(w, http.StatusNotFound, troubleshoot.ErrNoProbe.Error())
		return
	}
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), troubleshootTimeout)
	defer cancel()
	writeJSON(w, http.StatusOK, c.Troubleshoot(ctx))
}

func (s *Server) handlePrefMeta(w http.ResponseWriter, r *http.Request) {
	rep := PrefMetaReply{Schema: DiagSchema, Prefs: []PrefMeta{}}
	if src, ok := s.app.(PrefMetaSource); ok {
		rep.Prefs = src.PrefMeta()
	}
	_, remote := remoteDevice(r)
	if !remote {
		if rd, ok := s.app.(RemoteDesktopControl); ok {
			remote = len(rd.RDeskStatus().Sessions) > 0
		}
	}
	rep.RemoteSession = remote
	writeJSON(w, http.StatusOK, rep)
}
