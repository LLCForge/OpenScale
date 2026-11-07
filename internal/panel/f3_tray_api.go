package panel

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/p2psend"
)

// Tray requests for end-to-end files (#803, #813, ADR-0204), with the app
// token like the other /api/app/tray endpoints (administrators running
// this OpenScale program only):
//
//	GET  /api/app/tray/e2e          pending offers and recent transfers
//	POST /api/app/tray/e2e/decide   accept or reject an offer
//	POST /api/app/tray/e2e/stage    store a file chosen with "Send with
//	                                OpenScale" (raw body, name header)
//	POST /api/app/tray/e2e/send     send a staged file to a device
//
// The tray reads the chosen files with the rights of the person who chose
// them and streams them to the service's private staging folder; only
// paths staged this way can be sent from the tray, so the tray route
// cannot be used to send an arbitrary file the service can read.

const (
	trayStagedLife = time.Hour
	maxTrayStaged  = 64
)

// TrayE2EView is GET /api/app/tray/e2e.
type TrayE2EView struct {
	Schema    int                    `json:"schema"`
	Pending   []p2psend.Offer        `json:"pending"`
	Transfers []p2psend.TransferView `json:"transfers"`
}

// TrayE2ESend is POST /api/app/tray/e2e/send.
type TrayE2ESend struct {
	Device string `json:"device"`
	Path   string `json:"path"`
}

func (s *Server) f3TrayRoutes(mux *http.ServeMux) {
	tray := func(h func(http.ResponseWriter, *http.Request, E2EFileControl)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.trayAuthorized(w, r) {
				return
			}
			c, ok := s.app.(E2EFileControl)
			if !ok {
				writeError(w, http.StatusNotFound, "Uçtan uca dosya aktarımı bu sürümde yok.")
				return
			}
			h(w, r, c)
		}
	}
	mux.HandleFunc("GET /api/app/tray/e2e", tray(func(w http.ResponseWriter, _ *http.Request, c E2EFileControl) {
		writeJSON(w, http.StatusOK, TrayE2EView{Schema: 1, Pending: c.E2EPending(), Transfers: c.E2ETransfers()})
	}))
	mux.HandleFunc("POST /api/app/tray/e2e/decide", tray(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req E2EDecision
		if !decodeSmall(w, r, &req) {
			return
		}
		if err := c.E2EDecide(req.ID, req.Accept); err != nil {
			writeError(w, http.StatusNotFound, "Bu dosya teklifi artık beklemiyor.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/app/tray/e2e/stage", tray(func(w http.ResponseWriter, r *http.Request, _ E2EFileControl) {
		s.handleTrayStage(w, r)
	}))
	mux.HandleFunc("POST /api/app/tray/e2e/send", tray(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req TrayE2ESend
		if !decodeSmall(w, r, &req) {
			return
		}
		if !s.takeStaged(req.Path) {
			writeError(w, http.StatusForbidden, "Bu dosya tepsi üzerinden hazırlanmadı.")
			return
		}
		if err := c.E2EStart(p2psend.SendRequest{Device: req.Device, Path: req.Path}); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Info("e2e send started from Explorer's Send to menu", "device", req.Device)
		writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
	}))
}

func (s *Server) handleTrayStage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.app.(E2EStager)
	if !ok {
		writeError(w, http.StatusNotFound, "Dosya hazırlama bu sürümde yok.")
		return
	}
	raw := r.Header.Get(E2EFileNameHeader)
	name, err := url.PathUnescape(raw)
	if raw == "" || len(raw) > 1024 || err != nil || strings.TrimSpace(name) == "" {
		writeError(w, http.StatusBadRequest, "Dosya adı eksik veya geçersiz.")
		return
	}
	if r.ContentLength > MaxE2EUpload {
		writeError(w, http.StatusRequestEntityTooLarge, "Dosya çok büyük (en çok 2 GiB).")
		return
	}
	extendDeadlines(w)
	path, err := st.E2EStage(name, http.MaxBytesReader(w, r.Body, MaxE2EUpload))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, "Dosya çok büyük (en çok 2 GiB).")
		return
	case errors.Is(err, ErrE2EStageName):
		writeError(w, http.StatusBadRequest, "Bu dosya adı kullanılamıyor; dosyayı yeniden adlandırıp tekrar deneyin.")
		return
	case err != nil:
		s.logger.Warn("tray e2e staging failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "Dosya hazırlanamadı; diskte yer olduğundan emin olun ve tekrar deneyin.")
		return
	}
	s.rememberStaged(path)
	writeJSON(w, http.StatusOK, E2EStaged{Schema: 1, Path: path, Name: name})
}

func (s *Server) rememberStaged(path string) {
	st := s.f3()
	now := s.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	for p, at := range st.staged {
		if now.Sub(at) > trayStagedLife {
			delete(st.staged, p)
		}
	}
	if len(st.staged) >= maxTrayStaged {
		var oldest string
		var at time.Time
		for p, t := range st.staged {
			if oldest == "" || t.Before(at) {
				oldest, at = p, t
			}
		}
		delete(st.staged, oldest)
	}
	st.staged[path] = now
}

// takeStaged reports whether path was staged by the tray recently and
// forgets it (one send per staged file).
func (s *Server) takeStaged(path string) bool {
	st := s.f3()
	st.mu.Lock()
	defer st.mu.Unlock()
	at, ok := st.staged[path]
	delete(st.staged, path)
	return ok && path != "" && s.now().Sub(at) <= trayStagedLife
}
