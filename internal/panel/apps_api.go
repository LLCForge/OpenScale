package panel

import (
	"context"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"
)

// Remote access and diagnostics endpoints (ADR-0030, ADR-0031). They act
// from this computer: what it may do is decided by the signed rules on the
// receiving device, so the panel needs no root key here. Every endpoint
// that changes or does something is a POST with session, CSRF and the
// read-only check (F-180); reading is a GET with a session. The command
// line uses the app-token variants under /api/app/cli/ (administrators
// only, like the tray).

const (
	wakeTimeout       = 20 * time.Second
	speedtestTimeout  = 40 * time.Second
	uploadReadTimeout = 2 * time.Hour
	maxDeviceParam    = 63
)

func (s *Server) remoteRoutes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireApp(s.requireRemote(h)))
	}
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(s.requireRemote(h)))))
	}
	mux.HandleFunc("GET /api/app/apps", read(s.handleAppsStatus))
	mux.HandleFunc("GET /api/app/remote", read(s.handleRemoteDevice))
	mux.HandleFunc("GET /api/app/inbox", read(s.handleInbox))
	mux.HandleFunc("GET /api/app/inbox/file", read(s.handleInboxFile))
	mux.HandleFunc("POST /api/app/inbox/decide", write(s.handleInboxDecide))
	mux.HandleFunc("POST /api/app/inbox/delete", write(s.handleInboxDelete))
	mux.HandleFunc("POST /api/app/inbox/auto-accept", write(s.handleInboxAutoAccept))
	mux.HandleFunc("GET /api/app/transfers", read(s.handleTransfers))
	mux.HandleFunc("POST /api/app/files/send", write(s.handleSendFile))
	mux.HandleFunc("POST /api/app/wake", write(s.handleWake))
	mux.HandleFunc("POST /api/app/wake/mac", write(s.handleWakeMAC))
	mux.HandleFunc("POST /api/app/speedtest", write(s.handleSpeedtest))
	// Command line (app token).
	mux.HandleFunc("GET /api/app/cli/inbox", s.handleCLIInbox)
	mux.HandleFunc("POST /api/app/cli/inbox/decide", s.handleCLIDecide)
}

func (s *Server) remote() (RemoteApps, bool) {
	if s.app == nil {
		return nil, false
	}
	ra, ok := s.app.(RemoteApps)
	return ra, ok
}

func (s *Server) requireRemote(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.remote(); !ok {
			writeError(w, http.StatusNotFound, "Bu işlem yalnızca masaüstü uygulamasında var.")
			return
		}
		next(w, r)
	}
}

// validDeviceParam accepts a device name as the rules write it.
func validDeviceParam(name string) bool {
	if name == "" || len(name) > maxDeviceParam {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func (s *Server) handleAppsStatus(w http.ResponseWriter, _ *http.Request) {
	ra, _ := s.remote()
	writeJSON(w, http.StatusOK, ra.AppsStatus())
}

func (s *Server) handleRemoteDevice(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	name := r.URL.Query().Get("device")
	if !validDeviceParam(name) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	v, err := ra.RemoteDevice(name)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleInbox(w http.ResponseWriter, _ *http.Request) {
	ra, _ := s.remote()
	writeJSON(w, http.StatusOK, ra.Inbox())
}

// handleInboxFile downloads a received file. It is always an attachment
// served as opaque bytes, so the browser never renders or runs it.
func (s *Server) handleInboxFile(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	name := r.URL.Query().Get("name")
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		writeError(w, http.StatusBadRequest, "Geçersiz dosya adı.")
		return
	}
	f, info, err := ra.OpenInboxFile(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Dosya bulunamadı.")
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name}))
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	// Large files need more than the server's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(uploadReadTimeout))
	http.ServeContent(w, r, "", time.Time{}, f)
}

type decideRequest struct {
	ID     string `json:"id"`
	Accept bool   `json:"accept"`
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	var req decideRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ID == "" || len(req.ID) > 32 {
		writeError(w, http.StatusBadRequest, "Geçersiz teklif.")
		return
	}
	if err := ra.DecideOffer(req.ID, req.Accept); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.logger.Info("file offer decided", "accept", req.Accept)
	writeJSON(w, http.StatusOK, ra.Inbox())
}

func (s *Server) handleInboxDecide(w http.ResponseWriter, r *http.Request) { s.decide(w, r) }

type inboxNameRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleInboxDelete(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	var req inboxNameRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := ra.DeleteInboxFile(req.Name); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ra.Inbox())
}

type autoAcceptRequest struct {
	Device string `json:"device"`
	On     bool   `json:"on"`
}

func (s *Server) handleInboxAutoAccept(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	var req autoAcceptRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Device) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	if err := ra.SetAutoAccept(req.Device, req.On); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("file auto-accept changed", "device", req.Device, "on", req.On)
	writeJSON(w, http.StatusOK, ra.Inbox())
}

func (s *Server) handleTransfers(w http.ResponseWriter, _ *http.Request) {
	ra, _ := s.remote()
	writeJSON(w, http.StatusOK, ra.Transfers())
}

// handleSendFile takes the file as the raw request body; the device and
// file name come in the query.
func (s *Server) handleSendFile(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	q := r.URL.Query()
	device, name := q.Get("device"), q.Get("name")
	if !validDeviceParam(device) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) {
		writeError(w, http.StatusBadRequest, "Geçersiz dosya adı.")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, "Dosya application/octet-stream olarak gönderilmeli.")
		return
	}
	size := r.ContentLength
	if size <= 0 {
		writeError(w, http.StatusLengthRequired, "Dosya boyutu bildirilmeli.")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(uploadReadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(uploadReadTimeout))
	body := http.MaxBytesReader(w, r.Body, size)
	id, err := ra.SendFile(device, name, body, size)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("file send started from the panel", "device", device, "size", size)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

type deviceRequest struct {
	Device string `json:"device"`
}

func (s *Server) handleWake(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	var req deviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Device) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), wakeTimeout)
	defer cancel()
	res, err := ra.Wake(ctx, req.Device)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("wake request sent", "device", req.Device, "relay", res.Relay)
	writeJSON(w, http.StatusOK, res)
}

type wakeMACRequest struct {
	Device string `json:"device"`
	MAC    string `json:"mac"`
}

func (s *Server) handleWakeMAC(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	var req wakeMACRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Device) || len(req.MAC) > 32 {
		writeError(w, http.StatusBadRequest, "Geçersiz istek.")
		return
	}
	if err := ra.SetWakeMAC(req.Device, req.MAC); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	v, err := ra.RemoteDevice(req.Device)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type speedtestRequest struct {
	Device  string `json:"device"`
	Upload  bool   `json:"upload"`
	Seconds int    `json:"seconds"`
}

func (s *Server) handleSpeedtest(w http.ResponseWriter, r *http.Request) {
	ra, _ := s.remote()
	var req speedtestRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !validDeviceParam(req.Device) || req.Seconds < 0 || req.Seconds > 10 {
		writeError(w, http.StatusBadRequest, "Geçersiz istek; süre 1-10 saniye olmalı.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), speedtestTimeout)
	defer cancel()
	res, err := ra.SpeedTest(ctx, req.Device, req.Upload, req.Seconds)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- command line (app token) ---

func (s *Server) cliRemote(w http.ResponseWriter, r *http.Request) (RemoteApps, bool) {
	if !s.trayAuthorized(w, r) {
		return nil, false
	}
	ra, ok := s.remote()
	if !ok {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
		return nil, false
	}
	return ra, true
}

func (s *Server) handleCLIInbox(w http.ResponseWriter, r *http.Request) {
	ra, ok := s.cliRemote(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, ra.Inbox())
}

// handleCLIDecide accepts or rejects an offer from "openscale files". Like
// the tray, it stays available while the panel is read-only: only
// administrators can read the app token.
func (s *Server) handleCLIDecide(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.cliRemote(w, r); !ok {
		return
	}
	s.decide(w, r)
}
