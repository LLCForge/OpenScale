package panel

import (
	"context"
	"net/http"
	"time"
	"unicode/utf8"
)

const (
	syncNowTimeout   = 10 * time.Minute
	snapshotsTimeout = 30 * time.Second
	minBackupPass    = 12
	maxBackupPass    = 1024
)

func (s *Server) syncRoutes(mux *http.ServeMux, read, write func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/app/sync", read(s.handleSyncStatus))
	mux.HandleFunc("POST /api/app/sync/folder", write(s.handleSyncFolder))
	mux.HandleFunc("POST /api/app/sync/folder/remove", write(s.handleSyncFolderRemove))
	mux.HandleFunc("POST /api/app/sync/now", write(s.handleSyncNow))
	mux.HandleFunc("GET /api/app/sync/versions", read(s.handleSyncVersions))
	mux.HandleFunc("POST /api/app/sync/versions/restore", write(s.handleSyncRestore))
	mux.HandleFunc("POST /api/app/sync/backup", write(s.handleSyncBackup))
	mux.HandleFunc("POST /api/app/sync/backup/key", write(s.handleBackupKeyExport))
	mux.HandleFunc("POST /api/app/sync/backup/now", write(s.handleBackupNow))
	mux.HandleFunc("GET /api/app/sync/backup/snapshots", read(s.handleBackupSnapshots))
	mux.HandleFunc("POST /api/app/files/queue", write(s.handleQueueFile))
	mux.HandleFunc("POST /api/app/files/queue/remove", write(s.handleOutboxRemove))
}

func (s *Server) syncControl(w http.ResponseWriter) (SyncControl, bool) {
	c, ok := s.app.(SyncControl)
	if !ok {
		writeError(w, http.StatusNotFound, "Bu işlem yalnızca masaüstü uygulamasında var.")
	}
	return c, ok
}

func (s *Server) handleSyncStatus(w http.ResponseWriter, _ *http.Request) {
	if c, ok := s.syncControl(w); ok {
		writeJSON(w, http.StatusOK, c.SyncStatus())
	}
}

func (s *Server) syncResult(w http.ResponseWriter, c SyncControl, err error) {
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c.SyncStatus())
}

func (s *Server) handleSyncFolder(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	var req SyncFolderChange
	if !decodeBody(w, r, &req) {
		return
	}
	s.syncResult(w, c, c.SetSyncFolder(req))
}

type syncIDRequest struct {
	ID string `json:"id"`
}

func (s *Server) handleSyncFolderRemove(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	var req syncIDRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.syncResult(w, c, c.RemoveSyncFolder(req.ID))
}

func (s *Server) handleSyncNow(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), syncNowTimeout)
	defer cancel()
	s.syncResult(w, c, c.SyncNow(ctx))
}

func (s *Server) handleSyncVersions(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	vs, err := c.SyncVersions(r.URL.Query().Get("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": vs})
}

type syncRestoreRequest struct {
	ID     string `json:"id"`
	Stored string `json:"stored"`
}

func (s *Server) handleSyncRestore(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	var req syncRestoreRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.syncResult(w, c, c.RestoreSyncVersion(req.ID, req.Stored))
}

func (s *Server) handleSyncBackup(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	var req SyncBackupChange
	if !decodeBody(w, r, &req) {
		return
	}
	s.syncResult(w, c, c.SetSyncBackup(req))
}

type backupKeyRequest struct {
	Passphrase string `json:"passphrase"`
}

func (s *Server) handleBackupKeyExport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	var req backupKeyRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pass := []byte(req.Passphrase)
	defer wipe(pass)
	if n := utf8.RuneCount(pass); n < minBackupPass || len(pass) > maxBackupPass {
		writeError(w, http.StatusBadRequest, "Yedek anahtarı parolası en az 12 karakter olmalı.")
		return
	}
	text, err := c.ExportBackupKey(pass)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("backup key exported from the panel")
	writeJSON(w, http.StatusOK, map[string]string{"key": text})
}

func (s *Server) handleBackupNow(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), syncNowTimeout)
	defer cancel()
	s.syncResult(w, c, c.BackupNow(ctx))
}

func (s *Server) handleBackupSnapshots(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), snapshotsTimeout)
	defer cancel()
	snaps, err := c.BackupSnapshots(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
}

func (s *Server) handleQueueFile(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	device, name, strip := q.Get("device"), q.Get("name"), q.Get("strip")
	if !validDeviceParam(device) {
		writeError(w, http.StatusBadRequest, "Geçersiz cihaz adı.")
		return
	}
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) {
		writeError(w, http.StatusBadRequest, "Geçersiz dosya adı.")
		return
	}
	if strip != "" && strip != "location" && strip != "all" {
		writeError(w, http.StatusBadRequest, "Üst veri seçeneği location veya all olmalı.")
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
	id, err := c.QueueFile(device, name, http.MaxBytesReader(w, r.Body, size), size, strip)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.logger.Info("file queued from the panel", "device", device, "size", size)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

func (s *Server) handleOutboxRemove(w http.ResponseWriter, r *http.Request) {
	c, ok := s.syncControl(w)
	if !ok {
		return
	}
	var req syncIDRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.syncResult(w, c, c.RemoveOutbox(req.ID))
}
