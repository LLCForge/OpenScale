package panel

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Drag and drop for end-to-end sending (ADR-0204). Neither a browser nor
// the desktop window (WebView2) tells the page where a dropped file lives,
// so the panel uploads the file's bytes once over loopback; the desktop
// service keeps them in a private staging folder and answers with the
// full path, which the page then hands to POST /api/app/e2e/send as
// before. Metadata removal (#658) still happens when the file is sent.

// MaxE2EUpload bounds one staged file.
const MaxE2EUpload int64 = 2 << 30

// E2EFileNameHeader carries the dropped file's name, percent-encoded.
const E2EFileNameHeader = "X-OpenScale-File-Name"

// E2EStager is implemented by the desktop app.
type E2EStager interface {
	// E2EStage stores body under name and returns the staged file's full
	// path. It must refuse unsafe names and remove stale staged files.
	E2EStage(name string, body io.Reader) (string, error)
}

// E2EStaged is the answer to POST /api/app/e2e/upload.
type E2EStaged struct {
	Schema int    `json:"schema"`
	Path   string `json:"path"`
	Name   string `json:"name"`
}

// ErrE2EStageName is returned by stagers for names that cannot be used.
var ErrE2EStageName = errors.New("dosya adı kullanılamıyor")

func (s *Server) w5Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/app/e2e/upload", s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(s.handleE2EUpload)))))
}

func (s *Server) handleE2EUpload(w http.ResponseWriter, r *http.Request) {
	st, ok := s.app.(E2EStager)
	if !ok {
		writeError(w, http.StatusNotFound, "Sürükle-bırak ile gönderme bu sürümde yok; dosyanın tam yolunu yazın.")
		return
	}
	raw := r.Header.Get(E2EFileNameHeader)
	name, err := url.PathUnescape(raw)
	if raw == "" || len(raw) > 1024 || err != nil || strings.TrimSpace(name) == "" {
		writeError(w, http.StatusBadRequest, "Dosya adı eksik veya geçersiz.")
		return
	}
	if r.ContentLength > MaxE2EUpload {
		writeError(w, http.StatusRequestEntityTooLarge, "Dosya bırakarak gönderilemeyecek kadar büyük (en çok 2 GiB); tam yolunu yazın.")
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxE2EUpload)
	path, err := st.E2EStage(name, body)
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, "Dosya bırakarak gönderilemeyecek kadar büyük (en çok 2 GiB); tam yolunu yazın.")
		return
	case errors.Is(err, ErrE2EStageName):
		writeError(w, http.StatusBadRequest, "Bu dosya adı kullanılamıyor; dosyayı yeniden adlandırıp tekrar bırakın.")
		return
	case err != nil:
		s.logger.Warn("e2e upload failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "Dosya hazırlanamadı; diskte yer olduğundan emin olun ve tekrar deneyin.")
		return
	}
	writeJSON(w, http.StatusOK, E2EStaged{Schema: 1, Path: path, Name: name})
}
