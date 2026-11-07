package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// Panel and usability endpoints (P16): security score (#238), network map
// (#229), connection history (#190) and document export/import (#234).
// Every one of them reads; none signs or writes anything, so they also
// work while the panel is read-only. The import check is a POST only
// because it carries a file; it still needs the session and CSRF token.

// scoreLocalTimeout bounds this computer's exposure check for the score;
// the service answers from its cache unless asked to refresh.
const scoreLocalTimeout = 5 * time.Second

// maxImportBody is a signed document (at most trust.MaxEnvelopeSize) as a
// JSON string, where escaping can double its size, plus the wrapper.
const maxImportBody = 2*trust.MaxEnvelopeSize + 4<<10

func (s *Server) p16Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerCheck := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireNetwork(h)))
	}
	mux.HandleFunc("GET /api/security/score", owner(s.handleSecurityScore))
	mux.HandleFunc("GET /api/map", owner(s.handleNetworkMap))
	mux.HandleFunc("GET /api/network/export", owner(s.handleExportDocument))
	mux.HandleFunc("POST /api/network/import/inspect", ownerCheck(s.handleInspectDocument))
	mux.HandleFunc("GET /api/app/diag/history", s.requireSession(s.requireApp(s.handleConnHistory)))
}

func (s *Server) handleSecurityScore(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	backups, err := s.network().Backups()
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now()
	in := scoreInput{Doc: doc, BackupCount: len(backups), Now: now}
	if len(backups) > 0 {
		in.LastBackup = backups[len(backups)-1].CreatedAt
	}
	l := s.liveView()
	for _, d := range doc.Devices {
		if v := l.device(doc, d, now); v.System != nil && v.System.Outdated {
			in.Outdated = append(in.Outdated, d.Name)
		}
	}
	if s.app != nil {
		if st := s.app.Status(); st.Device != nil {
			dev := *st.Device
			in.Device = &dev
		}
		ctx, cancel := context.WithTimeout(r.Context(), scoreLocalTimeout)
		defer cancel()
		if sec, err := s.app.LocalSecurity(ctx, false); err == nil {
			in.Local = &sec
		}
	}
	writeJSON(w, http.StatusOK, computeScore(in))
}

// handleExportDocument sends the signed network document as a file. It is
// the same public document every device holds: no private key, and not a
// backup of the root key.
func (s *Server) handleExportDocument(w http.ResponseWriter, _ *http.Request) {
	data, err := s.network().SignedDocument()
	if err != nil {
		s.fail(w, err)
		return
	}
	doc, err := s.network().Document()
	if err != nil {
		s.fail(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="openscale-belge-v%d.json"`, doc.Version))
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	s.logger.Info("network document exported", "version", doc.Version)
}

type importRequest struct {
	// Document is the exported file's text.
	Document string `json:"document"`
}

// Relations of an imported document to the current one.
const (
	relationSame  = "same"
	relationOlder = "older"
	relationNewer = "newer"
	relationOther = "different"
)

type importResponse struct {
	Version        uint64    `json:"version"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Expired        bool      `json:"expired"`
	DisplayName    string    `json:"displayName"`
	CurrentVersion uint64    `json:"currentVersion"`
	// Relation is same, older, newer or different (same version, other
	// content).
	Relation string   `json:"relation"`
	Devices  []string `json:"devices"`
	Revoked  []string `json:"revoked"`
	Rules    int      `json:"rules"`
	// SHA256 of the file, to compare with a copy kept elsewhere.
	SHA256 string `json:"sha256"`
	// Changes lists what changed between the two versions, oldest first
	// (admin.Diff lines).
	Changes []string `json:"changes"`
}

func (s *Server) handleInspectDocument(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if !decodeLargeBody(w, r, &req, maxImportBody) {
		return
	}
	data := []byte(strings.TrimSpace(req.Document))
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "Dosya boş. Panelden veya 'openscale network export' ile dışa aktarılmış bir belge seçin.")
		return
	}
	imported, err := s.network().InspectDocument(data)
	if err != nil {
		s.logger.Warn("imported document did not verify")
		writeError(w, http.StatusBadRequest, describeImportError(err))
		return
	}
	current, ok := s.currentDocument(w)
	if !ok {
		return
	}
	now := s.now()
	sum := sha256.Sum256(data)
	resp := importResponse{
		Version: imported.Version, IssuedAt: imported.IssuedAt, ExpiresAt: imported.ExpiresAt,
		Expired: !now.Before(imported.ExpiresAt), DisplayName: imported.DisplayName,
		CurrentVersion: current.Version, Devices: []string{}, Revoked: []string{},
		Rules: len(imported.Rules), SHA256: hex.EncodeToString(sum[:]), Changes: []string{},
	}
	for _, d := range imported.Devices {
		resp.Devices = append(resp.Devices, d.Name)
	}
	for _, rv := range imported.Revoked {
		resp.Revoked = append(resp.Revoked, rv.Name)
	}
	var diff admin.Diff
	switch {
	case imported.Version < current.Version:
		resp.Relation = relationOlder
		diff = admin.ComputeDiff(imported, current)
	case imported.Version > current.Version:
		resp.Relation = relationNewer
		diff = admin.ComputeDiff(current, imported)
	default:
		resp.Relation = relationSame
		a, errA := json.Marshal(imported)
		b, errB := json.Marshal(current)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			resp.Relation = relationOther
			diff = admin.ComputeDiff(current, imported)
		}
	}
	if resp.Relation != relationSame {
		if lines := diff.Lines(); lines != nil {
			resp.Changes = lines
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// describeImportError explains why a file was refused without echoing it.
func describeImportError(err error) string {
	switch {
	case errors.Is(err, admin.ErrForeignDocument):
		return "Belge başka bir ağa ait; içe aktarılmadı."
	case errors.Is(err, trust.ErrTooLarge):
		return "Dosya bir ağ belgesi için çok büyük."
	case errors.Is(err, trust.ErrBadSignature), errors.Is(err, trust.ErrWrongContext):
		return "Belge bu ağın kök anahtarıyla imzalanmamış veya değiştirilmiş; hiçbir şey yapılmadı."
	}
	return "Dosya okunamadı: OpenScale'in dışa aktardığı imzalı bir ağ belgesi değil."
}

// decodeLargeBody is decodeBody with a caller-chosen size limit.
func decodeLargeBody(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "İstek JSON olmalı.")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "İstek çok büyük.")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "İstek biçimi geçersiz.")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "İstek biçimi geçersiz.")
		return false
	}
	return true
}
