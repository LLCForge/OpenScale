package panel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/qr"
	"github.com/openscale/openscale/internal/trust"
)

// Key hardening in the panel (P13; ADR-0060, ADR-0062, ADR-0063): the root
// key's short authentication string, a paper backup with its QR image and
// re-encrypting root.key with stronger Argon2id parameters.

const (
	paperQRScale     = 6
	defaultKDFTarget = time.Second
	minKDFTarget     = 100 * time.Millisecond
	maxKDFTarget     = 10 * time.Second
)

func (s *Server) keyRoutes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("GET /api/network/sas", owner(s.handleRootSAS))
	mux.HandleFunc("POST /api/security/paper-backup", ownerWrite(s.handlePaperBackup))
	mux.HandleFunc("GET /api/security/kdf", owner(s.handleKDF))
	mux.HandleFunc("POST /api/security/kdf", ownerWrite(s.handleUpgradeKDF))
}

func (s *Server) handleRootSAS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"sas": s.network().RootSAS()})
}

type paperBackupResponse struct {
	// QR is a PNG data URL of the QR code; Lines are the same content for
	// typing back by hand.
	QR    string   `json:"qr"`
	Lines []string `json:"lines"`
}

func (s *Server) handlePaperBackup(w http.ResponseWriter, r *http.Request) {
	var req backupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	current, backupPass := []byte(req.Current), []byte(req.BackupPassphrase)
	defer wipe(current)
	defer wipe(backupPass)
	packed, err := s.network().CreatePaperBackup(current, backupPass, strings.TrimSpace(req.Label), s.now())
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	code, err := qr.EncodeText(trust.PaperQRText(packed), qr.Q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "QR kodu üretilemedi; satırları kullanın.")
		return
	}
	var png bytes.Buffer
	if err := code.PNG(&png, paperQRScale); err != nil {
		writeError(w, http.StatusInternalServerError, "QR görüntüsü üretilemedi.")
		return
	}
	s.logger.Info("paper backup created from the panel")
	// The backup is passphrase protected; it is still not cached.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, paperBackupResponse{
		QR:    "data:image/png;base64," + base64.StdEncoding.EncodeToString(png.Bytes()),
		Lines: trust.PaperLines(packed),
	})
}

type kdfView struct {
	Time      uint32 `json:"time"`
	MemoryMiB uint32 `json:"memoryMiB"`
	Threads   uint8  `json:"threads"`
}

func viewKDF(p trust.Argon2Params) kdfView {
	return kdfView{Time: p.Time, MemoryMiB: p.MemoryKiB / 1024, Threads: p.Threads}
}

func (s *Server) handleKDF(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"current": viewKDF(s.network().KDFParams())})
}

type kdfRequest struct {
	Passphrase string `json:"passphrase"`
	TargetMs   int    `json:"targetMs"`
}

func (s *Server) handleUpgradeKDF(w http.ResponseWriter, r *http.Request) {
	var req kdfRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	target := defaultKDFTarget
	if req.TargetMs != 0 {
		target = time.Duration(req.TargetMs) * time.Millisecond
	}
	if target < minKDFTarget || target > maxKDFTarget {
		writeError(w, http.StatusBadRequest, "Hedef süre 100 ms ile 10 sn arasında olmalı.")
		return
	}
	pass := []byte(req.Passphrase)
	defer wipe(pass)
	before := s.network().KDFParams()
	after, err := s.network().UpgradeKDF(pass, trust.CalibrateArgon2(target))
	if errors.Is(err, admin.ErrKDFCurrent) {
		writeJSON(w, http.StatusOK, map[string]any{"changed": false, "before": viewKDF(before), "current": viewKDF(after)})
		return
	}
	if err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("root key re-encrypted with stronger KDF parameters")
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "before": viewKDF(before), "current": viewKDF(after)})
}
