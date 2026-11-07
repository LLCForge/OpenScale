package panel

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// Panel API of package P01 (ADR-0151): signature ledger (#342), change
// draft (#344), limits (#345), revocation compaction (#346), key age
// (#347), visual fingerprints (#351), emergency lock (#361) and bulk
// membership (#362). Every change goes through s.change, so dry runs,
// drafts, the passphrase lock and read-only mode apply as everywhere.

// Health codes of the P01 warnings on the overview.
const (
	HealthLimitNear     = "limit_near"
	HealthForeignSigner = "foreign_signer"
	HealthLedgerBroken  = "ledger_broken"
	HealthKeyAgeOverdue = "key_age_overdue"
	HealthLockdown      = "network_lockdown"
	HealthDraftPending  = "draft_pending"
)

func (s *Server) p01Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("GET /api/p01/ledger", owner(s.handleLedger))
	mux.HandleFunc("GET /api/p01/limits", owner(s.handleLimits))
	mux.HandleFunc("GET /api/p01/fingerprints", owner(s.handleFingerprints))
	mux.HandleFunc("GET /api/p01/key-ages", owner(s.handleKeyAges))
	mux.HandleFunc("GET /api/p01/draft", owner(s.handleDraft))
	mux.HandleFunc("POST /api/p01/draft/sign", ownerWrite(s.handleDraftSign))
	mux.HandleFunc("POST /api/p01/draft/discard", ownerWrite(s.handleDraftDiscard))
	mux.HandleFunc("POST /api/p01/devices/bulk", ownerWrite(s.handleBulkMembership))
	mux.HandleFunc("POST /api/p01/lockdown", ownerWrite(s.handleLockdown))
	mux.HandleFunc("POST /api/p01/key-age", ownerWrite(s.handleKeyAgePolicy))
	mux.HandleFunc("POST /api/p01/revoked/compact", ownerWrite(s.handleCompactRevoked))
}

// p01Warnings are added to the overview.
func (s *Server) p01Warnings(doc *trust.Document, now time.Time) []warning {
	var out []warning
	for _, u := range doc.NearLimits() {
		out = append(out, warning{Code: HealthLimitNear, Level: LevelWarning, Message: trust.LimitWarning(u)})
	}
	if l := doc.Lockdown; l != nil {
		msg := "Ağ geneli acil kilit açık: bütün kurallar askıda, yalnızca yönetici cihazlar erişebilir."
		if l.Reason != "" {
			msg += " Not: " + l.Reason
		}
		out = append(out, warning{Code: HealthLockdown, Level: LevelDanger, Message: msg})
	}
	for _, k := range doc.KeyAges(now) {
		if k.Overdue {
			out = append(out, warning{Code: HealthKeyAgeOverdue, Level: LevelWarning,
				Message: fmt.Sprintf("%s cihazının anahtarı %d günlük; politika %d gün. Cihazda anahtar yenileme iste ('openscale device rotate-key').", k.Name, k.AgeDays, doc.MaxKeyAgeDays)})
		}
	}
	n := s.network()
	if st, err := n.LedgerStatus(); err == nil {
		for _, p := range st.Problems {
			code := HealthLedgerBroken
			if st.ForeignSeen {
				code = HealthForeignSigner
			}
			out = append(out, warning{Code: code, Level: LevelDanger, Message: p})
		}
	}
	if s.app != nil {
		if st := s.app.Status(); st.Mode == ModeAdmin && st.Device != nil {
			if msg, err := n.CheckRunningVersion(st.Device.DocumentVersion); err == nil && msg != "" {
				out = append(out, warning{Code: HealthForeignSigner, Level: LevelDanger, Message: msg})
			}
		}
	}
	if d, err := n.Draft(); err == nil {
		out = append(out, warning{Code: HealthDraftPending, Level: LevelInfo, Message: fmt.Sprintf("İmzalanmamış değişiklik taslağı var (%d düzenleme).", len(d.Entries))})
	}
	return out
}

func (s *Server) handleLedger(w http.ResponseWriter, r *http.Request) {
	st, err := s.network().LedgerStatus()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleLimits(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	type usage struct {
		trust.LimitUsage
		Percent int  `json:"percent"`
		Near    bool `json:"near"`
	}
	out := []usage{}
	for _, u := range doc.LimitUsages() {
		out = append(out, usage{LimitUsage: u, Percent: u.Percent(), Near: u.Percent() >= trust.LimitWarnPercent})
	}
	writeJSON(w, http.StatusOK, map[string]any{"limits": out})
}

type fingerprintArt struct {
	Label       string   `json:"label"`
	Fingerprint string   `json:"fingerprint"`
	Art         []string `json:"art"`
}

func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	add := func(out []fingerprintArt, label, title, fp string) []fingerprintArt {
		return append(out, fingerprintArt{Label: label, Fingerprint: fp, Art: trust.RandomArt(title, fp)})
	}
	out := add(nil, "Kök anahtar", "KÖK", s.network().RootFingerprint())
	if c := doc.Coordinator; c != nil {
		out = add(out, "Koordinatör", "KOORDİNATÖR", trust.CoordinatorFingerprint(c.WireGuardKey))
	}
	for _, d := range doc.Devices {
		out = add(out, d.Name, d.Name, trust.DeviceFingerprint(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"fingerprints": out})
}

func (s *Server) handleKeyAges(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"maxKeyAgeDays": doc.MaxKeyAgeDays, "devices": doc.KeyAges(s.now())})
}

// --- draft ---

func (s *Server) stageDraft(w http.ResponseWriter, fn admin.Change) {
	lines, err := s.network().StageDraft(s.now(), fn)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"draft": true, "lines": lines})
}

func (s *Server) handleDraft(w http.ResponseWriter, r *http.Request) {
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	d, err := s.network().Draft()
	if errors.Is(err, admin.ErrNoDraft) {
		writeJSON(w, http.StatusOK, map[string]any{"draft": nil})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"draft": d})
}

func (s *Server) handleDraftSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if !decodeBody(w, r, &req) {
		return
	}
	days := req.ValidityDays
	if days == 0 {
		days = int(trust.DefaultValidity.Hours() / 24)
	}
	maxDays := int(trust.MaxValidity.Hours() / 24)
	if days < 1 || days > maxDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Belge geçerliliği 1 ile %d gün arasında olmalı.", maxDays))
		return
	}
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	plan, err := s.network().PrepareDraft(s.now(), time.Duration(days)*24*time.Hour)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := changeResponse{DryRun: req.DryRun, Diff: plan.Diff, Lines: plan.Diff.Lines(), Version: plan.Next.Version}
	if req.DryRun {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	if err := s.network().CommitDraft(plan, passphrase); err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("network document signed from draft", "version", plan.Next.Version)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDraftDiscard(w http.ResponseWriter, r *http.Request) {
	if err := s.network().DiscardDraft(); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"discarded": true})
}

// --- changes ---

type bulkMembershipRequest struct {
	signRequest
	Names      []string `json:"names"`
	ExtendDays int      `json:"extendDays"`
	Expire     bool     `json:"expire"`
	AddTags    []string `json:"addTags"`
	RemoveTags []string `json:"removeTags"`
}

func (s *Server) handleBulkMembership(w http.ResponseWriter, r *http.Request) {
	var req bulkMembershipRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Names) == 0 || len(req.Names) > admin.MaxBulkDevices {
		writeError(w, http.StatusBadRequest, "En az bir cihaz seçin.")
		return
	}
	for _, n := range req.Names {
		if !validDeviceName(n) {
			writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
			return
		}
	}
	if len(req.AddTags) > trust.MaxTags || len(req.RemoveTags) > trust.MaxTags {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("En fazla %d etiket verilebilir.", trust.MaxTags))
		return
	}
	if req.ExtendDays < 0 || req.ExtendDays > maxDeviceLifeDay {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Üyelik süresi 1 ile %d gün arasında olmalı.", maxDeviceLifeDay))
		return
	}
	op := admin.BulkOp{Extend: time.Duration(req.ExtendDays) * 24 * time.Hour, Expire: req.Expire, AddTags: req.AddTags, RemoveTags: req.RemoveTags}
	change, err := admin.BulkMembership(req.Names, op, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "Toplu işlem geçersiz: "+err.Error())
		return
	}
	s.change(w, req.signRequest, change)
}

type lockdownRequest struct {
	signRequest
	On     bool   `json:"on"`
	Reason string `json:"reason"`
	// Confirm acknowledges that members older than ADR-0151 keep their
	// previous rules.
	Confirm bool `json:"confirm"`
}

func (s *Server) handleLockdown(w http.ResponseWriter, r *http.Request) {
	var req lockdownRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.On && !req.Confirm && !req.DryRun && !req.Draft {
		writeError(w, http.StatusBadRequest, "Acil kilit bütün kuralları askıya alır; eski sürümdeki cihazlar kilidi uygulamaz. İmzalamak için açıkça onayla.")
		return
	}
	s.change(w, req.signRequest, admin.SetLockdown(req.On, req.Reason, s.now()))
}

type keyAgeRequest struct {
	signRequest
	Days    int  `json:"days"`
	Confirm bool `json:"confirm"`
}

func (s *Server) handleKeyAgePolicy(w http.ResponseWriter, r *http.Request) {
	var req keyAgeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Days < 0 || req.Days > trust.MaxKeyAgeDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Anahtar yaşı 0 ile %d gün arasında olmalı.", trust.MaxKeyAgeDays))
		return
	}
	if req.Days > 0 && !req.Confirm && !req.DryRun && !req.Draft {
		writeError(w, http.StatusBadRequest, "Bu alan eski sürümdeki cihazlarca reddedilir. İmzalamak için açıkça onayla.")
		return
	}
	s.change(w, req.signRequest, admin.SetMaxKeyAge(req.Days))
}

type compactRequest struct {
	signRequest
	Keep    int  `json:"keep"`
	Confirm bool `json:"confirm"`
}

func (s *Server) handleCompactRevoked(w http.ResponseWriter, r *http.Request) {
	var req compactRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Keep < 0 || req.Keep > trust.MaxRevoked {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Tutulacak iptal sayısı 0 ile %d arasında olmalı.", trust.MaxRevoked))
		return
	}
	if !req.Confirm && !req.DryRun && !req.Draft {
		writeError(w, http.StatusBadRequest, "Sıkıştırma geri alınamaz ve eski sürümdeki cihazlarca reddedilir. İmzalamak için açıkça onayla.")
		return
	}
	s.change(w, req.signRequest, admin.CompactRevocations(req.Keep))
}
