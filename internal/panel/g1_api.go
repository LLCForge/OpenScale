package panel

import (
	"errors"
	"net/http"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// G1 endpoints (ADR-0172..0179): delegated administrator grants, the risk
// summary of the pending draft, personal data warnings, the sensitive
// device approvals, the duress setting and pre-signed emergency documents
// (panic button). Interface requests for the Next.js panel are in
// docs/rakip-analizi/calisma/panel-devir-G1.md. Issuing a grant needs the
// administrator's public key and is done with the CLI ("openscale admin
// grant"); the panel lists and revokes.

// G1AdminList is GET /api/g1/admins.
type G1AdminList struct {
	Schema int                 `json:"schema"`
	Grants []admin.GrantRecord `json:"grants"`
	// Revoked mirrors GrantRecord's unexported state per grant id.
	Revoked []string `json:"revoked"`
	Expired []string `json:"expired"`
}

// G1RevokeRequest revokes a grant (root signature).
type G1RevokeRequest struct {
	signRequest
	ID string `json:"id"`
}

// G1PanicRequest publishes a prepared emergency document.
type G1PanicRequest struct {
	Kind       string `json:"kind"`
	Device     string `json:"device"`
	Passphrase string `json:"passphrase"`
	Confirm    string `json:"confirm"`
}

func (s *Server) g1Routes(mux *http.ServeMux) {
	owner := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireNetwork(h)) }
	ownerWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(h))))
	}
	mux.HandleFunc("GET /api/g1/admins", owner(s.handleG1Admins))
	mux.HandleFunc("POST /api/g1/admins/revoke", ownerWrite(s.handleG1Revoke))
	mux.HandleFunc("GET /api/g1/risk", owner(s.handleG1Risk))
	mux.HandleFunc("GET /api/g1/pii", owner(s.handleG1PII))
	mux.HandleFunc("GET /api/g1/sensitive", owner(s.handleG1Sensitive))
	mux.HandleFunc("GET /api/g1/duress", owner(s.handleG1Duress))
	mux.HandleFunc("GET /api/g1/emergency", owner(s.handleG1Emergency))
	mux.HandleFunc("POST /api/g1/emergency/publish", ownerWrite(s.handleG1Panic))
}

func (s *Server) handleG1Admins(w http.ResponseWriter, _ *http.Request) {
	if err := s.network().Reload(); err != nil {
		s.fail(w, err)
		return
	}
	list, err := s.network().AdminGrants(s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := G1AdminList{Schema: 1, Grants: list, Revoked: []string{}, Expired: []string{}}
	if out.Grants == nil {
		out.Grants = []admin.GrantRecord{}
	}
	for _, g := range list {
		if g.Revoked {
			out.Revoked = append(out.Revoked, g.ID)
		}
		if g.ExpiredAt {
			out.Expired = append(out.Expired, g.ID)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleG1Revoke(w http.ResponseWriter, r *http.Request) {
	var req G1RevokeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	id := strings.ToLower(strings.TrimSpace(req.ID))
	if len(id) != 32 {
		writeError(w, http.StatusBadRequest, "Yetki kimliği 32 onaltılık karakter olmalı.")
		return
	}
	s.change(w, req.signRequest, admin.RevokeAdminGrant(id))
}

func (s *Server) handleG1Risk(w http.ResponseWriter, _ *http.Request) {
	n := s.network()
	if err := n.Reload(); err != nil {
		s.fail(w, err)
		return
	}
	plan, err := n.PrepareDraft(s.now(), trust.DefaultValidity)
	if errors.Is(err, admin.ErrNoDraft) {
		writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "risk": nil})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	cur, err := n.Document()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "risk": admin.AssessRisk(cur, plan.Next)})
}

func (s *Server) handleG1PII(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.network().Document()
	if err != nil {
		s.fail(w, err)
		return
	}
	ws := admin.PersonalDataWarnings(doc)
	if ws == nil {
		ws = []admin.PIIWarning{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "warnings": ws})
}

func (s *Server) handleG1Sensitive(w http.ResponseWriter, _ *http.Request) {
	st, err := s.network().Sensitive()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "sensitive": st})
}

func (s *Server) handleG1Duress(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "configured": admin.DuressConfigured(s.network().Dir())})
}

func (s *Server) handleG1Emergency(w http.ResponseWriter, _ *http.Request) {
	list, err := s.network().EmergencyStatus(s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	if list == nil {
		list = []admin.EmergencyRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "documents": list})
}

func (s *Server) handleG1Panic(w http.ResponseWriter, r *http.Request) {
	var req G1PanicRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pass := []byte(req.Passphrase)
	defer clear(pass)
	if req.Confirm != "PANIK" {
		writeError(w, http.StatusBadRequest, "Panik için onay metni PANIK olmalı.")
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	_, doc, err := s.network().PublishEmergency(req.Kind, req.Device, pass, s.now())
	switch {
	case errors.Is(err, trust.ErrWrongPassphrase):
		s.failPassphrase(w, err)
		return
	case errors.Is(err, admin.ErrNoEmergency):
		writeError(w, http.StatusNotFound, "Bu türde hazır acil durum belgesi yok.")
		return
	case errors.Is(err, admin.ErrEmergencyOutdated):
		writeError(w, http.StatusConflict, "Ağ bu acil durum belgesinden ileri gitti; belgeyi yeniden hazırlayın.")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "version": doc.Version, "lockdown": doc.Lockdown != nil})
}
