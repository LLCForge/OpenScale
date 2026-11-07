package panel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// The members-only documents switch of Ağ > Koordinatörler (blind
// coordinator, #629, ADR-0178). The change goes through the usual dry run and
// root signature; the setting takes effect in the version signed here.

// F1MembersOnlyRequest turns members-only documents on or off.
type F1MembersOnlyRequest struct {
	signRequest
	Enabled bool `json:"enabled"`
}

func (s *Server) f1Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/g1/members-only", s.requireSession(s.requireNetwork(s.handleF1MembersOnly)))
	mux.HandleFunc("POST /api/g1/members-only", s.requireSession(s.requireCSRF(s.requireWritable(s.requireNetwork(s.handleF1SetMembersOnly)))))
}

func (s *Server) handleF1MembersOnly(w http.ResponseWriter, _ *http.Request) {
	n := s.network()
	if err := n.Reload(); err != nil {
		s.fail(w, err)
		return
	}
	st, err := n.MembersOnlyState()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleF1SetMembersOnly(w http.ResponseWriter, r *http.Request) {
	var req F1MembersOnlyRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Draft {
		writeError(w, http.StatusBadRequest, "Bu ayar taslağa eklenemez; imzalanması gerekir.")
		return
	}
	validityDays := req.ValidityDays
	if validityDays == 0 {
		validityDays = int(trust.DefaultValidity.Hours() / 24)
	}
	if validityDays < 1 || validityDays > int(trust.MaxValidity.Hours()/24) {
		writeError(w, http.StatusBadRequest, "Belge geçerliliği aralık dışında.")
		return
	}
	n := s.network()
	if err := n.Reload(); err != nil {
		s.fail(w, err)
		return
	}
	if req.Enabled {
		st, err := n.MembersOnlyState()
		if err != nil {
			s.fail(w, err)
			return
		}
		if len(st.Blockers) > 0 {
			writeError(w, http.StatusBadRequest, strings.Join(st.Blockers, " "))
			return
		}
	}
	plan, err := n.PrepareMembersOnly(req.Enabled, s.now(), time.Duration(validityDays)*24*time.Hour)
	if errors.Is(err, admin.ErrMembersOnlyUnchanged) {
		writeError(w, http.StatusBadRequest, "Bu ayar zaten bu durumda.")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := changeResponse{DryRun: req.DryRun, Diff: plan.Diff, Lines: plan.Diff.Lines(), Version: plan.Next.Version, Risk: s.riskOf(plan)}
	if req.DryRun {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if req.Token { // ADR-0223, ym_admin_token.go
		lines := resp.Lines
		if len(lines) > 12 {
			lines = append(lines[:12:12], "...")
		}
		err := n.CommitMembersOnly(req.Enabled, plan, func(p *admin.Plan) error {
			return s.commitWithTrayToken(context.Background(), p, strings.Join(lines, "\n"))
		})
		var te trayRelayError
		switch {
		case errors.As(err, &te):
			writeErrorCode(w, http.StatusConflict, string(te), err)
		case err != nil:
			s.fail(w, err)
		default:
			s.logger.Info("members-only setting signed with the tray's token session", "enabled", req.Enabled, "version", plan.Next.Version)
			writeJSON(w, http.StatusOK, resp)
		}
		return
	}
	if s.auth.passphraseLocked() {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	passphrase := []byte(req.Passphrase)
	defer wipe(passphrase)
	if err := n.CommitMembersOnly(req.Enabled, plan, func(p *admin.Plan) error { return n.Commit(p, passphrase) }); err != nil {
		s.failPassphrase(w, err)
		return
	}
	s.logger.Info("members-only setting signed", "enabled", req.Enabled, "version", plan.Next.Version)
	writeJSON(w, http.StatusOK, resp)
}
