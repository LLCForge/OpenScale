package panel

import (
	"errors"
	"net/http"

	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/privacy"
	"github.com/openscale/openscale/internal/tpm"
)

// G6 endpoints (ADR-0204..0208): end-to-end file transfer, quarantine,
// screen share detection, extended posture, tamper log and TPM status.
// The idle lock (#661) lives in g6_lock.go. Interface requests for the
// Next.js panel are in docs/rakip-analizi/calisma/panel-devir-G6.md.

// E2EFileControl is implemented by the desktop app (p2psend.Service has
// exactly these methods).
type E2EFileControl interface {
	E2ETransfers() []p2psend.TransferView
	E2EPending() []p2psend.Offer
	E2EDecide(id string, accept bool) error
	E2EStart(req p2psend.SendRequest) error
	E2EQuarantine() p2psend.Quarantine
	E2ERelay() bool
	SetE2ERelay(on bool) error
}

// TamperControl exposes the device's tamper log (#606).
type TamperControl interface {
	TamperEvents() []posture.TamperEvent
}

// TPMControl reports whether the device key is sealed (#602).
type TPMControl interface {
	DeviceKeySealed() (sealed bool, kind string)
}

// E2EStatus is GET /api/app/e2e.
type E2EStatus struct {
	Schema    int                    `json:"schema"`
	Transfers []p2psend.TransferView `json:"transfers"`
	Pending   []p2psend.Offer        `json:"pending"`
	Relay     bool                   `json:"relay"`
}

// E2EDecision answers an offer.
type E2EDecision struct {
	ID     string `json:"id"`
	Accept bool   `json:"accept"`
}

// E2ERelayRequest turns relaying on or off.
type E2ERelayRequest struct {
	Enabled bool `json:"enabled"`
}

// QuarantineStatus is GET /api/app/e2e/quarantine.
type QuarantineStatus struct {
	Schema int                       `json:"schema"`
	Files  []p2psend.QuarantinedFile `json:"files"`
}

// QuarantineRelease is the answer to a release.
type QuarantineRelease struct {
	Schema  int    `json:"schema"`
	Path    string `json:"path"`
	Warning string `json:"warning"`
}

// ExtPostureView is GET /api/app/posture/extended.
type ExtPostureView struct {
	Schema         int      `json:"schema"`
	DiskEncryption string   `json:"disk_encryption"`
	Firewall       string   `json:"firewall"`
	SecureBoot     string   `json:"secure_boot"`
	TPM            string   `json:"tpm"`
	ScreenLock     string   `json:"screen_lock"`
	LockMinutes    int      `json:"lock_minutes"`
	MaxLockMinutes int      `json:"max_lock_minutes"`
	Grade          string   `json:"grade"`
	Reasons        []string `json:"reasons"`
	Disclaimer     string   `json:"disclaimer"`
}

// TamperView is GET /api/app/tamper.
type TamperView struct {
	Schema int                   `json:"schema"`
	Events []posture.TamperEvent `json:"events"`
}

// TPMView is GET /api/app/tpm.
type TPMView struct {
	Schema    int    `json:"schema"`
	Present   bool   `json:"present"`
	Version   string `json:"version"`
	Sealed    bool   `json:"sealed"`
	SealKind  string `json:"seal_kind,omitempty"`
	Supported bool   `json:"supported"`
	Note      string `json:"note"`
}

func (s *Server) g6Routes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	e2e := func(h func(http.ResponseWriter, *http.Request, E2EFileControl)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, ok := s.app.(E2EFileControl)
			if !ok {
				writeError(w, http.StatusNotFound, "Uçtan uca dosya aktarımı bu sürümde yok.")
				return
			}
			h(w, r, c)
		}
	}
	mux.HandleFunc("GET /api/app/e2e", read(e2e(func(w http.ResponseWriter, _ *http.Request, c E2EFileControl) {
		writeJSON(w, http.StatusOK, E2EStatus{Schema: 1, Transfers: c.E2ETransfers(), Pending: c.E2EPending(), Relay: c.E2ERelay()})
	})))
	mux.HandleFunc("POST /api/app/e2e/send", write(e2e(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req p2psend.SendRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if err := c.E2EStart(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
	})))
	mux.HandleFunc("POST /api/app/e2e/decide", write(e2e(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req E2EDecision
		if !decodeBody(w, r, &req) {
			return
		}
		if err := c.E2EDecide(req.ID, req.Accept); err != nil {
			writeError(w, http.StatusNotFound, "Bu dosya teklifi artık beklemiyor.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})))
	mux.HandleFunc("POST /api/app/e2e/relay", write(e2e(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req E2ERelayRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if err := c.SetE2ERelay(req.Enabled); err != nil {
			writeError(w, http.StatusBadRequest, "Ara cihaz ayarı kaydedilemedi.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"relay": c.E2ERelay()})
	})))
	mux.HandleFunc("GET /api/app/e2e/quarantine", read(e2e(func(w http.ResponseWriter, _ *http.Request, c E2EFileControl) {
		files, err := c.E2EQuarantine().List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Karantina klasörü okunamadı.")
			return
		}
		if files == nil {
			files = []p2psend.QuarantinedFile{}
		}
		writeJSON(w, http.StatusOK, QuarantineStatus{Schema: 1, Files: files})
	})))
	mux.HandleFunc("POST /api/app/e2e/quarantine/release", write(e2e(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req FileNameRequest
		if !decodeBody(w, r, &req) {
			return
		}
		p, err := c.E2EQuarantine().Release(req.Name)
		if err != nil {
			quarantineFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, QuarantineRelease{Schema: 1, Path: p, Warning: p2psend.Warning(req.Name)})
	})))
	mux.HandleFunc("POST /api/app/e2e/quarantine/delete", write(e2e(func(w http.ResponseWriter, r *http.Request, c E2EFileControl) {
		var req FileNameRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if err := c.E2EQuarantine().Remove(req.Name); err != nil {
			quarantineFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})))
	// Screen share detection (#689). Polled by the panel; reads only the
	// process list of this computer.
	mux.HandleFunc("GET /api/app/privacy/screen-share", s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, privacy.DetectScreenShare(s.now()))
	}))
	mux.HandleFunc("GET /api/app/posture/extended", s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, extPostureView(posture.Cached(), posture.CachedExtended()))
	}))
	mux.HandleFunc("GET /api/app/tamper", read(func(w http.ResponseWriter, _ *http.Request) {
		c, ok := s.app.(TamperControl)
		if !ok {
			writeError(w, http.StatusNotFound, "Kurcalama günlüğü bu sürümde yok.")
			return
		}
		ev := c.TamperEvents()
		if ev == nil {
			ev = []posture.TamperEvent{}
		}
		writeJSON(w, http.StatusOK, TamperView{Schema: 1, Events: ev})
	}))
	mux.HandleFunc("GET /api/app/tpm", s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
		v := TPMView{Schema: 1, Note: "TPM mühürleme gerçek donanımda henüz denenmedi."}
		p, err := tpm.Detect()
		v.Supported = !errors.Is(err, tpm.ErrUnsupported)
		v.Present, v.Version = p.Present, p.Version
		if c, ok := s.app.(TPMControl); ok {
			v.Sealed, v.SealKind = c.DeviceKeySealed()
		}
		writeJSON(w, http.StatusOK, v)
	}))
	s.g6LockRoutes(mux)
}

func quarantineFail(w http.ResponseWriter, err error) {
	if errors.Is(err, p2psend.ErrNotInQuarantine) {
		writeError(w, http.StatusNotFound, "Karantinada böyle bir dosya yok.")
		return
	}
	writeError(w, http.StatusInternalServerError, "Dosya işlenemedi.")
}

func extPostureView(r posture.Report, x posture.Extended) ExtPostureView {
	r = x.Merge(r)
	g, why := posture.Classify(r, x)
	if why == nil {
		why = []string{}
	}
	return ExtPostureView{Schema: 1, DiskEncryption: r.DiskEncryption.String(), Firewall: r.Firewall.String(),
		SecureBoot: x.SecureBoot.String(), TPM: x.TPM.String(), ScreenLock: x.ScreenLock.String(), LockMinutes: x.LockMinutes,
		MaxLockMinutes: posture.MaxLockMinutes, Grade: string(g), Reasons: why, Disclaimer: posture.Disclaimer}
}
