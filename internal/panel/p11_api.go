package panel

import (
	"context"
	"net/http"
	"time"
)

// Edge device modes and hardening (P11, ADR-0154): travel, game and
// metered modes that change several preferences together and put them
// back (#464, #447, #385), the shield while the screen is locked (#501),
// the start-up integrity gate (#522), local network attack detection
// (#466), OpenScale's own attack surface (#521) and third-party filters
// that could defeat the kill switch (#499).
//
// The endpoints use the app token (administrators only), like the
// command line diagnostics API and the tray; the browser panel has no
// session route to them.

// EdgeSchema versions the replies below.
const EdgeSchema = 1

// Edge mode names.
const (
	EdgeModeTravel  = "travel"
	EdgeModeGame    = "game"
	EdgeModeMetered = "metered"
	EdgeModeOff     = "off"
)

// EdgeOptions are the owner's P11 options. Zero values are the defaults.
type EdgeOptions struct {
	// LockShield turns the shield on while the screen is locked.
	LockShield bool `json:"lock_shield,omitempty"`
	// RequireIntegrity keeps the tunnel down when the program does not
	// match its signed manifest.
	RequireIntegrity bool `json:"require_integrity,omitempty"`
	// LANGuardOff turns local network attack detection off (on by default;
	// it only reads this computer's neighbour table).
	LANGuardOff bool `json:"lan_guard_off,omitempty"`
	// LANGuardTravel starts the travel mode when an attack is suspected.
	LANGuardTravel bool `json:"lan_guard_travel,omitempty"`
	// AutoMetered starts the metered mode while the system reports a
	// metered connection, and ends it afterwards.
	AutoMetered bool `json:"auto_metered,omitempty"`
	// TravelExit is the exit node an automatic travel mode uses.
	TravelExit string `json:"travel_exit,omitempty"`
}

// EdgeOptionsChange changes some options; nil fields stay.
type EdgeOptionsChange struct {
	LockShield       *bool   `json:"lock_shield,omitempty"`
	RequireIntegrity *bool   `json:"require_integrity,omitempty"`
	LANGuard         *bool   `json:"lan_guard,omitempty"`
	LANGuardTravel   *bool   `json:"lan_guard_travel,omitempty"`
	AutoMetered      *bool   `json:"auto_metered,omitempty"`
	TravelExit       *string `json:"travel_exit,omitempty"`
}

// EdgeChange is one preference a mode changed.
type EdgeChange struct {
	Key  string `json:"key"`
	From string `json:"from"`
	To   string `json:"to"`
}

// EdgeLANAlert is one suspected local network attack.
type EdgeLANAlert struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Gateway string    `json:"gateway"`
	Message string    `json:"message"`
}

// EdgeStatus is the reply of the edge endpoints.
type EdgeStatus struct {
	Schema    int          `json:"schema"`
	Mode      string       `json:"mode,omitempty"`
	ModeSince *time.Time   `json:"mode_since,omitempty"`
	ModeAuto  string       `json:"mode_auto,omitempty"`
	Changes   []EdgeChange `json:"changes,omitempty"`
	Options   EdgeOptions  `json:"options"`
	// Metered is the system's metered connection hint; nil when unknown.
	Metered *bool `json:"metered,omitempty"`
	// LockShield is true while the shield is on because of a lock.
	LockShield bool           `json:"lock_shield_active,omitempty"`
	LANAlerts  []EdgeLANAlert `json:"lan_alerts,omitempty"`
	// Notes explain what the last change did or left alone.
	Notes []string `json:"notes,omitempty"`
}

// EdgeModeRequest starts or ends a mode.
type EdgeModeRequest struct {
	Mode     string `json:"mode"`
	ExitNode string `json:"exit_node,omitempty"`
}

// EdgeLockRequest is sent by the tray on session lock and unlock.
type EdgeLockRequest struct {
	Locked bool `json:"locked"`
}

// SurfaceEntry is one socket the OpenScale service has open.
type SurfaceEntry struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Purpose string `json:"purpose"`
	Reach   string `json:"reach"`
	Rule    string `json:"rule"`
}

// SurfaceReply lists the service's attack surface.
type SurfaceReply struct {
	Schema  int            `json:"schema"`
	PID     int            `json:"pid"`
	Entries []SurfaceEntry `json:"entries"`
	Notes   []string       `json:"notes,omitempty"`
}

// EdgeCheck is one finding of the hardening audit.
type EdgeCheck struct {
	Area    string `json:"area"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// EdgeAuditReply is the hardening audit.
type EdgeAuditReply struct {
	Schema int         `json:"schema"`
	Checks []EdgeCheck `json:"checks"`
}

// EdgeApp is implemented by the service.
type EdgeApp interface {
	EdgeStatus() (EdgeStatus, error)
	EdgeSetMode(req EdgeModeRequest) (EdgeStatus, error)
	EdgeSetOptions(c EdgeOptionsChange) (EdgeStatus, error)
	EdgeSessionLock(locked bool) (EdgeStatus, error)
	EdgeSurface() (SurfaceReply, error)
	EdgeAudit(ctx context.Context) (EdgeAuditReply, error)
}

// edgeAuditTimeout bounds the hardening audit.
const edgeAuditTimeout = 20 * time.Second

func (s *Server) p11Routes(mux *http.ServeMux) {
	token := func(h func(http.ResponseWriter, *http.Request, EdgeApp)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.trayAuthorized(w, r) {
				return
			}
			e, ok := s.app.(EdgeApp)
			if s.app == nil || !ok {
				writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
				return
			}
			h(w, r, e)
		}
	}
	p := LocalAPIPrefix + "/edge"
	mux.HandleFunc("GET "+p, token(func(w http.ResponseWriter, _ *http.Request, e EdgeApp) {
		edgeReply(w, e.EdgeStatus)
	}))
	mux.HandleFunc("POST "+p+"/mode", token(func(w http.ResponseWriter, r *http.Request, e EdgeApp) {
		var req EdgeModeRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.Mode) > 16 || len(req.ExitNode) > 255 {
			writeError(w, http.StatusBadRequest, "Kip veya çıkış düğümü adı geçersiz.")
			return
		}
		edgeReply(w, func() (EdgeStatus, error) { return e.EdgeSetMode(req) })
	}))
	mux.HandleFunc("POST "+p+"/options", token(func(w http.ResponseWriter, r *http.Request, e EdgeApp) {
		var req EdgeOptionsChange
		if !decodeBody(w, r, &req) {
			return
		}
		if req.TravelExit != nil && len(*req.TravelExit) > 255 {
			writeError(w, http.StatusBadRequest, "Çıkış düğümü adı geçersiz.")
			return
		}
		edgeReply(w, func() (EdgeStatus, error) { return e.EdgeSetOptions(req) })
	}))
	mux.HandleFunc("POST "+p+"/lock", token(func(w http.ResponseWriter, r *http.Request, e EdgeApp) {
		var req EdgeLockRequest
		if !decodeBody(w, r, &req) {
			return
		}
		edgeReply(w, func() (EdgeStatus, error) { return e.EdgeSessionLock(req.Locked) })
	}))
	mux.HandleFunc("GET "+p+"/surface", token(func(w http.ResponseWriter, _ *http.Request, e EdgeApp) {
		rep, err := e.EdgeSurface()
		if err != nil {
			diagFailed(w, err)
			return
		}
		rep.Schema = EdgeSchema
		writeJSON(w, http.StatusOK, rep)
	}))
	mux.HandleFunc("GET "+p+"/audit", token(func(w http.ResponseWriter, r *http.Request, e EdgeApp) {
		ctx, cancel := context.WithTimeout(r.Context(), edgeAuditTimeout)
		defer cancel()
		rep, err := e.EdgeAudit(ctx)
		if err != nil {
			diagFailed(w, err)
			return
		}
		rep.Schema = EdgeSchema
		writeJSON(w, http.StatusOK, rep)
	}))
}

func edgeReply(w http.ResponseWriter, fn func() (EdgeStatus, error)) {
	st, err := fn()
	if err != nil {
		diagFailed(w, err)
		return
	}
	st.Schema = EdgeSchema
	writeJSON(w, http.StatusOK, st)
}

// trustedTypesReportOnly asks the browser to report, without blocking,
// every DOM sink that receives a plain string (#519). The panel and the
// Next.js runtime have not been checked page by page in a real browser
// yet; enforcing it now could break the panel, so the policy is report
// only (the browser console lists violations) until that check is done.
const trustedTypesReportOnly = "require-trusted-types-for 'script'"
