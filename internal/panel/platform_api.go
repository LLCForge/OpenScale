package panel

import (
	"context"
	"net/http"
	"time"
)

// Platform support (P10, ADR-0162-0164): the operating system build and
// the repair after a major update (#498), the memory profile (#392), the
// service's resource limits (#494), Windows Server Core (#493), WSL2
// (#490) and the portable mode (#497).
//
// The browser panel reads the status with its session and asks for a
// repair with the session and the CSRF token (it changes nothing in the
// network document, so no signature is needed); the command line uses
// the app token like the other local diagnostics.

// PlatformSchema versions PlatformStatus.
const PlatformSchema = 1

// Check levels.
const (
	PlatformOK       = "ok"
	PlatformWarn     = "warn"
	PlatformError    = "error"
	PlatformRepaired = "repaired"
)

// PlatformOS is the operating system this service runs on.
type PlatformOS struct {
	Family     string `json:"family"`
	Version    string `json:"version,omitempty"`
	Build      string `json:"build,omitempty"`
	Patch      string `json:"patch,omitempty"`
	Edition    string `json:"edition,omitempty"`
	Arch       string `json:"arch"`
	ServerCore bool   `json:"server_core,omitempty"`
}

// PlatformCheck is one item of a repair.
type PlatformCheck struct {
	Area    string `json:"area"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// PlatformRepair is the result of the last repair.
type PlatformRepair struct {
	At time.Time `json:"at"`
	// Reason is "os-update" (automatic) or "manual".
	Reason string          `json:"reason"`
	From   string          `json:"from,omitempty"`
	To     string          `json:"to,omitempty"`
	Checks []PlatformCheck `json:"checks"`
}

// PlatformOSUpdate tells that the build changed since the last start.
type PlatformOSUpdate struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	DetectedAt time.Time `json:"detected_at"`
}

// PlatformMemory is the memory profile and the live Go memory.
type PlatformMemory struct {
	Profile     string `json:"profile"`
	MemoryLimit int64  `json:"memory_limit,omitempty"`
	GCPercent   int    `json:"gc_percent,omitempty"`
	// Live is heap in use plus goroutine stacks, in bytes.
	Live uint64 `json:"live"`
	// Budget is the profile's target (low: 32 MiB); 0 for the default.
	Budget   int64 `json:"budget,omitempty"`
	MaxFlows int   `json:"max_flows,omitempty"`
}

// PlatformLimits are the resource limits of the service process.
type PlatformLimits struct {
	// Mechanism is "job" (Windows job object), "systemd" or "".
	Mechanism  string `json:"mechanism,omitempty"`
	MemoryMax  uint64 `json:"memory_max,omitempty"`
	CPUPercent int    `json:"cpu_percent,omitempty"`
	Applied    bool   `json:"applied,omitempty"`
	Error      string `json:"error,omitempty"`
}

// PlatformWSL is the WSL2 compatibility hint.
type PlatformWSL struct {
	Installed bool     `json:"installed,omitempty"`
	Inside    bool     `json:"inside,omitempty"`
	Version   int      `json:"version,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// PlatformStatus is the reply of every platform endpoint.
type PlatformStatus struct {
	Schema     int               `json:"schema"`
	OS         PlatformOS        `json:"os"`
	OSUpdate   *PlatformOSUpdate `json:"os_update,omitempty"`
	LastRepair *PlatformRepair   `json:"last_repair,omitempty"`
	// Repairing is true while a repair runs.
	Repairing bool            `json:"repairing,omitempty"`
	Memory    PlatformMemory  `json:"memory"`
	Limits    *PlatformLimits `json:"limits,omitempty"`
	WSL       *PlatformWSL    `json:"wsl,omitempty"`
	// Portable is true when this process runs in the portable mode.
	Portable bool     `json:"portable,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// PlatformApp is implemented by the service.
type PlatformApp interface {
	PlatformStatus() (PlatformStatus, error)
	PlatformRepair(ctx context.Context) (PlatformStatus, error)
}

// platformRepairTimeout bounds a repair started from the panel.
const platformRepairTimeout = 60 * time.Second

func (s *Server) platformRoutes(mux *http.ServeMux) {
	app := func(w http.ResponseWriter) (PlatformApp, bool) {
		p, ok := s.app.(PlatformApp)
		if s.app == nil || !ok {
			writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
			return nil, false
		}
		return p, true
	}
	status := func(w http.ResponseWriter, _ *http.Request) {
		if p, ok := app(w); ok {
			platformReply(w, p.PlatformStatus)
		}
	}
	repair := func(w http.ResponseWriter, r *http.Request) {
		p, ok := app(w)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), platformRepairTimeout)
		defer cancel()
		platformReply(w, func() (PlatformStatus, error) { return p.PlatformRepair(ctx) })
	}
	token := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.trayAuthorized(w, r) {
				h(w, r)
			}
		}
	}
	mux.HandleFunc("GET "+LocalAPIPrefix+"/platform", token(status))
	mux.HandleFunc("POST "+LocalAPIPrefix+"/platform/repair", token(repair))
	mux.HandleFunc("GET /api/app/platform", s.requireSession(s.requireApp(status)))
	mux.HandleFunc("POST /api/app/platform/repair", s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(repair)))))
}

func platformReply(w http.ResponseWriter, fn func() (PlatformStatus, error)) {
	st, err := fn()
	if err != nil {
		diagFailed(w, err)
		return
	}
	st.Schema = PlatformSchema
	writeJSON(w, http.StatusOK, st)
}
