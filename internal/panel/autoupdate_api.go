package panel

import (
	"net/http"
	"time"
)

// Automatic update card (ADR-0225): the switch and what the device last
// learnt from the coordinator's release mirror.

// AutoUpdateAttempt is the last installation.
type AutoUpdateAttempt struct {
	Version    string    `json:"version"`
	At         time.Time `json:"at"`
	OK         bool      `json:"ok"`
	RolledBack bool      `json:"rolledBack,omitempty"`
	Message    string    `json:"message,omitempty"`
}

// AutoUpdateStatus is the reply of GET and POST /api/app/auto-update.
type AutoUpdateStatus struct {
	Supported      bool               `json:"supported"`
	Enabled        bool               `json:"enabled"`
	State          string             `json:"state"`
	Message        string             `json:"message"`
	Action         string             `json:"action,omitempty"`
	Channel        string             `json:"channel"`
	Current        string             `json:"current"`
	Latest         string             `json:"latest,omitempty"`
	LatestVerified bool               `json:"latestVerified"`
	LastCheck      time.Time          `json:"lastCheck,omitzero"`
	NextCheck      time.Time          `json:"nextCheck,omitzero"`
	ScheduledAt    time.Time          `json:"scheduledAt,omitzero"`
	Source         string             `json:"source,omitempty"`
	SourceChecked  time.Time          `json:"sourceChecked,omitzero"`
	LastAttempt    *AutoUpdateAttempt `json:"lastAttempt,omitempty"`
	// Ring is this device's update ring and Rollout the coordinator's
	// progress for the announced release (ADR-0235).
	Ring    string             `json:"ring,omitempty"`
	Rollout *AutoUpdateRollout `json:"rollout,omitempty"`
}

// AutoUpdateRing is one ring's numbers as the coordinator reports them.
type AutoUpdateRing struct {
	Ring       string `json:"ring"`
	Members    int    `json:"members"`
	Updated    int    `json:"updated"`
	Healthy    int    `json:"healthy"`
	RolledBack int    `json:"rolledBack"`
}

// AutoUpdateRollout is the ring progress of the announced release; the
// soak times are in seconds.
type AutoUpdateRollout struct {
	Announced  bool             `json:"announced"`
	Open       string           `json:"open,omitempty"`
	Halted     bool             `json:"halted,omitempty"`
	HaltRing   string           `json:"haltRing,omitempty"`
	CanarySoak int64            `json:"canarySoak"`
	EarlySoak  int64            `json:"earlySoak"`
	Since      time.Time        `json:"since,omitzero"`
	EarlyAt    time.Time        `json:"earlyAt,omitzero"`
	MainAt     time.Time        `json:"mainAt,omitzero"`
	FirstSeen  time.Time        `json:"firstSeen,omitzero"`
	NotBefore  time.Time        `json:"notBefore,omitzero"`
	Rings      []AutoUpdateRing `json:"rings,omitempty"`
}

// AutoUpdateRequest turns the switch.
type AutoUpdateRequest struct {
	On bool `json:"on"`
}

// AutoUpdateControl is implemented by the desktop service.
type AutoUpdateControl interface {
	AutoUpdateStatus() (AutoUpdateStatus, error)
	SetAutoUpdate(on bool) (AutoUpdateStatus, error)
}

func (s *Server) autoUpdateRoutes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	control := func(w http.ResponseWriter) (AutoUpdateControl, bool) {
		c, ok := s.app.(AutoUpdateControl)
		if !ok {
			writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
		}
		return c, ok
	}
	reply := func(w http.ResponseWriter, st AutoUpdateStatus, err error) {
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st)
	}
	mux.HandleFunc("GET /api/app/auto-update", read(func(w http.ResponseWriter, _ *http.Request) {
		if c, ok := control(w); ok {
			st, err := c.AutoUpdateStatus()
			reply(w, st, err)
		}
	}))
	mux.HandleFunc("POST /api/app/auto-update", write(func(w http.ResponseWriter, r *http.Request) {
		c, ok := control(w)
		if !ok {
			return
		}
		var req AutoUpdateRequest
		if !decodeBody(w, r, &req) {
			return
		}
		st, err := c.SetAutoUpdate(req.On)
		reply(w, st, err)
	}))
}
