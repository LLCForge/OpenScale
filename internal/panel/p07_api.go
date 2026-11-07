package panel

import (
	"context"
	"net/http"
	"time"
)

// P07 endpoints (ADR-0159, ADR-0160): the ransomware guard and pause of
// folder synchronization (#453), the backup integrity probe (#452) and
// the dynamic DNS check and updater (#448, #449). The page is drawn by
// the panel; see docs/rakip-analizi/calisma/panel-devir-P07.md.

// P07Schema versions the replies below.
const P07Schema = 1

// Pause reasons.
const (
	SyncPauseOwner   = "owner"
	SyncPauseGame    = "edge:game"
	SyncPauseMetered = "edge:metered"
)

// SyncPauseView is one reason that holds scheduled sync and backups.
type SyncPauseView struct {
	Reason string     `json:"reason"`
	Label  string     `json:"label"`
	Since  *time.Time `json:"since,omitempty"`
	Until  *time.Time `json:"until,omitempty"`
}

// SyncAlarmView is a folder the ransomware guard suspended.
type SyncAlarmView struct {
	Since       time.Time `json:"since"`
	Source      string    `json:"source"`
	Reason      string    `json:"reason"`
	Files       int       `json:"files"`
	Modified    int       `json:"modified"`
	Deleted     int       `json:"deleted"`
	Added       int       `json:"added"`
	ExtChanged  int       `json:"ext_changed"`
	Sampled     int       `json:"sampled"`
	HighEntropy int       `json:"high_entropy"`
	BadMagic    int       `json:"bad_magic"`
	Examples    []string  `json:"examples,omitempty"`
}

// SyncGuardFolder is the guard state of one configured folder.
type SyncGuardFolder struct {
	ID       string         `json:"id"`
	GuardOff bool           `json:"guard_off,omitempty"`
	Alarm    *SyncAlarmView `json:"alarm,omitempty"`
	// Error is set when the folder could not be opened to read its state.
	Error string `json:"error,omitempty"`
}

// BackupProbeProblem is one damaged or missing file.
type BackupProbeProblem struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// BackupProbeFolder is the probe result of one backed up folder.
type BackupProbeFolder struct {
	Folder       string               `json:"folder"`
	OK           bool                 `json:"ok"`
	Error        string               `json:"error,omitempty"`
	Snapshot     string               `json:"snapshot,omitempty"`
	SnapshotTime *time.Time           `json:"snapshot_time,omitempty"`
	Snapshots    int                  `json:"snapshots"`
	Files        int                  `json:"files"`
	Checked      int                  `json:"checked"`
	Bytes        int64                `json:"bytes"`
	Missing      int                  `json:"missing"`
	Problems     []BackupProbeProblem `json:"problems,omitempty"`
}

// BackupProbeStatus is the last probe.
type BackupProbeStatus struct {
	At      time.Time           `json:"at"`
	Target  string              `json:"target"`
	OK      bool                `json:"ok"`
	Error   string              `json:"error,omitempty"`
	Folders []BackupProbeFolder `json:"folders"`
}

// SyncGuardStatus is GET /api/app/sync/guard.
type SyncGuardStatus struct {
	Schema  int               `json:"schema"`
	Paused  bool              `json:"paused"`
	Pauses  []SyncPauseView   `json:"pauses"`
	Folders []SyncGuardFolder `json:"folders"`
	// Probe is the last backup integrity probe; nil before the first.
	Probe *BackupProbeStatus `json:"probe,omitempty"`
	// ProbeHours is how often the probe runs while backups are on.
	ProbeHours int `json:"probe_hours"`
}

// SyncPauseRequest pauses (for Hours, 0: until resumed) or resumes the
// owner's pause.
type SyncPauseRequest struct {
	Paused bool `json:"paused"`
	Hours  int  `json:"hours,omitempty"`
}

// SyncGuardRequest turns the guard of one folder off or on.
type SyncGuardRequest struct {
	ID  string `json:"id"`
	Off bool   `json:"off"`
}

// SyncFolderRequest names a folder.
type SyncFolderRequest struct {
	ID string `json:"id"`
}

// SyncGuardControl is implemented by the service.
type SyncGuardControl interface {
	SyncGuardStatus() (SyncGuardStatus, error)
	SetSyncPause(req SyncPauseRequest) (SyncGuardStatus, error)
	SetSyncGuard(req SyncGuardRequest) (SyncGuardStatus, error)
	ClearSyncAlarm(id string) (SyncGuardStatus, error)
	ProbeBackup(ctx context.Context) (SyncGuardStatus, error)
}

// probeTimeout bounds a probe started from the panel.
const probeTimeout = 30 * time.Minute

func (s *Server) p07Routes(mux *http.ServeMux) {
	read := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	guard := func(h func(http.ResponseWriter, *http.Request, SyncGuardControl)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, ok := s.app.(SyncGuardControl)
			if !ok {
				writeError(w, http.StatusNotFound, "Bu işlem yalnızca OpenScale servisinde var.")
				return
			}
			h(w, r, c)
		}
	}
	mux.HandleFunc("GET /api/app/sync/guard", read(guard(func(w http.ResponseWriter, _ *http.Request, c SyncGuardControl) {
		guardReply(w, c.SyncGuardStatus)
	})))
	mux.HandleFunc("POST /api/app/sync/pause", write(guard(func(w http.ResponseWriter, r *http.Request, c SyncGuardControl) {
		var req SyncPauseRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.Hours < 0 || req.Hours > 24*30 {
			writeError(w, http.StatusBadRequest, "Duraklatma süresi 0 ile 720 saat arasında olmalı.")
			return
		}
		guardReply(w, func() (SyncGuardStatus, error) { return c.SetSyncPause(req) })
	})))
	mux.HandleFunc("POST /api/app/sync/guard", write(guard(func(w http.ResponseWriter, r *http.Request, c SyncGuardControl) {
		var req SyncGuardRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.ID) == 0 || len(req.ID) > 63 {
			writeError(w, http.StatusBadRequest, "Klasör kimliği geçersiz.")
			return
		}
		guardReply(w, func() (SyncGuardStatus, error) { return c.SetSyncGuard(req) })
	})))
	mux.HandleFunc("POST /api/app/sync/guard/clear", write(guard(func(w http.ResponseWriter, r *http.Request, c SyncGuardControl) {
		var req SyncFolderRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if len(req.ID) == 0 || len(req.ID) > 63 {
			writeError(w, http.StatusBadRequest, "Klasör kimliği geçersiz.")
			return
		}
		guardReply(w, func() (SyncGuardStatus, error) { return c.ClearSyncAlarm(req.ID) })
	})))
	mux.HandleFunc("POST /api/app/sync/backup/probe", write(guard(func(w http.ResponseWriter, r *http.Request, c SyncGuardControl) {
		ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
		defer cancel()
		guardReply(w, func() (SyncGuardStatus, error) { return c.ProbeBackup(ctx) })
	})))
	s.p07NetRoutes(mux, read, write)
}

func guardReply(w http.ResponseWriter, fn func() (SyncGuardStatus, error)) {
	st, err := fn()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	st.Schema = P07Schema
	if st.Pauses == nil {
		st.Pauses = []SyncPauseView{}
	}
	if st.Folders == nil {
		st.Folders = []SyncGuardFolder{}
	}
	writeJSON(w, http.StatusOK, st)
}
