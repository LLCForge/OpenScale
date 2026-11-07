package autoupdate

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/rollout"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Update rings (#827, ADR-0235): the device learns its ring from its own
// signed tags, sends a small report with every announcement request and
// installs only when the coordinator's progress opens its ring and its own
// floor (the soak times since it first saw the release) has passed.

// States of Status.State for the rings.
const (
	// StateRingWait: the release waits for this device's ring.
	StateRingWait = "ring-wait"
	// StateHalted: a rollback halted the release.
	StateHalted = "halted"
)

// SeenFile in Paths.Work remembers when this device first saw the
// announced release, for the local floor.
const SeenFile = "ring-seen.json"

const (
	// ringReportEvery is how often canary and early devices check (and
	// report), so the next ring does not wait a full Every for them.
	ringReportEvery = time.Hour
	ringRecheckMin  = time.Minute
)

// RingInfo is what this device's signed document says about the rings.
type RingInfo struct {
	// Ring is this device's ring; Canary and Early count those rings'
	// members.
	Ring          string
	Canary, Early int
}

// RingInfoOf reads the rings from a document for the device id.
func RingInfoOf(doc *trust.Document, id string) RingInfo {
	info := RingInfo{Ring: rollout.RingMain}
	if doc == nil {
		return info
	}
	for i := range doc.Devices {
		d := &doc.Devices[i]
		ring := rollout.RingOf(d.Tags)
		switch ring {
		case rollout.RingCanary:
			info.Canary++
		case rollout.RingEarly:
			info.Early++
		}
		if d.ID == id {
			info.Ring = ring
		}
	}
	return info
}

// RingCount is one ring's numbers as the coordinator reports them.
type RingCount struct {
	Ring       string `json:"ring"`
	Members    int    `json:"members"`
	Updated    int    `json:"updated"`
	Healthy    int    `json:"healthy"`
	RolledBack int    `json:"rolledBack"`
}

// RolloutStatus is the ring part of Status.
type RolloutStatus struct {
	// Announced: the coordinator sent progress (an older one does not).
	Announced bool   `json:"announced"`
	Open      string `json:"open,omitempty"`
	Halted    bool   `json:"halted,omitempty"`
	HaltRing  string `json:"haltRing,omitempty"`
	// CanarySoak and EarlySoak are in seconds.
	CanarySoak int64       `json:"canarySoak"`
	EarlySoak  int64       `json:"earlySoak"`
	Since      time.Time   `json:"since,omitzero"`
	EarlyAt    time.Time   `json:"earlyAt,omitzero"`
	MainAt     time.Time   `json:"mainAt,omitzero"`
	FirstSeen  time.Time   `json:"firstSeen,omitzero"`
	NotBefore  time.Time   `json:"notBefore,omitzero"`
	Rings      []RingCount `json:"rings,omitempty"`
}

func rolloutStatus(a *rollout.Announcement, seen time.Time, d rollout.Decision) *RolloutStatus {
	rs := &RolloutStatus{FirstSeen: seen, NotBefore: d.NotBefore,
		CanarySoak: int64(rollout.DefaultCanarySoak / time.Second), EarlySoak: int64(rollout.DefaultEarlySoak / time.Second)}
	if a == nil {
		return rs
	}
	rs.Announced, rs.Open, rs.Halted, rs.HaltRing = true, a.Open, a.Halted, a.HaltRing
	rs.CanarySoak, rs.EarlySoak = int64(rollout.ClampSoak(a.CanarySoak)/time.Second), int64(rollout.ClampSoak(a.EarlySoak)/time.Second)
	rs.Since, rs.EarlyAt, rs.MainAt = a.Since, a.EarlyAt, a.MainAt
	for _, c := range a.Rings {
		rs.Rings = append(rs.Rings, RingCount(c))
	}
	return rs
}

type seenRecord struct {
	Digest string    `json:"digest"`
	First  time.Time `json:"first"`
}

// firstSeen returns when this device first saw digest, recording now for
// a new one. A future-dated record (clock moved back) counts from now.
func firstSeen(work, digest string, now time.Time) time.Time {
	path := filepath.Join(work, SeenFile)
	if data, err := securefile.ReadPrivate(path, maxSmallFile); err == nil {
		var s seenRecord
		if decodeStrict(data, &s) == nil && s.Digest == digest && !s.First.After(now) {
			return s.First
		}
	}
	// Without the record the floor counts from the next check again.
	_ = writeJSON(path, seenRecord{Digest: digest, First: now.UTC()})
	return now
}

// report is this device's rollout report for the announcement request.
func (r *Runner) report() []byte {
	rep := rollout.Report{Run: r.cfg.Installed, OK: true}
	if r.cfg.Healthy != nil {
		rep.OK = r.cfg.Healthy()
	}
	r.mu.Lock()
	if a := r.status.LastAttempt; a != nil && a.RolledBack {
		rep.RolledBack = a.Version
	}
	r.mu.Unlock()
	data, err := rep.Encode()
	if err != nil {
		return nil
	}
	return data
}

func (r *Runner) ringInfo() RingInfo {
	if r.cfg.Rings == nil {
		return RingInfo{Ring: rollout.RingMain}
	}
	info := r.cfg.Rings()
	if rollout.Index(info.Ring) < 0 {
		info.Ring = rollout.RingMain
	}
	return info
}

// ringGate decides for a verified release; a non-empty state stops the
// check with it.
func (r *Runner) ringGate(st *Status, ann announcement, now time.Time) (time.Duration, bool) {
	info := r.ringInfo()
	seen := firstSeen(r.cfg.Paths.Work, ann.Digest, now)
	d := rollout.Decide(rollout.Gate{Ring: info.Ring, Canary: info.Canary, Early: info.Early, Ann: ann.Rollout, FirstSeen: seen, Now: now})
	st.Rollout = rolloutStatus(ann.Rollout, seen, d)
	switch d.Wait {
	case rollout.WaitHalted:
		st.State = StateHalted
		st.Message = "Koordinatör " + ann.Version + " sürümünü durdurdu: " + ringName(ann.Rollout.HaltRing) + " halkasında bir cihaz önceki sürüme döndü. Sahip sorunu inceleyip 'openscale update rings resume' ile sürdürebilir ya da yeni sürüm yayımlayabilir."
		return r.cfg.Every, false
	case rollout.WaitRing:
		st.State = StateRingWait
		st.Message = "İmzalı " + ann.Version + " doğrulandı; bu cihaz " + ringName(info.Ring) + " halkasında ve sıra henüz bu halkaya gelmedi (önce önceki halkadaki cihazlar yeni sürümde sorunsuz çalışmalı)."
		return r.cfg.Every, false
	case rollout.WaitFloor:
		st.State, st.ScheduledAt = StateRingWait, d.NotBefore
		st.Message = "İmzalı " + ann.Version + " doğrulandı; bu cihaz " + ringName(info.Ring) + " halkasında ve önceki halkaların bekleme süresi bu cihazın kendi saatine göre dolmadı."
		return max(min(d.NotBefore.Sub(now), r.cfg.Every), ringRecheckMin), false
	}
	return 0, true
}

func ringName(ring string) string {
	switch ring {
	case rollout.RingCanary:
		return "canary"
	case rollout.RingEarly:
		return "early"
	}
	return "main"
}

// decodeRollout parses the progress in a TypeRelease reply; anything
// unusable counts as none (the local floor still applies).
func decodeRollout(data []byte) *rollout.Announcement {
	if len(data) == 0 {
		return nil
	}
	a, err := rollout.DecodeAnnouncement(data)
	if err != nil {
		return nil
	}
	return &a
}

var errNoRings = errors.New("no ring data")

// RingsView is what "openscale update rings status" prints on a device.
type RingsView struct {
	Ring    string         `json:"ring"`
	Latest  string         `json:"latest,omitempty"`
	State   string         `json:"state"`
	Message string         `json:"message"`
	Rollout *RolloutStatus `json:"rollout,omitempty"`
}

// ReadRingsView reads the device's saved status for the CLI.
func ReadRingsView(work string) (RingsView, error) {
	st, err := ReadStatus(work)
	if err != nil {
		return RingsView{}, err
	}
	if st.Ring == "" {
		return RingsView{}, errNoRings
	}
	return RingsView{Ring: st.Ring, Latest: st.Latest, State: st.State, Message: st.Message, Rollout: st.Rollout}, nil
}

// WriteRingSettings saves the owner's ring settings into the coordinator's
// state folder with the folder's owner, so the coordinator unit (the
// openscale user on Linux) can read what root wrote.
func WriteRingSettings(stateDir string, s rollout.Settings) error {
	if err := rollout.WriteSettings(stateDir, s); err != nil {
		return err
	}
	return matchOwner(filepath.Join(stateDir, rollout.SettingsFile), stateDir)
}
