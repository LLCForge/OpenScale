package rollout

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Coordinator side: the owner's settings and the progress of the current
// publication, both in the coordinator's state directory.

// Files in the coordinator's state directory.
const (
	// SettingsFile is written by "openscale update rings set/resume".
	SettingsFile = "release-rings.json"
	// StateFile is the progress the coordinator keeps.
	StateFile = "release-rollout.json"
)

const (
	settingsSchema = 1
	stateSchema    = 1
	maxSettings    = 4 << 10
	maxState       = 1 << 20
	// settingsEvery is how often the tracker reads SettingsFile again.
	settingsEvery = time.Minute
	// saveEvery bounds writes that only refresh report times.
	saveEvery = time.Minute
)

// Settings are the owner's ring settings.
type Settings struct {
	Schema     int      `json:"schema"`
	CanarySoak Duration `json:"canarySoak"`
	EarlySoak  Duration `json:"earlySoak"`
	// ResumeDigest and ResumedAt lift a halt of that publication: only
	// rollbacks reported after ResumedAt halt it again.
	ResumeDigest string    `json:"resumeDigest,omitempty"`
	ResumedAt    time.Time `json:"resumedAt,omitzero"`
}

// DefaultSettings are used while no SettingsFile exists.
func DefaultSettings() Settings {
	return Settings{Schema: settingsSchema, CanarySoak: Duration(DefaultCanarySoak), EarlySoak: Duration(DefaultEarlySoak)}
}

// Validate checks the soak times.
func (s Settings) Validate() error {
	for _, d := range []Duration{s.CanarySoak, s.EarlySoak} {
		if time.Duration(d) < MinSoak || time.Duration(d) > MaxSoak {
			return fmt.Errorf("bekleme süresi %s ile %s arasında olmalı", MinSoak, MaxSoak)
		}
	}
	return nil
}

// ReadSettings returns the settings; a missing file gives the defaults.
func ReadSettings(stateDir string) (Settings, error) {
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, SettingsFile), maxSettings)
	if errors.Is(err, fs.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return DefaultSettings(), err
	}
	var s Settings
	if err := decodeStrict(data, &s); err != nil || s.Schema != settingsSchema || s.Validate() != nil {
		return DefaultSettings(), fmt.Errorf("%s bozuk", SettingsFile)
	}
	return s, nil
}

// WriteSettings saves the settings (owner, on the coordinator host).
func WriteSettings(stateDir string, s Settings) error {
	s.Schema = settingsSchema
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(stateDir, SettingsFile), data)
}

// DeviceRecord is what the coordinator saw of one device for the release.
// First and Last are coordinator times of the first and the latest report
// of the release version; the soak is measured between them, so neither a
// device clock nor a single report opens a ring.
type DeviceRecord struct {
	Ring       string    `json:"ring"`
	Version    string    `json:"version"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	OK         bool      `json:"ok"`
	RolledBack bool      `json:"rolledBack,omitempty"`
	RolledAt   time.Time `json:"rolledAt,omitzero"`
}

// State is the progress of the current publication (StateFile).
type State struct {
	Schema   int                      `json:"schema"`
	Digest   string                   `json:"digest"`
	Version  string                   `json:"version"`
	Since    time.Time                `json:"since"`
	EarlyAt  time.Time                `json:"earlyAt,omitzero"`
	MainAt   time.Time                `json:"mainAt,omitzero"`
	Halted   bool                     `json:"halted,omitempty"`
	HaltRing string                   `json:"haltRing,omitempty"`
	HaltedAt time.Time                `json:"haltedAt,omitzero"`
	Devices  map[string]*DeviceRecord `json:"devices"`
	// Announcement is the last computed progress, for the owner's CLI.
	Announcement *Announcement `json:"announcement,omitempty"`
}

// ReadState returns the saved progress (owner's CLI).
func ReadState(stateDir string) (State, error) {
	var st State
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, StateFile), maxState)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil || st.Schema != stateSchema {
		return State{}, fmt.Errorf("%s bozuk", StateFile)
	}
	return st, nil
}

// Member is one device of the document with its ring.
type Member struct {
	ID   string
	Ring string
}

// Tracker keeps the progress on the coordinator.
type Tracker struct {
	dir string
	now func() time.Time

	mu        sync.Mutex
	st        State
	set       Settings
	setRead   time.Time
	saved     time.Time
	saveError string
	// Logf reports state changes; nil discards them.
	Logf func(format string, args ...any)
}

// NewTracker loads the saved progress from stateDir; an empty stateDir
// keeps it in memory only.
func NewTracker(stateDir string, now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	t := &Tracker{dir: stateDir, now: now, set: DefaultSettings()}
	if stateDir != "" {
		if st, err := ReadState(stateDir); err == nil && st.Devices != nil {
			t.st = st
		}
	}
	return t
}

func (t *Tracker) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	}
}

func (t *Tracker) settings(now time.Time) Settings {
	if t.dir != "" && (t.setRead.IsZero() || now.Sub(t.setRead) >= settingsEvery || now.Before(t.setRead)) {
		s, err := ReadSettings(t.dir)
		if err != nil {
			t.logf("ring settings unreadable, using defaults: %v", err)
		}
		t.set, t.setRead = s, now
	}
	return t.set
}

// Observe records a device's report (rep may be nil) for the publication
// (digest, version) and returns the progress to announce. members lists
// every device of the current document with its ring; deviceID is the
// reporting device, "" for none.
func (t *Tracker) Observe(digest, version string, members []Member, deviceID string, rep *Report) Announcement {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	set := t.settings(now)
	changed, urgent := false, false
	if t.st.Digest != digest || t.st.Devices == nil {
		t.st = State{Schema: stateSchema, Digest: digest, Version: version, Since: now, Devices: map[string]*DeviceRecord{}}
		changed, urgent = true, true
		t.logf("release rollout started: %s", version)
	}
	ringOf := make(map[string]string, len(members))
	for _, m := range members {
		ringOf[m.ID] = m.Ring
	}
	// Forget devices that left the document.
	for id := range t.st.Devices {
		if _, ok := ringOf[id]; !ok {
			delete(t.st.Devices, id)
			changed = true
		}
	}
	if ring, ok := ringOf[deviceID]; ok && rep != nil {
		c, u := t.record(deviceID, ring, version, rep, now)
		changed, urgent = changed || c, urgent || u
	}
	a := t.compute(set, members, now)
	if a.Halted != t.st.Halted || !a.EarlyAt.Equal(t.st.EarlyAt) || !a.MainAt.Equal(t.st.MainAt) {
		changed, urgent = true, true
	}
	t.st.Halted, t.st.HaltRing, t.st.EarlyAt, t.st.MainAt = a.Halted, a.HaltRing, a.EarlyAt, a.MainAt
	if a.Halted && t.st.HaltedAt.IsZero() {
		t.st.HaltedAt = now
		t.logf("release rollout halted: %s (rollback in the %s ring)", version, a.HaltRing)
	}
	if !a.Halted {
		t.st.HaltedAt = time.Time{}
	}
	ac := a
	t.st.Announcement = &ac
	if changed && (urgent || now.Sub(t.saved) >= saveEvery) {
		t.save(now)
	}
	return a
}

// record folds one report in; it returns whether anything changed and
// whether that must be saved at once.
func (t *Tracker) record(id, ring, version string, rep *Report, now time.Time) (bool, bool) {
	rec, ok := t.st.Devices[id]
	if !ok {
		if len(t.st.Devices) >= maxTracked {
			return false, false
		}
		rec = &DeviceRecord{}
		t.st.Devices[id] = rec
	}
	urgent := false
	rec.Ring = ring
	if rep.RolledBack == version && !rec.RolledBack {
		rec.RolledBack, rec.RolledAt, urgent = true, now, true
	}
	if rep.Run != version {
		// Still on the old version (or rolled back to it).
		rec.Version, rec.OK = rep.Run, rep.OK
		return true, urgent
	}
	if rec.Version != version {
		rec.Version, rec.First, urgent = version, now, true
	}
	if rec.OK != rep.OK {
		urgent = true
		if rep.OK {
			// A device healthy again starts its soak over.
			rec.First = now
		}
	}
	rec.OK, rec.Last = rep.OK, now
	return true, urgent
}

func (t *Tracker) compute(set Settings, members []Member, now time.Time) Announcement {
	a := Announcement{
		Open:       RingCanary,
		CanarySoak: time.Duration(set.CanarySoak), EarlySoak: time.Duration(set.EarlySoak),
		Since: t.st.Since, EarlyAt: t.st.EarlyAt, MainAt: t.st.MainAt,
	}
	counts := map[string]*RingCount{}
	for _, r := range Rings {
		counts[r] = &RingCount{Ring: r}
	}
	blocked := map[string]bool{}
	passed := map[string]bool{}
	resumed := set.ResumeDigest == t.st.Digest
	var haltBy string
	for _, m := range members {
		c := counts[m.Ring]
		if c == nil {
			continue
		}
		c.Members++
		rec := t.st.Devices[m.ID]
		if rec == nil {
			continue
		}
		if rec.RolledBack && (!resumed || rec.RolledAt.After(set.ResumedAt)) {
			c.RolledBack++
			if haltBy == "" {
				haltBy = m.Ring
			}
		}
		if rec.Version != t.st.Version {
			continue
		}
		c.Updated++
		if !rec.OK {
			blocked[m.Ring] = true
			continue
		}
		c.Healthy++
		soak := time.Duration(set.CanarySoak)
		if m.Ring == RingEarly {
			soak = time.Duration(set.EarlySoak)
		}
		if rec.Last.Sub(rec.First) >= soak {
			passed[m.Ring] = true
		}
	}
	ringPassed := func(r string) bool {
		return counts[r].Members == 0 || (passed[r] && !blocked[r])
	}
	if a.EarlyAt.IsZero() && ringPassed(RingCanary) {
		a.EarlyAt = now
	}
	if !a.EarlyAt.IsZero() {
		a.Open = RingEarly
		if a.MainAt.IsZero() && ringPassed(RingEarly) {
			a.MainAt = now
		}
	}
	if !a.MainAt.IsZero() {
		a.Open = RingMain
	}
	if haltBy != "" {
		a.Halted, a.HaltRing = true, haltBy
	}
	for _, r := range Rings {
		a.Rings = append(a.Rings, *counts[r])
	}
	return a
}

func (t *Tracker) save(now time.Time) {
	if t.dir == "" {
		return
	}
	data, err := json.Marshal(t.st)
	if err == nil {
		err = securefile.Replace(filepath.Join(t.dir, StateFile), data)
	}
	t.saved = now
	if err != nil {
		if msg := err.Error(); msg != t.saveError {
			t.saveError = msg
			t.logf("release rollout state not saved: %v", err)
		}
		return
	}
	t.saveError = ""
}
