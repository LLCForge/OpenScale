// Package rollout stages automatic updates in rings (#827, ADR-0235).
//
// Devices are put into rings with the tags of the signed network document:
// "ring-canary", "ring-early" and, the default for every device without one
// of them, "ring-main" (tags are DNS labels, so the rings are written with a
// dash). A new release reaches the canary ring first; the early ring opens
// once a canary device has run it healthily for the canary soak time, the
// main ring once an early device has done the same for the early soak time.
// A rollback reported on the release halts it for every ring.
//
// Trust. The coordinator computes the progress and carries it in its
// release announcement, but it is untrusted: a device learns its own ring
// from its own signed document, never from the coordinator, and keeps a
// local floor (the soak times since it first saw the release, for rings
// that have members in that document). A lying coordinator can delay a
// release or open a ring early; opening early only installs early, the
// release signature is verified as always.
package rollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// Rings.
const (
	RingCanary = "canary"
	RingEarly  = "early"
	RingMain   = "main"
)

// Tags that put a device into a ring.
const (
	TagCanary = "ring-canary"
	TagEarly  = "ring-early"
	TagMain   = "ring-main"
)

// Rings lists the rings in order.
var Rings = []string{RingCanary, RingEarly, RingMain}

// Soak limits and defaults.
const (
	DefaultCanarySoak = 6 * time.Hour
	DefaultEarlySoak  = 24 * time.Hour
	MinSoak           = time.Hour
	MaxSoak           = 30 * 24 * time.Hour
)

// Wire limits.
const (
	maxReport       = 512
	maxAnnouncement = 400
	maxVersion      = 64
	// maxTracked bounds the devices a coordinator tracks (and a count).
	maxTracked  = 4096
	wireVersion = 1
)

// RingOf returns the ring of a device with tags; the earliest ring wins
// when a device carries several ring tags.
func RingOf(tags []string) string {
	switch {
	case slices.Contains(tags, TagCanary):
		return RingCanary
	case slices.Contains(tags, TagEarly):
		return RingEarly
	}
	return RingMain
}

// Index returns the position of ring (0 canary, 1 early, 2 main) or -1.
func Index(ring string) int { return slices.Index(Rings, ring) }

// Duration is a time.Duration written as text ("6h0m0s").
type Duration time.Duration

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ClampSoak bounds a soak time taken from an untrusted announcement.
func ClampSoak(d time.Duration) time.Duration { return min(max(d, MinSoak), MaxSoak) }

// Report is what a device sends with its announcement request (in the
// request's Data): the version it runs, whether its service is healthy and
// the version whose installation it last rolled back.
type Report struct {
	V          int    `json:"v"`
	Run        string `json:"run"`
	OK         bool   `json:"ok"`
	RolledBack string `json:"rb,omitempty"`
}

// Encode returns the report for the request's Data.
func (r Report) Encode() ([]byte, error) {
	r.V = wireVersion
	if !validVersion(r.Run) || (r.RolledBack != "" && !validVersion(r.RolledBack)) {
		return nil, errors.New("rollout report: invalid version")
	}
	return json.Marshal(r)
}

// DecodeReport parses a device report strictly.
func DecodeReport(data []byte) (Report, error) {
	var r Report
	if len(data) == 0 || len(data) > maxReport {
		return r, errors.New("rollout report: size")
	}
	if err := decodeStrict(data, &r); err != nil {
		return Report{}, fmt.Errorf("rollout report: %w", err)
	}
	if r.V != wireVersion || !validVersion(r.Run) || (r.RolledBack != "" && !validVersion(r.RolledBack)) {
		return Report{}, errors.New("rollout report: invalid")
	}
	return r, nil
}

// RingCount is what the coordinator knows of one ring for the release.
type RingCount struct {
	Ring string `json:"ring"`
	// Members carry the ring's tag in the document; Updated reported the
	// release; Healthy reported it running healthily; RolledBack reported a
	// rollback of it.
	Members    int `json:"members"`
	Updated    int `json:"updated"`
	Healthy    int `json:"healthy"`
	RolledBack int `json:"rolledBack"`
}

// Announcement is the coordinator's progress for the publication its
// TypeRelease reply announces (it travels in that reply's Data, so it is
// bound to the reply's Digest). Devices treat it as untrusted.
type Announcement struct {
	// Open is the latest ring allowed to install.
	Open string `json:"open"`
	// Halted stops the release in every ring; HaltRing is the ring in
	// which a rollback was reported.
	Halted   bool   `json:"halted,omitempty"`
	HaltRing string `json:"haltRing,omitempty"`
	// CanarySoak and EarlySoak are the owner's settings.
	CanarySoak time.Duration `json:"canarySoak"`
	EarlySoak  time.Duration `json:"earlySoak"`
	// Since is when the coordinator first announced the release; EarlyAt
	// and MainAt when it opened those rings.
	Since   time.Time   `json:"since"`
	EarlyAt time.Time   `json:"earlyAt,omitzero"`
	MainAt  time.Time   `json:"mainAt,omitzero"`
	Rings   []RingCount `json:"rings,omitempty"`
}

// wireAnnouncement is the compact form: a control datagram is at most
// MaxDatagram (1200) bytes and the reply carries the release fields too.
type wireAnnouncement struct {
	V        int      `json:"v"`
	Open     int      `json:"o"`
	Halted   bool     `json:"h,omitempty"`
	HaltRing int      `json:"hr,omitempty"`
	Canary   int64    `json:"cs"`
	Early    int64    `json:"es"`
	Since    int64    `json:"s"`
	EarlyAt  int64    `json:"ea,omitempty"`
	MainAt   int64    `json:"ma,omitempty"`
	Rings    [][4]int `json:"n,omitempty"`
}

func unixSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(s int64) time.Time {
	if s <= 0 {
		return time.Time{}
	}
	return time.Unix(s, 0).UTC()
}

// Encode returns the announcement for the reply's Data.
func (a Announcement) Encode() ([]byte, error) {
	w := wireAnnouncement{
		V: wireVersion, Open: Index(a.Open), Halted: a.Halted, HaltRing: max(Index(a.HaltRing), 0),
		Canary: int64(a.CanarySoak / time.Second), Early: int64(a.EarlySoak / time.Second),
		Since: unixSeconds(a.Since), EarlyAt: unixSeconds(a.EarlyAt), MainAt: unixSeconds(a.MainAt),
	}
	if w.Open < 0 {
		return nil, errors.New("rollout announcement: invalid ring")
	}
	for _, r := range a.Rings {
		if Index(r.Ring) != len(w.Rings) {
			return nil, errors.New("rollout announcement: rings out of order")
		}
		w.Rings = append(w.Rings, [4]int{r.Members, r.Updated, r.Healthy, r.RolledBack})
	}
	data, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(data) > maxAnnouncement {
		return nil, errors.New("rollout announcement too large")
	}
	return data, nil
}

// DecodeAnnouncement parses the coordinator's progress strictly.
func DecodeAnnouncement(data []byte) (Announcement, error) {
	var w wireAnnouncement
	if len(data) == 0 || len(data) > maxAnnouncement {
		return Announcement{}, errors.New("rollout announcement: size")
	}
	if err := decodeStrict(data, &w); err != nil {
		return Announcement{}, fmt.Errorf("rollout announcement: %w", err)
	}
	const maxSeconds = int64(10 * MaxSoak / time.Second)
	if w.V != wireVersion || w.Open < 0 || w.Open >= len(Rings) || w.HaltRing < 0 || w.HaltRing >= len(Rings) ||
		w.Canary < 0 || w.Canary > maxSeconds || w.Early < 0 || w.Early > maxSeconds ||
		w.Since < 0 || w.EarlyAt < 0 || w.MainAt < 0 || len(w.Rings) > len(Rings) {
		return Announcement{}, errors.New("rollout announcement: invalid")
	}
	a := Announcement{
		Open: Rings[w.Open], Halted: w.Halted,
		CanarySoak: time.Duration(w.Canary) * time.Second, EarlySoak: time.Duration(w.Early) * time.Second,
		Since: fromUnix(w.Since), EarlyAt: fromUnix(w.EarlyAt), MainAt: fromUnix(w.MainAt),
	}
	if w.Halted {
		a.HaltRing = Rings[w.HaltRing]
	}
	for i, n := range w.Rings {
		for _, v := range n {
			if v < 0 || v > maxTracked {
				return Announcement{}, errors.New("rollout announcement: invalid ring")
			}
		}
		a.Rings = append(a.Rings, RingCount{Ring: Rings[i], Members: n[0], Updated: n[1], Healthy: n[2], RolledBack: n[3]})
	}
	return a, nil
}

func validVersion(v string) bool {
	if v == "" || len(v) > maxVersion {
		return false
	}
	for _, r := range v {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
