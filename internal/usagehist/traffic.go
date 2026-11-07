// Package usagehist keeps two small local histories for the owner:
// hourly byte totals per device for 30 days (#505) and OpenScale's own
// processor, memory and battery cost over the last day (#516).
//
// Only totals are kept. The traffic history stores, per device name and
// hour, how many bytes went to and came from that device: no
// destinations, ports, flows or addresses. Nothing leaves the computer;
// the panel and the command line read it through the local API.
package usagehist

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Limits of the traffic history.
const (
	// RetainHours is how long hourly totals are kept.
	RetainHours = 30 * 24
	// MaxDevices bounds the devices tracked; further names are ignored so
	// a flood of renamed devices cannot grow the memory.
	MaxDevices = 1024
	// MaxFileSize bounds the encoded history.
	MaxFileSize = 8 << 20
	maxKeyLen   = 128
	schema      = 1
)

// ErrCorrupt is returned for a history file that is not valid.
var ErrCorrupt = errors.New("trafik geçmişi dosyası bozuk")

// Point is one hour of one device.
type Point struct {
	Hour time.Time `json:"hour"`
	Rx   uint64    `json:"rx"`
	Tx   uint64    `json:"tx"`
}

type counters struct{ rx, tx uint64 }

// Traffic is the hourly history, safe for concurrent use.
type Traffic struct {
	mu    sync.Mutex
	hours map[string]map[int64]counters // device -> unix hour -> totals
	last  map[string]counters           // last cumulative reading
	dirty bool
}

// NewTraffic returns an empty history.
func NewTraffic() *Traffic {
	return &Traffic{hours: map[string]map[int64]counters{}, last: map[string]counters{}}
}

func hourOf(t time.Time) int64 { return t.UTC().Unix() / 3600 }

func addSat(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// Observe takes a device's cumulative byte counters. The first reading
// of a device only sets the baseline; a counter that went down (the
// tunnel restarted) starts a new baseline from zero.
func (t *Traffic) Observe(device string, rx, tx uint64, now time.Time) {
	if device == "" || len(device) > maxKeyLen {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, seen := t.last[device]
	if !seen {
		if _, known := t.hours[device]; !known && len(t.hours) >= MaxDevices {
			return
		}
		if len(t.last) >= MaxDevices {
			return
		}
		t.last[device] = counters{rx, tx}
		return
	}
	t.last[device] = counters{rx, tx}
	dr, dt := rx-prev.rx, tx-prev.tx
	if rx < prev.rx {
		dr = rx
	}
	if tx < prev.tx {
		dt = tx
	}
	if dr == 0 && dt == 0 {
		return
	}
	m := t.hours[device]
	if m == nil {
		if len(t.hours) >= MaxDevices {
			return
		}
		m = map[int64]counters{}
		t.hours[device] = m
	}
	h := hourOf(now)
	c := m[h]
	m[h] = counters{addSat(c.rx, dr), addSat(c.tx, dt)}
	t.dirty = true
	t.pruneLocked(h)
}

// Forget drops the baselines of devices that are no longer peers, so the
// map of baselines stays bounded; their history stays.
func (t *Traffic) Forget(keep func(device string) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for d := range t.last {
		if !keep(d) {
			delete(t.last, d)
		}
	}
}

func (t *Traffic) pruneLocked(nowHour int64) {
	oldest := nowHour - RetainHours + 1
	for d, m := range t.hours {
		for h := range m {
			if h < oldest {
				delete(m, h)
				t.dirty = true
			}
		}
		if len(m) == 0 {
			delete(t.hours, d)
		}
	}
}

// Prune drops hours older than the retention.
func (t *Traffic) Prune(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(hourOf(now))
}

// Devices returns the devices with history, sorted.
func (t *Traffic) Devices() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.hours))
	for d := range t.hours {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// Series returns hours points ending with the current hour; hours without
// traffic are zero.
func (t *Traffic) Series(device string, hours int, now time.Time) []Point {
	hours = max(1, min(hours, RetainHours))
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.hours[device]
	end := hourOf(now)
	out := make([]Point, 0, hours)
	for h := end - int64(hours) + 1; h <= end; h++ {
		c := m[h]
		out = append(out, Point{Hour: time.Unix(h*3600, 0).UTC(), Rx: c.rx, Tx: c.tx})
	}
	return out
}

// Total returns a device's totals over the last hours.
func (t *Traffic) Total(device string, hours int, now time.Time) (rx, tx uint64) {
	for _, p := range t.Series(device, hours, now) {
		rx, tx = addSat(rx, p.Rx), addSat(tx, p.Tx)
	}
	return rx, tx
}

// Dirty reports unsaved changes.
func (t *Traffic) Dirty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dirty
}

// file is the encoded history: per device a list of [hour, rx, tx].
type file struct {
	Schema  int                    `json:"schema"`
	Devices map[string][][3]uint64 `json:"devices"`
}

// Encode returns the history and clears the dirty mark.
func (t *Traffic) Encode() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := file{Schema: schema, Devices: map[string][][3]uint64{}}
	for d, m := range t.hours {
		rows := make([][3]uint64, 0, len(m))
		for h, c := range m {
			rows = append(rows, [3]uint64{uint64(h), c.rx, c.tx})
		}
		slices.SortFunc(rows, func(a, b [3]uint64) int { return cmp.Compare(a[0], b[0]) })
		f.Devices[d] = rows
	}
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("trafik geçmişi %d baytı aşıyor", MaxFileSize)
	}
	t.dirty = false
	return data, nil
}

// DecodeTraffic reads an encoded history; hours older than the retention
// at now are dropped.
func DecodeTraffic(data []byte, now time.Time) (*Traffic, error) {
	if len(data) > MaxFileSize {
		return nil, ErrCorrupt
	}
	var f file
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Schema != schema || len(f.Devices) > MaxDevices {
		return nil, ErrCorrupt
	}
	t := NewTraffic()
	nowHour := hourOf(now)
	for d, rows := range f.Devices {
		if d == "" || len(d) > maxKeyLen || len(rows) > RetainHours*2 {
			return nil, ErrCorrupt
		}
		m := map[int64]counters{}
		for _, r := range rows {
			h := int64(r[0])
			if h < 0 || h > nowHour+1 {
				return nil, ErrCorrupt
			}
			m[h] = counters{r[1], r[2]}
		}
		t.hours[d] = m
	}
	t.pruneLocked(nowHour)
	t.dirty = false
	return t, nil
}
