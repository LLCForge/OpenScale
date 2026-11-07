// Package usage keeps monthly byte totals per key (#482, ADR-0153; meant
// to be shared with the exit node quota, #401). Only the month, an opaque
// key such as a device id and a byte count are kept: no flows, no
// destinations, no timestamps finer than the month. The current and the
// previous month are retained; older months are dropped on the next write.
package usage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"
)

// Limits of the counter and its file.
const (
	// DefaultMaxKeys bounds the keys of one month; further keys are added
	// to OtherKey so a flood of new keys cannot grow the memory.
	DefaultMaxKeys = 4096
	// MaxFileSize bounds the encoded counter.
	MaxFileSize = 1 << 20
	// OtherKey collects the bytes of keys beyond the limit.
	OtherKey = "_other"
	// monthsKept is the current month and the previous one.
	monthsKept = 2
	schema     = 1
	maxKeyLen  = 128
	monthForm  = "2006-01"
)

// Month is one calendar month (UTC) of totals.
type Month struct {
	Month string            `json:"month"`
	Bytes map[string]uint64 `json:"bytes"`
}

// Monthly is a set of monthly totals, safe for concurrent use.
type Monthly struct {
	mu      sync.Mutex
	maxKeys int
	months  map[string]map[string]uint64
	dirty   bool
}

// NewMonthly returns an empty counter; maxKeys <= 0 uses DefaultMaxKeys.
func NewMonthly(maxKeys int) *Monthly {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	return &Monthly{maxKeys: maxKeys, months: map[string]map[string]uint64{}}
}

// MonthOf returns the month label of t in UTC.
func MonthOf(t time.Time) string { return t.UTC().Format(monthForm) }

// Add counts n bytes for key in the month of now.
func (m *Monthly) Add(key string, n uint64, now time.Time) {
	if n == 0 || key == "" || len(key) > maxKeyLen {
		return
	}
	month := MonthOf(now)
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.months[month]
	if cur == nil {
		cur = map[string]uint64{}
		m.months[month] = cur
		m.pruneLocked()
	}
	if _, ok := cur[key]; !ok && len(cur) >= m.maxKeys {
		key = OtherKey
	}
	v := cur[key]
	if v > ^uint64(0)-n {
		cur[key] = ^uint64(0)
	} else {
		cur[key] = v + n
	}
	m.dirty = true
}

// pruneLocked keeps the newest monthsKept months.
func (m *Monthly) pruneLocked() {
	if len(m.months) <= monthsKept {
		return
	}
	keys := slices.Sorted(maps.Keys(m.months))
	for _, k := range keys[:len(keys)-monthsKept] {
		delete(m.months, k)
	}
	m.dirty = true
}

// Snapshot returns a copy of the months, oldest first.
func (m *Monthly) Snapshot() []Month {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Month, 0, len(m.months))
	for _, k := range slices.Sorted(maps.Keys(m.months)) {
		out = append(out, Month{Month: k, Bytes: maps.Clone(m.months[k])})
	}
	return out
}

// Get returns the total of key in month (zero when unknown).
func (m *Monthly) Get(month, key string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.months[month][key]
}

// Dirty reports whether there are changes since the last Encode or
// Decode.
func (m *Monthly) Dirty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dirty
}

type file struct {
	Schema int     `json:"schema"`
	Months []Month `json:"months"`
}

// Encode returns the counter as JSON and clears the dirty flag.
func (m *Monthly) Encode() ([]byte, error) {
	snap := m.Snapshot()
	data, err := json.Marshal(file{Schema: schema, Months: snap})
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, errors.New("usage counter is too large")
	}
	m.mu.Lock()
	m.dirty = false
	m.mu.Unlock()
	return data, nil
}

// Decode parses an encoded counter strictly. maxKeys <= 0 uses
// DefaultMaxKeys.
func Decode(data []byte, maxKeys int) (*Monthly, error) {
	if len(data) > MaxFileSize {
		return nil, errors.New("usage file is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("usage file: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("usage file: trailing data")
	}
	if f.Schema != schema {
		return nil, fmt.Errorf("usage file: unsupported schema %d", f.Schema)
	}
	m := NewMonthly(maxKeys)
	if len(f.Months) > monthsKept {
		return nil, errors.New("usage file: too many months")
	}
	for _, mo := range f.Months {
		if _, err := time.Parse(monthForm, mo.Month); err != nil || len(mo.Month) != len(monthForm) {
			return nil, fmt.Errorf("usage file: invalid month %q", mo.Month)
		}
		if _, dup := m.months[mo.Month]; dup {
			return nil, errors.New("usage file: duplicate month")
		}
		if len(mo.Bytes) > m.maxKeys+1 {
			return nil, errors.New("usage file: too many keys")
		}
		cur := make(map[string]uint64, len(mo.Bytes))
		for k, v := range mo.Bytes {
			if k == "" || len(k) > maxKeyLen {
				return nil, errors.New("usage file: invalid key")
			}
			cur[k] = v
		}
		m.months[mo.Month] = cur
	}
	return m, nil
}
