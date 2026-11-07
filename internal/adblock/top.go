package adblock

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Top list limits: the list is off by default, holds at most MaxTopNames
// names in memory only and turns itself off after at most MaxTopSpan.
const (
	MaxTopSpan  = time.Hour
	MaxTopNames = 1000
)

// NameCount is one entry of the top list.
type NameCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type topRecorder struct {
	mu      sync.Mutex
	until   time.Time
	counts  map[string]uint64
	dropped uint64
}

func (t *topRecorder) start(d time.Duration, now time.Time) (time.Time, error) {
	if d <= 0 || d > MaxTopSpan {
		return time.Time{}, fmt.Errorf("süre 0 ile %s arasında olmalı", MaxTopSpan)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.until = now.Add(d)
	if t.counts == nil {
		t.counts = map[string]uint64{}
	}
	return t.until, nil
}

func (t *topRecorder) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.until, t.counts, t.dropped = time.Time{}, nil, 0
}

// activeLocked forgets everything once the window has passed.
func (t *topRecorder) activeLocked(now time.Time) bool {
	if t.counts == nil {
		return false
	}
	if !now.Before(t.until) {
		t.until, t.counts, t.dropped = time.Time{}, nil, 0
		return false
	}
	return true
}

func (t *topRecorder) record(n string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.activeLocked(now) {
		return
	}
	if _, ok := t.counts[n]; !ok && len(t.counts) >= MaxTopNames {
		t.dropped++
		return
	}
	t.counts[n]++
}

func (t *topRecorder) top(n int, now time.Time) ([]NameCount, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.activeLocked(now) || n <= 0 {
		return nil, t.until
	}
	out := make([]NameCount, 0, len(t.counts))
	for k, v := range t.counts {
		out = append(out, NameCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out, t.until
}
