package adblock

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Allow once limits.
const (
	MaxAllowOnce        = 256
	MaxAllowOnceSpan    = 24 * time.Hour
	DefaultAllowOnceFor = 15 * time.Minute
)

// Reason explains a decision.
type Reason string

// Reasons.
const (
	ReasonNone      Reason = "none"       // not listed in an active category
	ReasonListed    Reason = "listed"     // blocked
	ReasonKeep      Reason = "keep"       // on the keep list (update domain)
	ReasonException Reason = "exception"  // owner's permanent exception
	ReasonOnce      Reason = "allow-once" // timed allow once
	ReasonNoEngine  Reason = "no-engine"  // nothing installed
)

// Decision is the verdict for one query.
type Decision struct {
	Blocked bool `json:"blocked"`
	// Category is the category that blocked (or would have blocked) the
	// name, 0 when none applies.
	Category Category `json:"category"`
	Reason   Reason   `json:"reason"`
}

// AllowOnce is a timed exception. Device "" covers every device.
type AllowOnce struct {
	Device string    `json:"device,omitempty"`
	Name   string    `json:"name"`
	Until  time.Time `json:"until"`
}

type onceKey struct{ device, name string }

type installed struct {
	m *Matcher
	p *compiledPolicy
}

// Engine decides queries; safe for concurrent use. The zero value is not
// usable; call NewEngine.
type Engine struct {
	cur atomic.Pointer[installed]

	mu   sync.Mutex
	once map[onceKey]time.Time

	queries  atomic.Uint64
	blocked  [5]atomic.Uint64
	excepted atomic.Uint64
	kept     atomic.Uint64

	top topRecorder
}

// NewEngine returns an engine with nothing installed (blocks nothing).
func NewEngine() *Engine {
	return &Engine{once: map[onceKey]time.Time{}}
}

// Install replaces the matcher and the policy atomically. Turning on
// operating system telemetry anywhere in the policy while m has such a
// list requires a keep list
// in m (ErrKeepListRequired).
func (e *Engine) Install(m *Matcher, p Policy) error {
	if m == nil {
		return errors.New("adblock: eşleştirici yok")
	}
	cp, err := p.compile()
	if err != nil {
		return err
	}
	if cp.used.Has(CategoryOSTelemetry) && m.Has(CategoryOSTelemetry) && m.keep == 0 {
		return ErrKeepListRequired
	}
	e.cur.Store(&installed{m: m, p: cp})
	return nil
}

// Decide returns the verdict for name asked by device with tags and
// counts it. Only counters are kept unless the owner turned on the timed
// top list (StartTop).
func (e *Engine) Decide(device string, tags []string, name string, now time.Time) Decision {
	e.queries.Add(1)
	in := e.cur.Load()
	if in == nil {
		return Decision{Reason: ReasonNoEngine}
	}
	cats := in.p.categoriesFor(device, tags)
	if cats == 0 {
		return Decision{Reason: ReasonNone}
	}
	n := queryName(name)
	hit, keep := in.m.Match(n)
	if keep {
		e.kept.Add(1)
		return Decision{Reason: ReasonKeep}
	}
	hit &= cats
	if hit == 0 {
		return Decision{Reason: ReasonNone}
	}
	c := hit.first()
	if in.p.excepted(device, n) {
		e.excepted.Add(1)
		return Decision{Category: c, Reason: ReasonException}
	}
	if e.onceAllowed(device, n, now) {
		e.excepted.Add(1)
		return Decision{Category: c, Reason: ReasonOnce}
	}
	e.blocked[c.index()].Add(1)
	e.top.record(n, now)
	return Decision{Blocked: true, Category: c, Reason: ReasonListed}
}

func (e *Engine) onceAllowed(device, n string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.once) == 0 {
		return false
	}
	keys := []string{""}
	if device != "" {
		keys = append(keys, device)
	}
	found := false
	eachSuffix(n, func(s string) bool {
		for _, d := range keys {
			k := onceKey{d, s}
			if until, ok := e.once[k]; ok {
				if now.Before(until) {
					found = true
					return false
				}
				delete(e.once, k)
			}
		}
		return true
	})
	return found
}

// AllowOnceFor lets name (and names below it) through on device ("" for
// every device) for d (DefaultAllowOnceFor when 0, at most
// MaxAllowOnceSpan).
func (e *Engine) AllowOnceFor(device, name string, d time.Duration, now time.Time) (AllowOnce, error) {
	if d == 0 {
		d = DefaultAllowOnceFor
	}
	if d < 0 || d > MaxAllowOnceSpan {
		return AllowOnce{}, fmt.Errorf("süre 0 ile %s arasında olmalı", MaxAllowOnceSpan)
	}
	if device != "" && !validKey(device) {
		return AllowOnce{}, fmt.Errorf("geçersiz cihaz adı: %q", device)
	}
	n, err := NormalizeName(name)
	if err != nil {
		return AllowOnce{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLocked(now)
	k := onceKey{device, n}
	if _, ok := e.once[k]; !ok && len(e.once) >= MaxAllowOnce {
		return AllowOnce{}, fmt.Errorf("en fazla %d süreli izin olabilir", MaxAllowOnce)
	}
	until := now.Add(d)
	e.once[k] = until
	return AllowOnce{Device: device, Name: n, Until: until}, nil
}

// RevokeAllowOnce removes a timed exception.
func (e *Engine) RevokeAllowOnce(device, name string) bool {
	n, err := NormalizeName(name)
	if err != nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	k := onceKey{device, n}
	_, ok := e.once[k]
	delete(e.once, k)
	return ok
}

// AllowOnces lists the timed exceptions still in force.
func (e *Engine) AllowOnces(now time.Time) []AllowOnce {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireLocked(now)
	out := make([]AllowOnce, 0, len(e.once))
	for k, u := range e.once {
		out = append(out, AllowOnce{Device: k.device, Name: k.name, Until: u})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Until.Equal(out[j].Until) {
			return out[i].Device+out[i].Name < out[j].Device+out[j].Name
		}
		return out[i].Until.Before(out[j].Until)
	})
	return out
}

func (e *Engine) expireLocked(now time.Time) {
	for k, u := range e.once {
		if !now.Before(u) {
			delete(e.once, k)
		}
	}
}

// Stats are counters only; no name is kept.
type Stats struct {
	Queries  uint64            `json:"queries"`
	Blocked  map[string]uint64 `json:"blocked"`
	Excepted uint64            `json:"excepted"`
	Kept     uint64            `json:"kept"`
	Lists    MatcherInfo       `json:"lists"`
}

// Stats reports the counters since the engine was created.
func (e *Engine) Stats() Stats {
	s := Stats{Queries: e.queries.Load(), Blocked: map[string]uint64{}, Excepted: e.excepted.Load(), Kept: e.kept.Load()}
	for i, c := range AllCategories {
		s.Blocked[c.String()] = e.blocked[i].Load()
	}
	if in := e.cur.Load(); in != nil {
		s.Lists = in.m.Info()
	}
	return s
}

// StartTop turns on the memory-only list of the most blocked names for d
// (at most MaxTopSpan); it returns when the list turns itself off.
func (e *Engine) StartTop(d time.Duration, now time.Time) (time.Time, error) {
	return e.top.start(d, now)
}

// StopTop turns the list off and forgets every name.
func (e *Engine) StopTop() { e.top.stop() }

// Top returns at most n of the most blocked names while the list is on.
func (e *Engine) Top(n int, now time.Time) ([]NameCount, time.Time) { return e.top.top(n, now) }
