// Package notify delivers the owner's own notifications (ADR-0216): service
// down, device offline, a new LAN device, an intrusion pattern, a full
// disk, the weekly network report. It is off by default and has no
// built-in destination: every channel is an address the owner wrote into
// the configuration (ADR-0008).
//
// Channels are a desktop notification on the owner's own devices (carried
// through the tunnel by the caller), ntfy, Gotify, Matrix and SMTP e-mail.
// The Dispatcher in front of them suppresses repeats, holds low priority
// messages during quiet hours and limits each channel's rate, so a flapping
// service never floods the owner's phone.
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Priority orders messages. Channels have a minimum priority; quiet hours
// hold everything below PriorityHigh.
type Priority int

// Priorities.
const (
	PriorityLow    Priority = 1
	PriorityNormal Priority = 2
	PriorityHigh   Priority = 3
	PriorityUrgent Priority = 4
)

// String returns the configuration name of p.
func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "low"
	case PriorityNormal:
		return "normal"
	case PriorityHigh:
		return "high"
	case PriorityUrgent:
		return "urgent"
	default:
		return "unknown"
	}
}

// ParsePriority parses a configuration name; empty means normal.
func ParsePriority(s string) (Priority, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return PriorityLow, nil
	case "", "normal":
		return PriorityNormal, nil
	case "high":
		return PriorityHigh, nil
	case "urgent":
		return PriorityUrgent, nil
	default:
		return 0, fmt.Errorf("bilinmeyen öncelik %q (low, normal, high, urgent)", s)
	}
}

// Limits of a message.
const (
	MaxTitle = 120
	MaxBody  = 4000
	maxKey   = 200
)

// Message is one notification. It carries names chosen by the owner
// (devices, services) and counts; callers must not put addresses, MAC
// addresses or visited domains into it.
type Message struct {
	// Kind is a stable machine name such as "service_down".
	Kind     string
	Title    string
	Body     string
	Priority Priority
	// Subject is what the message is about (a device or service name);
	// with Kind it forms the default repeat-suppression key.
	Subject string
	// Key overrides the repeat-suppression key.
	Key string
	At  time.Time
	// HTML is an optional HTML body for e-mail (the weekly report).
	HTML string
}

func (m Message) dedupeKey() string {
	if m.Key != "" {
		return truncate(m.Key, maxKey)
	}
	return truncate(m.Kind+"|"+m.Subject, maxKey)
}

// normalized trims and bounds the message's text.
func (m Message) normalized() Message {
	m.Title = truncate(cleanLine(m.Title), MaxTitle)
	m.Body = truncate(strings.ToValidUTF8(m.Body, "?"), MaxBody)
	if m.Priority < PriorityLow || m.Priority > PriorityUrgent {
		m.Priority = PriorityNormal
	}
	return m
}

// cleanLine removes control characters so a title can never inject a
// header line into an HTTP request or an e-mail.
func cleanLine(s string) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Channel delivers messages to one destination.
type Channel interface {
	// Name is the owner's label of the channel.
	Name() string
	Send(ctx context.Context, m Message) error
}

// Route binds a channel to its delivery limits.
type Route struct {
	Channel Channel
	// MinPriority drops messages below it (zero means low).
	MinPriority Priority
	// MaxPerHour limits deliveries (zero means DefaultMaxPerHour).
	MaxPerHour int
}

// QuietHours hold messages below PriorityHigh between Start and End (local
// minutes after midnight in Location); End before Start spans midnight.
type QuietHours struct {
	Start, End int
	Location   *time.Location
}

// Contains reports whether t falls inside the quiet hours.
func (q *QuietHours) Contains(t time.Time) bool {
	if q == nil || q.Start == q.End {
		return false
	}
	loc := q.Location
	if loc == nil {
		loc = time.Local
	}
	lt := t.In(loc)
	m := lt.Hour()*60 + lt.Minute()
	if q.Start < q.End {
		return m >= q.Start && m < q.End
	}
	return m >= q.Start || m < q.End
}

// ParseClock parses "HH:MM" into minutes after midnight.
func ParseClock(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("saat SS:DD biçiminde olmalı: %q", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// Dispatcher defaults.
const (
	DefaultDedupeWindow = 30 * time.Minute
	DefaultMaxPerHour   = 30
	maxHeld             = 100
	maxDedupeKeys       = 4096
	maxRoutes           = 16
)

// ErrNoChannels is returned when no channel is configured.
var ErrNoChannels = errors.New("bildirim kanalı yapılandırılmamış")

// Outcome is what happened to a message on one channel.
type Outcome string

// Outcomes.
const (
	Sent        Outcome = "sent"
	Failed      Outcome = "failed"
	Suppressed  Outcome = "suppressed"   // repeat within the window
	Held        Outcome = "held"         // quiet hours, sent later
	BelowMin    Outcome = "below_min"    // channel's minimum priority
	RateLimited Outcome = "rate_limited" // channel's hourly limit
)

// Result reports one delivery attempt.
type Result struct {
	Channel string
	Outcome Outcome
	Err     error
}

// Dispatcher fans messages out to routes. It is safe for concurrent use.
type Dispatcher struct {
	routes []Route
	window time.Duration
	quiet  *QuietHours

	mu       sync.Mutex
	last     map[string]time.Time
	repeats  map[string]int
	held     []Message
	sentHour map[int][]time.Time
}

// DispatcherOptions configures a Dispatcher.
type DispatcherOptions struct {
	// DedupeWindow suppresses a message whose key was delivered within it
	// (zero means DefaultDedupeWindow, negative disables suppression).
	DedupeWindow time.Duration
	Quiet        *QuietHours
}

// NewDispatcher returns a dispatcher for routes.
func NewDispatcher(routes []Route, opts DispatcherOptions) (*Dispatcher, error) {
	if len(routes) == 0 {
		return nil, ErrNoChannels
	}
	if len(routes) > maxRoutes {
		return nil, fmt.Errorf("en fazla %d bildirim kanalı olabilir", maxRoutes)
	}
	for _, r := range routes {
		if r.Channel == nil {
			return nil, errors.New("bildirim kanalı boş")
		}
	}
	w := opts.DedupeWindow
	if w == 0 {
		w = DefaultDedupeWindow
	}
	return &Dispatcher{
		routes:   append([]Route(nil), routes...),
		window:   w,
		quiet:    opts.Quiet,
		last:     map[string]time.Time{},
		repeats:  map[string]int{},
		sentHour: map[int][]time.Time{},
	}, nil
}

// Notify delivers m to every route and reports each outcome. It blocks
// while channels deliver; callers run it outside hot paths.
func (d *Dispatcher) Notify(ctx context.Context, m Message) []Result {
	if m.At.IsZero() {
		m.At = time.Now()
	}
	m = m.normalized()
	now := m.At

	d.mu.Lock()
	key := m.dedupeKey()
	if d.window > 0 {
		if t, ok := d.last[key]; ok && now.Sub(t) < d.window && now.Sub(t) >= 0 {
			d.repeats[key]++
			d.mu.Unlock()
			return []Result{{Channel: "*", Outcome: Suppressed}}
		}
		if n := d.repeats[key]; n > 0 {
			m.Body = strings.TrimSpace(m.Body + fmt.Sprintf("\n(Bu bildirim son pencerede %d kez daha oluştu.)", n))
			delete(d.repeats, key)
		}
		d.remember(key, now)
	}
	if m.Priority < PriorityHigh && d.quiet.Contains(now) {
		if len(d.held) < maxHeld {
			d.held = append(d.held, m)
		}
		d.mu.Unlock()
		return []Result{{Channel: "*", Outcome: Held}}
	}
	d.mu.Unlock()
	return d.deliver(ctx, m)
}

func (d *Dispatcher) remember(key string, now time.Time) {
	if len(d.last) >= maxDedupeKeys {
		for k, t := range d.last {
			if now.Sub(t) >= d.window {
				delete(d.last, k)
			}
		}
		if len(d.last) >= maxDedupeKeys {
			clear(d.last)
		}
	}
	d.last[key] = now
}

// Flush sends the messages held during quiet hours as one digest once the
// quiet hours are over. It returns nil when nothing is due.
func (d *Dispatcher) Flush(ctx context.Context, now time.Time) []Result {
	d.mu.Lock()
	if len(d.held) == 0 || d.quiet.Contains(now) {
		d.mu.Unlock()
		return nil
	}
	held := d.held
	d.held = nil
	d.mu.Unlock()
	if len(held) == 1 {
		return d.deliver(ctx, held[0])
	}
	var b strings.Builder
	top := PriorityLow
	for _, m := range held {
		fmt.Fprintf(&b, "- %s %s\n", m.At.Format("15:04"), m.Title)
		if m.Priority > top {
			top = m.Priority
		}
	}
	return d.deliver(ctx, Message{
		Kind:     "quiet_digest",
		Title:    fmt.Sprintf("Sessiz saatlerde %d bildirim birikti", len(held)),
		Body:     b.String(),
		Priority: top,
		At:       now,
	}.normalized())
}

// HeldCount reports the messages waiting for the end of quiet hours.
func (d *Dispatcher) HeldCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.held)
}

func (d *Dispatcher) deliver(ctx context.Context, m Message) []Result {
	out := make([]Result, 0, len(d.routes))
	for i, r := range d.routes {
		name := r.Channel.Name()
		minP := r.MinPriority
		if minP == 0 {
			minP = PriorityLow
		}
		if m.Priority < minP {
			out = append(out, Result{Channel: name, Outcome: BelowMin})
			continue
		}
		if !d.takeRate(i, r.MaxPerHour, m.At) {
			out = append(out, Result{Channel: name, Outcome: RateLimited})
			continue
		}
		if err := r.Channel.Send(ctx, m); err != nil {
			out = append(out, Result{Channel: name, Outcome: Failed, Err: err})
			continue
		}
		out = append(out, Result{Channel: name, Outcome: Sent})
	}
	return out
}

func (d *Dispatcher) takeRate(route, limit int, now time.Time) bool {
	if limit <= 0 {
		limit = DefaultMaxPerHour
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	kept := d.sentHour[route][:0]
	for _, t := range d.sentHour[route] {
		if now.Sub(t) < time.Hour && now.Sub(t) >= 0 {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		d.sentHour[route] = kept
		return false
	}
	d.sentHour[route] = append(kept, now)
	return true
}
