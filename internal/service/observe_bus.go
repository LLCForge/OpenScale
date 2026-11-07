package service

import (
	"context"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

// EventBus is the local event stream (F-182, ADR-0105): every event gets a
// sequence number, the newest are kept in a bounded ring and readers wait
// for new ones instead of polling. It lives in memory only.
type EventBus struct {
	mu   sync.Mutex
	seq  uint64
	ring []panel.StreamEvent
	next int
	full bool
	wake chan struct{}
}

const (
	// busSize bounds the events kept for readers that fall behind.
	busSize = 512
	// maxBatch bounds the events of one answer.
	maxBatch = 200
)

// NewEventBus returns an empty bus.
func NewEventBus() *EventBus {
	return &EventBus{ring: make([]panel.StreamEvent, busSize), wake: make(chan struct{})}
}

// Publish adds an event and wakes the readers. Seq is assigned here.
func (b *EventBus) Publish(ev panel.StreamEvent) panel.StreamEvent {
	b.mu.Lock()
	b.seq++
	ev.Seq = b.seq
	b.ring[b.next] = ev
	b.next = (b.next + 1) % len(b.ring)
	if b.next == 0 {
		b.full = true
	}
	close(b.wake)
	b.wake = make(chan struct{})
	b.mu.Unlock()
	return ev
}

// Seq is the sequence number of the newest event.
func (b *EventBus) Seq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

// collect returns the events after since, oldest first. Called with b.mu
// held.
func (b *EventBus) collect(since uint64) []panel.StreamEvent {
	n := b.next
	if b.full {
		n = len(b.ring)
	}
	out := []panel.StreamEvent{}
	for i := n; i >= 1; i-- {
		ev := b.ring[(b.next-i+len(b.ring))%len(b.ring)]
		if ev.Seq > since {
			out = append(out, ev)
			if len(out) == maxBatch {
				break
			}
		}
	}
	return out
}

// Since returns the events after since, waiting up to wait for one. A
// since newer than the bus (the service restarted) starts over.
func (b *EventBus) Since(ctx context.Context, since uint64, wait time.Duration) ([]panel.StreamEvent, uint64) {
	var timer <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}
	for {
		b.mu.Lock()
		if since > b.seq {
			since = 0
		}
		evs := b.collect(since)
		next := b.seq
		if len(evs) > 0 {
			next = evs[len(evs)-1].Seq
		}
		wake := b.wake
		b.mu.Unlock()
		if len(evs) > 0 || timer == nil {
			return evs, next
		}
		select {
		case <-ctx.Done():
			return evs, next
		case <-timer:
			return evs, next
		case <-wake:
		}
	}
}
