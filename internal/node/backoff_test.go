package node

import (
	"testing"
	"time"
)

func TestBackoffGrowsCapsAndResets(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 10 * time.Second, Rand: func() float64 { return 0.5 }}
	want := []time.Duration{1, 2, 4, 8, 10, 10}
	for i, w := range want {
		if got := b.Next(); got != w*time.Second {
			t.Fatalf("attempt %d: %s, want %s", i, got, w*time.Second)
		}
	}
	if b.Attempts() != len(want) {
		t.Fatalf("attempts %d", b.Attempts())
	}
	b.Reset()
	if got := b.Next(); got != time.Second {
		t.Fatalf("after reset %s", got)
	}
}

func TestBackoffJitterBounds(t *testing.T) {
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 0.999999} {
		for attempt := 0; attempt < 70; attempt++ { // far past any shift overflow
			d := backoffDelay(2*time.Second, time.Minute, attempt, 0.2, r)
			if d < 1600*time.Millisecond || d > 72*time.Second {
				t.Fatalf("attempt %d r %.2f: %s out of bounds", attempt, r, d)
			}
		}
	}
	if got := backoffDelay(2*time.Second, time.Minute, 0, 0.2, 0); got != 1600*time.Millisecond {
		t.Fatalf("lowest jitter %s", got)
	}
	// Nonsense input stays sane: no base, max below base, jitter > 1.
	if got := backoffDelay(0, 0, 3, 5, 0); got < 500*time.Millisecond || got > time.Second {
		t.Fatalf("defaults %s", got)
	}
	if got := backoffDelay(time.Minute, time.Second, 0, 0, 0.5); got != time.Minute {
		t.Fatalf("max below base %s", got)
	}
}

func TestBackoffDefaultRandSpreads(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		b := Backoff{Base: time.Second, Max: time.Minute, Jitter: 0.5}
		seen[b.Next()] = true
	}
	if len(seen) < 5 {
		t.Fatalf("jitter produced only %d distinct delays", len(seen))
	}
}
