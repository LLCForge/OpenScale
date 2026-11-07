package node

import (
	"math/rand/v2"
	"time"
)

// Backoff produces exponentially growing, jittered retry delays with an
// upper bound (F-006). Each Next doubles the delay from Base up to Max; a
// success calls Reset. Jitter spreads the delays of many devices so they do
// not retry against the coordinator in lockstep. A Backoff is not safe for
// concurrent use.
type Backoff struct {
	Base time.Duration
	Max  time.Duration
	// Jitter is the fraction (0 to 1) by which a delay is randomly
	// shortened or lengthened; 0.2 gives ±20%.
	Jitter float64
	// Rand returns a number in [0, 1); nil uses math/rand/v2.
	Rand func() float64

	attempt int
}

// Next returns the delay before the next attempt and counts the attempt.
func (b *Backoff) Next() time.Duration {
	r := b.Rand
	if r == nil {
		r = rand.Float64
	}
	d := backoffDelay(b.Base, b.Max, b.attempt, b.Jitter, r())
	b.attempt++
	return d
}

// Reset starts over from Base, after a success.
func (b *Backoff) Reset() { b.attempt = 0 }

// Attempts returns how many delays Next handed out since the last Reset.
func (b *Backoff) Attempts() int { return b.attempt }

// backoffDelay returns base·2^attempt capped at maxDelay, then moved by up
// to ±jitter of itself according to r in [0, 1). The result never exceeds
// maxDelay·(1+jitter) and is never below half of base.
func backoffDelay(base, maxDelay time.Duration, attempt int, jitter, r float64) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if maxDelay < base {
		maxDelay = base
	}
	d := base
	for i := 0; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	jitter = min(max(jitter, 0), 1)
	r = min(max(r, 0), 1)
	d = time.Duration(float64(d) * (1 + jitter*(2*r-1)))
	return max(d, base/2)
}
