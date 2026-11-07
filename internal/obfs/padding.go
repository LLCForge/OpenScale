package obfs

import (
	"errors"
	"fmt"
	"slices"
)

// Padding normalises disguised datagram sizes to fixed buckets (#615). It
// works on the outer datagram, so it also hides WireGuard's fixed
// handshake sizes, which the inner padding of ADR-0043 (#36) cannot reach.
type Padding struct {
	// Buckets are the allowed wire sizes in bytes, ascending. A datagram is
	// padded to the smallest bucket that holds it; a larger one is sent at
	// its own size. Empty: no padding.
	Buckets []int `json:"buckets,omitempty"`
}

// Bucket bounds.
const (
	MinBucket  = 64
	MaxBucket  = 1452 // the UDP payload of a 1500-byte IPv6 path
	MaxBuckets = 16
)

// DefaultBuckets are the owner's example sizes plus the largest datagram
// that crosses a 1500-byte IPv6 path without fragmentation.
var DefaultBuckets = []int{256, 512, 1280, 1452}

// DefaultPadding returns padding with DefaultBuckets.
func DefaultPadding() Padding { return Padding{Buckets: slices.Clone(DefaultBuckets)} }

// ErrPadding is wrapped by every padding validation error.
var ErrPadding = errors.New("dolgu ayarı geçersiz")

// Validate checks the buckets.
func (p Padding) Validate() error {
	if len(p.Buckets) > MaxBuckets {
		return fmt.Errorf("%w: en fazla %d kova", ErrPadding, MaxBuckets)
	}
	prev := 0
	for _, b := range p.Buckets {
		if b < MinBucket || b > MaxBucket {
			return fmt.Errorf("%w: kova %d bayt, %d ile %d arasında olmalı", ErrPadding, b, MinBucket, MaxBucket)
		}
		if b <= prev {
			return fmt.Errorf("%w: kovalar artan sırada ve tekrarsız olmalı", ErrPadding)
		}
		prev = b
	}
	return nil
}

// size returns the padded wire size of a datagram of n bytes.
func (p Padding) size(n int) int {
	for _, b := range p.Buckets {
		if n <= b {
			return b
		}
	}
	return n
}

// WireSize reports the wire size a WireGuard datagram of n bytes gets.
func (p Padding) WireSize(n int) int { return p.size(n + Overhead) }
