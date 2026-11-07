package p2psend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// Offer is an incoming file waiting for the receiver's decision. Name is
// already sanitized; everything here came out of the sealed header.
type Offer struct {
	ID         string    `json:"id"`
	From       string    `json:"from"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	Executable bool      `json:"executable"`
	Resume     bool      `json:"resume"`
	Stripped   bool      `json:"stripped"`
	At         time.Time `json:"at"`
}

// Approvals holds offers until the user accepts or rejects them in the
// panel or the CLI. An offer nobody answers is rejected after the timeout.
type Approvals struct {
	mu      sync.Mutex
	pending map[string]*pendingOffer
	// AutoAccept, if set, accepts offers without asking (for example from
	// the user's own devices that the user chose to trust).
	AutoAccept func(Offer) bool
	timeout    time.Duration
	now        func() time.Time
}

type pendingOffer struct {
	offer  Offer
	answer chan bool
}

// MaxPending bounds offers waiting for a decision.
const MaxPending = 32

// ErrNoOffer is returned for an unknown or already answered offer.
var ErrNoOffer = errors.New("bekleyen böyle bir dosya teklifi yok")

// ErrTooManyOffers is returned when too many offers wait.
var ErrTooManyOffers = errors.New("çok fazla bekleyen dosya teklifi var")

// NewApprovals returns an approval queue; timeout <= 0 means 5 minutes.
func NewApprovals(timeout time.Duration) *Approvals {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Approvals{pending: map[string]*pendingOffer{}, timeout: timeout, now: time.Now}
}

// Ask blocks until the offer is answered, times out or ctx ends.
func (a *Approvals) Ask(ctx context.Context, o Offer) (bool, error) {
	if a.AutoAccept != nil && a.AutoAccept(o) {
		return true, nil
	}
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return false, err
	}
	o.ID = hex.EncodeToString(idb[:])
	o.At = a.now()
	p := &pendingOffer{offer: o, answer: make(chan bool, 1)}
	a.mu.Lock()
	if len(a.pending) >= MaxPending {
		a.mu.Unlock()
		return false, ErrTooManyOffers
	}
	a.pending[o.ID] = p
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, o.ID)
		a.mu.Unlock()
	}()
	t := time.NewTimer(a.timeout)
	defer t.Stop()
	select {
	case ok := <-p.answer:
		return ok, nil
	case <-t.C:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// Pending lists the waiting offers, oldest first.
func (a *Approvals) Pending() []Offer {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Offer, 0, len(a.pending))
	for _, p := range a.pending {
		out = append(out, p.offer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Decide answers an offer.
func (a *Approvals) Decide(id string, accept bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pending[id]
	if !ok {
		return ErrNoOffer
	}
	delete(a.pending, id)
	p.answer <- accept
	return nil
}
