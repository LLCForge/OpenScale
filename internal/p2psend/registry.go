package p2psend

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// Transfer states.
const (
	StateWaiting   = "waiting"   // waiting for the receiver's decision
	StateSending   = "sending"   // bytes are moving
	StateReceiving = "receiving" // bytes are moving
	StateDone      = "done"
	StateFailed    = "failed"
)

// Path kinds.
const (
	PathDirect = "direct"
	PathOnion  = "onion"
)

// TransferView is one transfer as the panel shows it.
type TransferView struct {
	ID          string    `json:"id"`
	Outgoing    bool      `json:"outgoing"`
	Peer        string    `json:"peer"`
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	Done        int64     `json:"done"`
	State       string    `json:"state"`
	Path        string    `json:"path,omitempty"`
	Hops        int       `json:"hops,omitempty"`
	Resumed     int64     `json:"resumed,omitempty"`
	Error       string    `json:"error,omitempty"`
	Started     time.Time `json:"started"`
	Finished    time.Time `json:"finished,omitempty"`
	Stripped    bool      `json:"stripped,omitempty"`
	Quarantined bool      `json:"quarantined,omitempty"`
}

// Registry keeps the recent transfers for the panel. It is bounded.
type Registry struct {
	mu    sync.Mutex
	items []*entry
	now   func() time.Time
}

type entry struct {
	view TransferView
	done atomic.Int64
}

const maxRegistry = 100

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{now: time.Now} }

// handle updates one transfer.
type handle struct {
	r *Registry
	e *entry
}

func (r *Registry) start(v TransferView) *handle {
	if r == nil {
		return nil
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	v.ID = hex.EncodeToString(b[:])
	v.Started = r.now()
	e := &entry{view: v}
	r.mu.Lock()
	r.items = append(r.items, e)
	if len(r.items) > maxRegistry {
		r.items = r.items[len(r.items)-maxRegistry:]
	}
	r.mu.Unlock()
	return &handle{r: r, e: e}
}

func (h *handle) set(f func(*TransferView)) {
	if h == nil {
		return
	}
	h.r.mu.Lock()
	f(&h.e.view)
	h.r.mu.Unlock()
}

func (h *handle) progress(n int64) {
	if h != nil {
		h.e.done.Store(n)
	}
}

func (h *handle) finish(err error) {
	if h == nil {
		return
	}
	h.set(func(v *TransferView) {
		v.Finished = h.r.now()
		if err != nil {
			v.State = StateFailed
			v.Error = err.Error()
			return
		}
		v.State = StateDone
		h.e.done.Store(v.Size)
	})
}

// List returns the transfers, newest first.
func (r *Registry) List() []TransferView {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TransferView, 0, len(r.items))
	for i := len(r.items) - 1; i >= 0; i-- {
		v := r.items[i].view
		v.Done = r.items[i].done.Load()
		out = append(out, v)
	}
	return out
}
