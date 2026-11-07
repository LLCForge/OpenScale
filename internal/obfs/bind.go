package obfs

import (
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Mode chooses when datagrams are disguised.
type Mode int

const (
	// ModeOff leaves the transport alone (the wrapper is not installed).
	ModeOff Mode = iota
	// ModeAuto accepts disguised and plain datagrams and disguises only
	// what goes to an endpoint that recently sent a disguised one. Safe
	// with peers of any version; the coordinator always runs this.
	ModeAuto
	// ModeOn disguises everything this device sends. Every peer and the
	// coordinator must understand the format (ADR-0186 minimum version).
	ModeOn
)

// ParseMode reads "off", "auto" or "on".
func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "off", "kapali", "kapalı":
		return ModeOff, nil
	case "auto", "otomatik":
		return ModeAuto, nil
	case "on", "acik", "açık":
		return ModeOn, nil
	}
	return ModeOff, fmt.Errorf("gizleme kipi %q geçersiz: off, auto veya on", s)
}

func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAuto:
		return "auto"
	case ModeOn:
		return "on"
	}
	return fmt.Sprintf("mode(%d)", int(m))
}

// Jitter delays bulk datagrams by a random amount (#616). Interactive
// traffic (small datagrams) is never delayed.
type Jitter struct {
	// Max is the largest delay; zero turns jitter off.
	Max time.Duration `json:"max,omitempty"`
	// BulkSize is the smallest WireGuard datagram counted as bulk
	// (default DefaultBulkSize).
	BulkSize int `json:"bulk_size,omitempty"`
}

// Jitter bounds.
const (
	MinJitter       = time.Millisecond
	MaxJitter       = 100 * time.Millisecond
	DefaultBulkSize = 1000
	MinBulkSize     = 256
	MaxBulkSize     = 65535
)

// Validate checks the jitter settings; zero values are allowed.
func (j Jitter) Validate() error {
	if j.Max != 0 && (j.Max < MinJitter || j.Max > MaxJitter) {
		return fmt.Errorf("zamanlama gürültüsü %s ile %s arasında olmalı", MinJitter, MaxJitter)
	}
	if j.BulkSize != 0 && (j.BulkSize < MinBulkSize || j.BulkSize > MaxBulkSize) {
		return fmt.Errorf("toplu aktarım eşiği %d ile %d bayt arasında olmalı", MinBulkSize, MaxBulkSize)
	}
	return nil
}

func (j Jitter) bulk() int {
	if j.BulkSize == 0 {
		return DefaultBulkSize
	}
	return j.BulkSize
}

// Options configures a Bind.
type Options struct {
	Mode    Mode
	Key     Key
	Padding Padding
	Jitter  Jitter
	// Now and Sleep are replaced by tests.
	Now   func() time.Time
	Sleep func(time.Duration)
	// Rand returns a float in [0, 1) for the jitter; nil uses math/rand.
	Rand func() float64
}

// autoTTL is how long an endpoint stays "speaks disguised" in ModeAuto.
const (
	autoTTL     = 10 * time.Minute
	maxAutoPeer = 4096
)

// Stats counts what the wrapper did.
type Stats struct {
	Wrapped   uint64 `json:"wrapped"`
	Unwrapped uint64 `json:"unwrapped"`
	Plain     uint64 `json:"plain_in"`
	Delayed   uint64 `json:"delayed"`
	PadBytes  uint64 `json:"pad_bytes"`
}

// Bind wraps a conn.Bind and disguises its datagrams.
type Bind struct {
	conn.Bind
	opts Options
	s    *Sealer

	mu   sync.Mutex
	auto map[string]time.Time

	wrapped, unwrapped, plain, delayed, padBytes atomic.Uint64
}

// NewBind wraps inner. ModeOff is refused: do not install the wrapper.
func NewBind(inner conn.Bind, o Options) (*Bind, error) {
	if inner == nil {
		return nil, errors.New("obfs: inner bind is nil")
	}
	if o.Mode != ModeAuto && o.Mode != ModeOn {
		return nil, errors.New("obfs: mode must be auto or on")
	}
	if err := o.Jitter.Validate(); err != nil {
		return nil, err
	}
	s, err := NewSealer(o.Key, o.Padding)
	if err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.Rand == nil {
		o.Rand = mrand.Float64
	}
	return &Bind{Bind: inner, opts: o, s: s, auto: map[string]time.Time{}}, nil
}

// Stats returns the counters.
func (b *Bind) Stats() Stats {
	return Stats{Wrapped: b.wrapped.Load(), Unwrapped: b.unwrapped.Load(), Plain: b.plain.Load(),
		Delayed: b.delayed.Load(), PadBytes: b.padBytes.Load()}
}

// Mode returns the configured mode.
func (b *Bind) Mode() Mode { return b.opts.Mode }

func (b *Bind) disguiseTo(ep conn.Endpoint) bool {
	if b.opts.Mode == ModeOn {
		return true
	}
	key := ep.DstToString()
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.auto[key]
	if !ok {
		return false
	}
	if !b.opts.Now().Before(until) {
		delete(b.auto, key)
		return false
	}
	return true
}

func (b *Bind) noteDisguised(ep conn.Endpoint) {
	if b.opts.Mode != ModeAuto || ep == nil {
		return
	}
	now := b.opts.Now()
	key := ep.DstToString()
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.auto[key]; !ok && len(b.auto) >= maxAutoPeer {
		for k, u := range b.auto {
			if !now.Before(u) {
				delete(b.auto, k)
			}
		}
		if len(b.auto) >= maxAutoPeer {
			return
		}
	}
	b.auto[key] = now.Add(autoTTL)
}

// Send disguises bufs when the endpoint should get disguised datagrams.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if !b.disguiseTo(ep) {
		return b.Bind.Send(bufs, ep)
	}
	out := make([][]byte, 0, len(bufs))
	bulk := false
	for _, p := range bufs {
		if len(p) >= b.opts.Jitter.bulk() {
			bulk = true
		}
		w, err := b.s.Wrap(make([]byte, 0, b.opts.Padding.WireSize(len(p))+tagLen), p)
		if err != nil {
			return err
		}
		b.padBytes.Add(uint64(len(w) - len(p) - Overhead))
		out = append(out, w)
	}
	b.wrapped.Add(uint64(len(out)))
	if bulk && b.opts.Jitter.Max > 0 {
		b.delayed.Add(1)
		b.opts.Sleep(time.Duration(b.opts.Rand() * float64(b.opts.Jitter.Max)))
	}
	return b.Bind.Send(out, ep)
}

// Open wraps every receive function so disguised datagrams arrive as the
// WireGuard datagrams inside. Plain WireGuard datagrams and anything else
// (control echoes) pass unchanged; disguised-looking datagrams that fail
// to open are dropped.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = b.receive(fn)
	}
	return fns, actual, nil
}

func (b *Bind) receive(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(packets, sizes, eps)
			kept := b.filter(packets, sizes, eps, n)
			if kept > 0 || err != nil || n == 0 {
				return kept, err
			}
		}
	}
}

// filter unwraps n received datagrams in place and returns how many remain.
func (b *Bind) filter(packets [][]byte, sizes []int, eps []conn.Endpoint, n int) int {
	kept := 0
	for i := 0; i < n; i++ {
		data := packets[i][:sizes[i]]
		switch {
		case len(data) == 0 || LooksLikeWireGuard(data) || data[0]&0xc0 != quicFixedBit:
			b.plain.Add(1)
			if kept != i {
				sizes[kept] = copy(packets[kept], data)
				eps[kept] = eps[i]
			}
			kept++
		default:
			inner, err := b.s.Unwrap(data)
			if err != nil {
				continue
			}
			b.unwrapped.Add(1)
			b.noteDisguised(eps[i])
			sizes[kept] = copy(packets[kept], inner)
			eps[kept] = eps[i]
			kept++
		}
	}
	return kept
}

// SetMark passes the mark on.
func (b *Bind) SetMark(mark uint32) error { return b.Bind.SetMark(mark) }

// BindSocketToInterface4 and 6 pass interface binding on when supported.
func (b *Bind) BindSocketToInterface4(index uint32, blackhole bool) error {
	if x, ok := b.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface4(index, blackhole)
	}
	return nil
}

func (b *Bind) BindSocketToInterface6(index uint32, blackhole bool) error {
	if x, ok := b.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface6(index, blackhole)
	}
	return nil
}
