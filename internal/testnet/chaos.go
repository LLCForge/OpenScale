package testnet

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// ChaosBind wraps a conn.Bind (normally a LoopbackBind) and injects the
// faults chaos tests need (#207, ADR-0095): random packet loss, added
// delay, a full partition of this endpoint and blocked peer ports (a
// network split between two endpoints). Faults can change while the bind
// is open. The random source is seeded, so a failing run can be repeated.
type ChaosBind struct {
	conn.Bind

	mu        sync.Mutex
	rng       *rand.Rand
	loss      float64
	delay     time.Duration
	partition bool
	blocked   map[uint16]bool

	dropped atomic.Uint64
	passed  atomic.Uint64
}

// NewChaosBind wraps inner; seed fixes the loss pattern.
func NewChaosBind(inner conn.Bind, seed uint64) *ChaosBind {
	return &ChaosBind{Bind: inner, rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), blocked: map[uint16]bool{}}
}

// SetLoss drops each packet, in both directions, with probability p.
func (b *ChaosBind) SetLoss(p float64) {
	b.mu.Lock()
	b.loss = min(max(p, 0), 1)
	b.mu.Unlock()
}

// SetDelay delays every sent packet by d.
func (b *ChaosBind) SetDelay(d time.Duration) {
	b.mu.Lock()
	b.delay = max(d, 0)
	b.mu.Unlock()
}

// SetPartition drops everything sent or received while on.
func (b *ChaosBind) SetPartition(on bool) {
	b.mu.Lock()
	b.partition = on
	b.mu.Unlock()
}

// BlockPort drops traffic to and from the given UDP port while on.
func (b *ChaosBind) BlockPort(port uint16, on bool) {
	b.mu.Lock()
	if on {
		b.blocked[port] = true
	} else {
		delete(b.blocked, port)
	}
	b.mu.Unlock()
}

// Stats returns how many packets were dropped and passed.
func (b *ChaosBind) Stats() (dropped, passed uint64) { return b.dropped.Load(), b.passed.Load() }

// drop decides the fate of one packet to or from peer.
func (b *ChaosBind) drop(peer string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.partition {
		return true
	}
	if len(b.blocked) > 0 {
		if ap, err := netip.ParseAddrPort(peer); err == nil && b.blocked[ap.Port()] {
			return true
		}
	}
	return b.loss > 0 && b.rng.Float64() < b.loss
}

func (b *ChaosBind) currentDelay() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.delay
}

// Open opens the inner bind and filters what it receives.
func (b *ChaosBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		out[i] = b.filter(fn)
	}
	return out, actual, nil
}

// filter keeps reading until at least one packet survives, so the caller
// never sees an empty batch.
func (b *ChaosBind) filter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(packets, sizes, eps)
			if err != nil {
				return n, err
			}
			kept := 0
			for i := 0; i < n; i++ {
				if eps[i] != nil && b.drop(eps[i].DstToString()) {
					b.dropped.Add(1)
					continue
				}
				b.passed.Add(1)
				if kept != i {
					// wireguard-go reads its own buffer array by index, so
					// the bytes move, not the slices.
					copy(packets[kept], packets[i][:sizes[i]])
					sizes[kept], eps[kept] = sizes[i], eps[i]
				}
				kept++
			}
			if kept > 0 {
				return kept, nil
			}
		}
	}
}

// Send drops, delays or passes the buffers.
func (b *ChaosBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.drop(ep.DstToString()) {
		b.dropped.Add(uint64(len(bufs)))
		return nil
	}
	b.passed.Add(uint64(len(bufs)))
	d := b.currentDelay()
	if d <= 0 {
		return b.Bind.Send(bufs, ep)
	}
	// The caller reuses its buffers: copy them for the late send.
	cp := make([][]byte, len(bufs))
	for i, buf := range bufs {
		cp[i] = append([]byte(nil), buf...)
	}
	time.AfterFunc(d, func() { _ = b.Bind.Send(cp, ep) })
	return nil
}
