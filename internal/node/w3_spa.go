package node

import (
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/trust"
)

// Device side of single packet authorization (#614, ADR-0181).
//
// A coordinator with port hiding drops every datagram from a source that
// has not knocked, and closes TCP connections that do not start with a
// knock. A device cannot know whether the gate is on (it is the
// coordinator's local setting), so it always knocks:
//
//   - UDP: before the first datagram to a coordinator, again every
//     spaKnockEvery, and again on a handshake initiation when the last
//     knock is older than spaRekockHandshake (the coordinator restarted and
//     lost its gate). A coordinator without the gate hands the knock to
//     WireGuard, which drops it as an unknown message type.
//   - TCP: the knock goes after the TLS camouflage (inside it) and before
//     the preamble. Coordinators of this version read and ignore a knock
//     when the gate is off; an older coordinator closes such a stream, so
//     on a failed preamble the next dial goes without the knock and the
//     two forms alternate until one works (tcpFallback.preamble).
//
// The key comes from the signed document: the coordinator's WireGuard
// key and the network id (obfs.SPAKey).

const (
	spaKnockEvery = 4 * time.Minute // under the coordinator's 5 (SPAKnockEvery)
	// spaRekockHandshake: a handshake initiation knocks again after this
	// long, so a restarted coordinator opens within one handshake retry.
	spaRekockHandshake = 20 * time.Second
	// wireguard handshake initiation: type 1, 148 bytes.
	wgInitiationType = 1
	wgInitiationSize = 148
)

type spaTarget struct {
	addr netip.Addr
	key  [32]byte
}

// spaKnockBind knocks before datagrams to coordinators.
type spaKnockBind struct {
	conn.Bind
	now    func() time.Time
	random io.Reader
	logger *slog.Logger

	mu      sync.Mutex
	targets map[trust.Key]spaTarget // by coordinator WireGuard key
	last    map[netip.AddrPort]time.Time
	sent    uint64
}

func newSPAKnockBind(now func() time.Time, logger *slog.Logger) *spaKnockBind {
	if now == nil {
		now = time.Now
	}
	return &spaKnockBind{now: now, random: rand.Reader, logger: logger,
		targets: map[trust.Key]spaTarget{}, last: map[netip.AddrPort]time.Time{}}
}

// setCoordinator records (or moves) a coordinator's address.
func (b *spaKnockBind) setCoordinator(wg trust.Key, networkID string, addr netip.Addr) {
	if b == nil || !addr.IsValid() || wg.IsZero() {
		return
	}
	addr = addr.Unmap()
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, ok := b.targets[wg]; ok && cur.addr == addr {
		return
	}
	b.targets[wg] = spaTarget{addr: addr, key: obfs.SPAKey(wg, networkID)}
	// Bounded: a handful of coordinators; forget sends to old addresses.
	for ap := range b.last {
		if !b.isTargetLocked(ap.Addr()) {
			delete(b.last, ap)
		}
	}
}

func (b *spaKnockBind) isTargetLocked(a netip.Addr) bool {
	_, ok := b.keyLocked(a)
	return ok
}

func (b *spaKnockBind) keyLocked(a netip.Addr) ([32]byte, bool) {
	for _, t := range b.targets {
		if t.addr == a {
			return t.key, true
		}
	}
	return [32]byte{}, false
}

// knockFor returns the knock to send before bufs to ap, or nil.
func (b *spaKnockBind) knockFor(bufs [][]byte, ap netip.AddrPort) []byte {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	now := b.now()
	b.mu.Lock()
	key, ok := b.keyLocked(ap.Addr())
	if !ok {
		b.mu.Unlock()
		return nil
	}
	last, seen := b.last[ap]
	due := !seen || now.Sub(last) >= spaKnockEvery || now.Before(last)
	if !due && now.Sub(last) >= spaRekockHandshake {
		for _, p := range bufs {
			if len(p) == wgInitiationSize && p[0] == wgInitiationType {
				due = true
				break
			}
		}
	}
	if !due {
		b.mu.Unlock()
		return nil
	}
	b.last[ap] = now
	b.sent++
	b.mu.Unlock()
	k, err := obfs.SPAKnock(key, now, b.random)
	if err != nil {
		return nil
	}
	return k
}

func (b *spaKnockBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if ep != nil {
		if ap, err := netip.ParseAddrPort(ep.DstToString()); err == nil {
			if k := b.knockFor(bufs, ap); k != nil {
				_ = b.Bind.Send([][]byte{k}, ep) // best effort; the next send retries
			}
		}
	}
	return b.Bind.Send(bufs, ep)
}

// SetMark and the interface binding pass through (the wrapped bind may
// support them; the tunnel's exit routing relies on them).
func (b *spaKnockBind) SetMark(mark uint32) error { return b.Bind.SetMark(mark) }

func (b *spaKnockBind) BindSocketToInterface4(index uint32, blackhole bool) error {
	if x, ok := b.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface4(index, blackhole)
	}
	return nil
}

func (b *spaKnockBind) BindSocketToInterface6(index uint32, blackhole bool) error {
	if x, ok := b.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface6(index, blackhole)
	}
	return nil
}

// knocks returns how many knocks were sent (diagnostics, tests).
func (b *spaKnockBind) knocks() uint64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}

// spaTCPKnock builds a knock for the primary coordinator's TCP transport.
func (e *Engine) spaTCPKnock() []byte {
	doc := e.cfg.Store.Document()
	if doc.Coordinator == nil || doc.Coordinator.WireGuardKey.IsZero() {
		return nil
	}
	k, err := obfs.SPAKnock(obfs.SPAKey(doc.Coordinator.WireGuardKey, doc.NetworkID), e.cfg.Now(), rand.Reader)
	if err != nil {
		return nil
	}
	return k
}

// spaSetPrimary records the primary coordinator's address for knocking.
func (e *Engine) spaSetPrimary(ep netip.AddrPort) {
	if e.spa == nil || !ep.IsValid() {
		return
	}
	doc := e.cfg.Store.Document()
	if doc.Coordinator == nil {
		return
	}
	e.spa.setCoordinator(doc.Coordinator.WireGuardKey, doc.NetworkID, ep.Addr())
}

// preamble writes the optional knock and the transport preamble on a fresh
// stream and reads the coordinator's preamble. On a failed exchange it
// flips whether the next dial knocks (older coordinators close a stream
// that starts with a knock; hiding coordinators close one without).
func (t *tcpFallback) preamble(s net.Conn) error {
	var out []byte
	knocked := false
	if t.knock != nil && !t.noKnock.Load() {
		if k := t.knock(); k != nil {
			out = append(out, k...)
			knocked = true
		}
	}
	out = append(out, control.TCPMagic...)
	if _, err := s.Write(out); err != nil {
		return err
	}
	if err := control.ReadMagic(s); err != nil {
		if t.knock != nil {
			t.noKnock.Store(knocked) // try the other form next time
		}
		return err
	}
	return nil
}
