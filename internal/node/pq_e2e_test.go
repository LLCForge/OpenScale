package node

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// pskOf returns the preshared key WireGuard holds for peer.
func pskOf(t *testing.T, e *Engine, peer trust.Key) [32]byte {
	t.Helper()
	ps, err := e.pqStatus()
	if err != nil {
		return [32]byte{}
	}
	return ps.psks[peer]
}

func handshakeOf(e *Engine, peer trust.Key) int64 {
	st, err := e.PeerStats()
	if err != nil {
		return 0
	}
	return st[peer].LastHandshakeUnix
}

// pinger sends a ping from a to b every interval and records the longest
// gap between pings arriving at b.
type pinger struct {
	mu      sync.Mutex
	last    time.Time
	maxGap  time.Duration
	arrived atomic.Int64
}

func startPinger(ctx context.Context, from, to *tuntest.ChannelTUN, src, dst trust.Device, every time.Duration) *pinger {
	p := &pinger{}
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				select {
				case from.Outbound <- tuntest.Ping(dst.IPv4, src.IPv4):
				default:
				}
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-to.Inbound:
				info, err := packet.Parse(pkt)
				if err != nil || !info.IsICMP() || info.Src != src.IPv4 {
					continue
				}
				now := time.Now()
				p.mu.Lock()
				if !p.last.IsZero() && now.Sub(p.last) > p.maxGap {
					p.maxGap = now.Sub(p.last)
				}
				p.last = now
				p.mu.Unlock()
				p.arrived.Add(1)
			}
		}
	}()
	return p
}

// drainTUN keeps reading what the engine writes to a test TUN: the channel
// TUN blocks WireGuard's receive path when nobody reads it.
func drainTUN(ctx context.Context, ch *tuntest.ChannelTUN) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch.Inbound:
			}
		}
	}()
}

func (p *pinger) gap() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxGap
}

// Two engines agree on a post-quantum PSK inside their tunnel, WireGuard
// uses it for new handshakes, and a rotation does not interrupt traffic
// (ADR-0033).
func TestPostQuantumPSKEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	mk := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, name string) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), ListenPort: freeUDPPort(t), PollInterval: 300 * time.Millisecond, Logger: testLogger(t, name)})
		if err != nil {
			t.Fatal(err)
		}
		// Rotate every few seconds instead of every ten minutes.
		e.pq.rotation = 4 * time.Second
		go func() { _ = e.Run(ctx) }()
		return e
	}
	a := mk(aStore, tn.aKey, aTUN, "[laptop]")
	b := mk(bStore, tn.bKey, bTUN, "[masaustu]")
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("no traffic")
	}
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	pg := startPinger(pctx, aTUN, bTUN, aSelf, bSelf, 50*time.Millisecond)
	var first [32]byte
	waitFor(t, 20*time.Second, "both sides hold the same post-quantum PSK", func() bool {
		sa, _ := a.PostQuantumState(bSelf.WireGuardKey)
		sb, _ := b.PostQuantumState(aSelf.WireGuardKey)
		first = pskOf(t, a, bSelf.WireGuardKey)
		return sa == PQStateActive && sb == PQStateActive && first != [32]byte{} && first == pskOf(t, b, aSelf.WireGuardKey)
	})
	paths, err := a.PeerPaths()
	if err != nil || len(paths) != 1 || paths[0].PostQuantum != PQStateActive {
		t.Fatalf("PeerPaths does not report the PSK: %+v %v", paths, err)
	}

	var second [32]byte
	waitFor(t, 30*time.Second, "the PSK rotates on both sides", func() bool {
		second = pskOf(t, a, bSelf.WireGuardKey)
		return second != first && second != [32]byte{} && second == pskOf(t, b, aSelf.WireGuardKey)
	})
	// New handshakes use the new PSK and succeed.
	switched := time.Now()
	time.Sleep(1100 * time.Millisecond)
	a.kickHandshakes()
	waitFor(t, 15*time.Second, "a handshake with the rotated PSK", func() bool {
		return handshakeOf(a, bSelf.WireGuardKey) > switched.Unix()
	})
	before := pg.arrived.Load()
	time.Sleep(time.Second)
	if pg.arrived.Load() <= before {
		t.Fatal("no traffic after the handshake with the rotated PSK")
	}
	if g := pg.gap(); g > 2*time.Second {
		t.Fatalf("traffic stopped for %s around the rotation", g)
	}
}

// A peer that does not take part (an older version, or post-quantum turned
// off) is reached classically, exactly as before, and shows as such.
func TestPostQuantumFallsBackForPeerWithoutSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, _ := startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t)})
	b, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t), PostQuantum: PostQuantumOff})
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("no traffic")
	}
	if s, _ := b.PostQuantumState(aSelf.WireGuardKey); s != PQStateOff {
		t.Fatalf("b reports %q, want %q", s, PQStateOff)
	}
	dctx, dcancel := context.WithCancel(ctx)
	drainTUN(dctx, aTUN)
	drainTUN(dctx, bTUN)
	// Whichever side initiates, a ends up classical: as initiator it marks
	// b unsupported after its retries; as responder it never hears an init.
	a.pq.mu.Lock()
	initiator := a.pq.peers[bSelf.WireGuardKey].initiator
	a.pq.mu.Unlock()
	if initiator {
		waitFor(t, 30*time.Second, "a marks b unsupported", func() bool {
			s, _ := a.PostQuantumState(bSelf.WireGuardKey)
			return s == PQStateUnsupported
		})
	} else {
		time.Sleep(time.Duration(pqMaxTries+2) * pqRetransmit)
		if s, _ := a.PostQuantumState(bSelf.WireGuardKey); s != PQStateClassical {
			t.Fatalf("a reports %q as responder", s)
		}
	}
	dcancel()
	if pskOf(t, a, bSelf.WireGuardKey) != ([32]byte{}) || pskOf(t, b, aSelf.WireGuardKey) != ([32]byte{}) {
		t.Fatal("a PSK was set with a peer that does not support it")
	}
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 5*time.Second) || !expectPacket(t, bTUN, aTUN, bSelf.IPv4, aSelf.IPv4, 5*time.Second) {
		t.Fatal("classical traffic broke")
	}
}

// A device that restarts forgets its PSK. Its signed reset hint (sent
// outside the tunnel, here through the relay) makes the peer drop its PSK
// too, so the tunnel comes back in seconds instead of after pqStaleReset.
func TestPostQuantumRecoversAfterPeerRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	bPort := freeUDPPort(t)
	a, _ := startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t)})
	bctx, bcancel := context.WithCancel(ctx)
	b, bDone := startEngine(bctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: bPort})
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	dctx, dcancel := context.WithCancel(ctx)
	drainTUN(dctx, bTUN)
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("no traffic")
	}
	waitFor(t, 30*time.Second, "agreement", func() bool {
		p := pskOf(t, a, bSelf.WireGuardKey)
		return p != [32]byte{} && p == pskOf(t, b, aSelf.WireGuardKey)
	})
	bcancel()
	<-bDone
	dcancel()
	bTUN2 := tuntest.NewChannelTUN()
	b2, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN2.TUN(), ListenPort: bPort})
	start := time.Now()
	if !expectPacket(t, aTUN, bTUN2, aSelf.IPv4, bSelf.IPv4, 40*time.Second) {
		t.Fatal("tunnel did not recover after the restart")
	}
	if took := time.Since(start); took > pqStaleReset-30*time.Second {
		t.Fatalf("recovery took %s: the reset hint did not work", took)
	}
	drainTUN(ctx, bTUN2)
	waitFor(t, 30*time.Second, "a new agreement after the restart", func() bool {
		p := pskOf(t, a, bSelf.WireGuardKey)
		return p != [32]byte{} && p == pskOf(t, b2, aSelf.WireGuardKey)
	})
}
