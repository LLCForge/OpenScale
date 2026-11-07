package node

import (
	"context"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/trust"
)

func configured(e *Engine, key trust.Key) bool {
	st, err := e.PeerStats()
	if err != nil {
		return false
	}
	_, ok := st[key]
	return ok
}

// With LazyPeers a peer is configured only when traffic for it appears,
// from either side, and removed again when idle (F-020).
func TestLazyPeers(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, err := New(Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t), LazyPeers: true,
		PollInterval: 300 * time.Millisecond, RelayAfter: time.Second, Logger: testLogger(t, "[laptop]")})
	if err != nil {
		t.Fatal(err)
	}
	// The minimum is a minute; tests are shorter, but longer than one
	// WireGuard handshake retry (5 s).
	a.cfg.LazyIdle = 7 * time.Second
	go func() { _ = a.Run(ctx) }()
	// b is lazy as well: a peer with its own keepalive would keep the
	// session (and so a's configuration) alive by design.
	b, err := New(Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t), LazyPeers: true,
		PollInterval: 300 * time.Millisecond, RelayAfter: time.Second, Logger: testLogger(t, "[masaustu]")})
	if err != nil {
		t.Fatal(err)
	}
	b.cfg.LazyIdle = 7 * time.Second
	go func() { _ = b.Run(ctx) }()
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	coordKey := aStore.Document().Coordinator.WireGuardKey

	waitFor(t, 10*time.Second, "a synced", func() bool { return a.Status().LastSync.After(time.Time{}) && a.Status().LastSyncError == "" })
	time.Sleep(time.Second)
	if configured(a, bSelf.WireGuardKey) || configured(b, aSelf.WireGuardKey) || !configured(a, coordKey) {
		t.Fatal("lazy peer configured before any traffic, or coordinator missing")
	}
	if a.Status().Peers != 1 || a.LazyActive(bSelf.WireGuardKey) {
		t.Fatalf("status counts %d peers; lazy active %v", a.Status().Peers, a.LazyActive(bSelf.WireGuardKey))
	}

	// Outbound traffic configures the peer.
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("first packet to a lazy peer did not arrive")
	}
	if !configured(a, bSelf.WireGuardKey) {
		t.Fatal("peer not configured after traffic")
	}
	drainTUN(ctx, bTUN)
	// Idle on both sides (no data, no keepalive, no handshake): removed.
	waitFor(t, 30*time.Second, "idle lazy peer removed", func() bool {
		return !configured(a, bSelf.WireGuardKey) && !configured(b, aSelf.WireGuardKey)
	})

	// The other side starts talking: its call (or relayed handshake)
	// configures the peer on a.
	if !expectPacket(t, bTUN, aTUN, bSelf.IPv4, aSelf.IPv4, 45*time.Second) {
		t.Fatal("peer could not reach an idle lazy device")
	}
	if !configured(a, bSelf.WireGuardKey) {
		t.Fatal("peer not configured after inbound traffic")
	}
}
