package node

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/trust"
)

// sealedLAN is the interface address every engine of these tests reports.
var sealedLAN = netip.MustParseAddr("10.77.0.7")

func withFakeInterfaces(t *testing.T) {
	t.Helper()
	saved := listInterfaceAddrs
	listInterfaceAddrs = func() ([]interfaceAddr, error) {
		return []interfaceAddr{{iface: "eth0", addr: sealedLAN}}, nil
	}
	t.Cleanup(func() { listInterfaceAddrs = saved })
}

// plainFrom is what the coordinator handed e plainly about peer.
func plainFrom(e *Engine, peer trust.Key) []netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.peerInfo[peer].cands)
}

// sealedFrom is what e learned end-to-end from peer.
func sealedFrom(e *Engine, peer trust.Key) []netip.AddrPort {
	e.probe.mu.Lock()
	defer e.probe.mu.Unlock()
	if pp := e.probe.peers[e.probe.byKey[peer]]; pp != nil {
		return slices.Clone(pp.sealed)
	}
	return nil
}

func hasLAN(cands []netip.AddrPort) bool {
	return slices.ContainsFunc(cands, func(ap netip.AddrPort) bool { return ap.Addr() == sealedLAN })
}

type sealedRun struct {
	a, b         *Engine
	aSelf, bSelf trust.Device
}

func startSealedRun(t *testing.T, ctx context.Context, aMode, bMode SealedCandidatesMode) sealedRun {
	t.Helper()
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	coordStore, aStore, bStore := tn.join(t, "coordinator"), tn.join(t, "laptop"), tn.join(t, "masaustu")
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: tn.coordSecrets, ListenPort: tn.coordPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	var r sealedRun
	r.a, _ = startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), SealedCandidates: aMode})
	r.b, _ = startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), SealedCandidates: bMode})
	r.aSelf, _ = r.a.Self()
	r.bSelf, _ = r.b.Self()
	if !expectPacket(t, aTUN, bTUN, r.aSelf.IPv4, r.bSelf.IPv4, 20*time.Second) {
		t.Fatal("tunnel did not come up")
	}
	return r
}

func waitSealed(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); !cond(); {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Two new devices in sealed-only mode: each learns the other's LAN
// candidate end-to-end; the coordinator hands out none plainly.
func TestSealedCandidatesEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	withFakeInterfaces(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startSealedRun(t, ctx, SealedCandidatesOnly, SealedCandidatesAuto)
	waitSealed(t, "sealed candidates did not arrive", 15*time.Second, func() bool {
		return hasLAN(sealedFrom(r.b, r.aSelf.WireGuardKey)) && hasLAN(sealedFrom(r.a, r.bSelf.WireGuardKey))
	})
	// Give the plain path a few more rounds to leak, if it would.
	time.Sleep(2 * time.Second)
	if c := plainFrom(r.b, r.aSelf.WireGuardKey); hasLAN(c) {
		t.Fatalf("coordinator handed out the sealed-only device's LAN address plainly: %v", c)
	}
	// The auto device needs no plain report either: its only peer reads
	// sealed candidates.
	if c := plainFrom(r.a, r.bSelf.WireGuardKey); hasLAN(c) {
		t.Fatalf("auto device reported plainly with no old peer online: %v", c)
	}
}

// A device that seals nothing (an old client, as far as the protocol goes)
// still gets the auto device's candidates plainly; a sealed-only device
// never gives it any.
func TestSealedCandidatesFallBackForOldPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	withFakeInterfaces(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startSealedRun(t, ctx, SealedCandidatesAuto, SealedCandidatesOff)
	waitSealed(t, "auto device did not fall back to plain candidates for the old peer", 20*time.Second, func() bool {
		return hasLAN(plainFrom(r.b, r.aSelf.WireGuardKey))
	})
	if c := sealedFrom(r.b, r.aSelf.WireGuardKey); len(c) != 0 {
		t.Fatalf("old peer got sealed candidates: %v", c)
	}
	cancel()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	r2 := startSealedRun(t, ctx2, SealedCandidatesOnly, SealedCandidatesOff)
	time.Sleep(4 * time.Second) // several sync rounds
	if c := plainFrom(r2.b, r2.aSelf.WireGuardKey); hasLAN(c) {
		t.Fatalf("sealed-only device leaked to an old peer: %v", c)
	}
	// The old peer still reports plainly and is reachable as before.
	waitSealed(t, "old peer's plain candidates missing", 10*time.Second, func() bool {
		return hasLAN(plainFrom(r2.a, r2.bSelf.WireGuardKey))
	})
}
