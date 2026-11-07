package node

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
)

// Chaos tests (#207, ADR-0095): the real engines and coordinator on
// 127.0.0.1, with faults injected by testnet.ChaosBind or by stopping the
// coordinator. They take seconds each and are skipped with -short.

type chaosNet struct {
	tn                 *testNet
	coordStore         *member.Store
	aStore, bStore     *member.Store
	aBind, bBind       *testnet.ChaosBind
	aTUN, bTUN         *tuntest.ChannelTUN
	a, b               *Engine
	aSelf, bSelf       trust.Device
	stopCoord          context.CancelFunc
	coordDone          chan struct{}
	coordBind          *testnet.ChaosBind
	ctx                context.Context
	networkDirForOwner string
}

func startChaosCoordinator(t *testing.T, c *chaosNet) {
	t.Helper()
	ctx, cancel := context.WithCancel(c.ctx)
	c.coordBind = testnet.NewChaosBind(testnet.NewLoopbackBind(), 7)
	coord, err := coordinator.New(coordinator.Config{Store: c.coordStore, Secrets: c.tn.coordSecrets, ListenPort: c.tn.coordPort,
		Bind: c.coordBind, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = coord.Run(ctx) }()
	select {
	case <-coord.Ready():
	case <-done:
		cancel()
		t.Fatal("coordinator stopped while starting")
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("coordinator did not start")
	}
	c.stopCoord, c.coordDone = cancel, done
}

func (c *chaosNet) killCoordinator(t *testing.T) {
	t.Helper()
	c.stopCoord()
	select {
	case <-c.coordDone:
	case <-time.After(10 * time.Second):
		t.Fatal("coordinator did not stop")
	}
}

// newChaosNet starts a coordinator and two devices whose binds can be
// disturbed. The laptop publishes the owner's documents (NetworkDir).
func newChaosNet(t *testing.T) *chaosNet {
	t.Helper()
	if testing.Short() {
		t.Skip("chaos test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &chaosNet{tn: tn, ctx: ctx, networkDirForOwner: filepath.Join(tn.base, "ag")}
	c.coordStore, c.aStore, c.bStore = tn.join(t, "coordinator"), tn.join(t, "laptop"), tn.join(t, "masaustu")
	startChaosCoordinator(t, c)
	c.aBind = testnet.NewChaosBind(testnet.NewLoopbackBind(), 11)
	c.bBind = testnet.NewChaosBind(testnet.NewLoopbackBind(), 13)
	c.aTUN, c.bTUN = tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	c.a, _ = startEngine(ctx, t, Config{Store: c.aStore, Secrets: tn.aKey, TUN: c.aTUN.TUN(), Bind: c.aBind, NetworkDir: c.networkDirForOwner})
	c.b, _ = startEngine(ctx, t, Config{Store: c.bStore, Secrets: tn.bKey, TUN: c.bTUN.TUN(), Bind: c.bBind})
	c.aSelf, _ = c.a.Self()
	c.bSelf, _ = c.b.Self()
	return c
}

// drain discards packets still in flight from an earlier ping.
func drain(ch *tuntest.ChannelTUN) {
	for {
		select {
		case <-ch.Inbound:
		case <-time.After(time.Second):
			return
		}
	}
}

func (c *chaosNet) ping(t *testing.T, fromA bool, within time.Duration) bool {
	t.Helper()
	if fromA {
		return expectPacket(t, c.aTUN, c.bTUN, c.aSelf.IPv4, c.bSelf.IPv4, within)
	}
	return expectPacket(t, c.bTUN, c.aTUN, c.bSelf.IPv4, c.aSelf.IPv4, within)
}

// TestChaosLossAndDelay: 20% loss and 30 ms extra delay on both devices
// still bring the tunnel up in both directions.
func TestChaosLossAndDelay(t *testing.T) {
	c := newChaosNet(t)
	for _, b := range []*testnet.ChaosBind{c.aBind, c.bBind} {
		b.SetLoss(0.2)
		b.SetDelay(30 * time.Millisecond)
	}
	if !c.ping(t, true, 45*time.Second) {
		t.Fatal("laptop -> masaustu did not arrive with loss and delay")
	}
	if !c.ping(t, false, 30*time.Second) {
		t.Fatal("masaustu -> laptop did not arrive with loss and delay")
	}
	if dropped, _ := c.aBind.Stats(); dropped == 0 {
		t.Fatal("no packet was dropped; the fault was not injected")
	}
}

// TestChaosCoordinatorOutage: the coordinator stops. Established tunnels
// keep working, a document signed meanwhile waits, and once a coordinator
// runs again it reaches the other device.
func TestChaosCoordinatorOutage(t *testing.T) {
	c := newChaosNet(t)
	if !c.ping(t, true, 20*time.Second) {
		t.Fatal("tunnel did not come up")
	}
	c.killCoordinator(t)
	if !c.ping(t, true, 10*time.Second) {
		t.Fatal("direct traffic stopped with the coordinator")
	}
	before := c.bStore.Document().Version
	// The owner signs a new document while the coordinator is down.
	commit(t, c.tn.n, func(doc *trust.Document) error {
		return doc.SetDisplayName("Kaos ağı")
	})
	time.Sleep(2 * time.Second)
	if c.bStore.Document().Version != before {
		t.Fatal("document arrived without a coordinator")
	}
	for deadline := time.Now().Add(20 * time.Second); c.b.Status().LastSyncError == ""; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("sync reports success without a coordinator")
		}
	}
	startChaosCoordinator(t, c)
	deadline := time.Now().Add(30 * time.Second)
	for c.bStore.Document().Version == before {
		if time.Now().After(deadline) {
			t.Fatalf("document did not arrive after the coordinator came back (masaustu: %+v)", c.b.Status())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !c.ping(t, true, 10*time.Second) {
		t.Fatal("tunnel lost after the coordinator came back")
	}
}

// TestChaosPartitionHeals: the laptop is cut off completely, then the
// network heals and traffic flows again without a restart.
func TestChaosPartitionHeals(t *testing.T) {
	c := newChaosNet(t)
	if !c.ping(t, true, 20*time.Second) {
		t.Fatal("tunnel did not come up")
	}
	c.aBind.SetPartition(true)
	drain(c.bTUN)
	if c.ping(t, true, 3*time.Second) {
		t.Fatal("traffic crossed a full partition")
	}
	c.aBind.SetPartition(false)
	if !c.ping(t, true, 30*time.Second) {
		t.Fatal("laptop -> masaustu did not recover after the partition")
	}
	if !c.ping(t, false, 15*time.Second) {
		t.Fatal("masaustu -> laptop did not recover after the partition")
	}
}

// TestChaosSplitBetweenDevices: the devices cannot reach each other
// directly but both reach the coordinator; traffic goes through the
// coordinator's relay.
func TestChaosSplitBetweenDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &chaosNet{tn: tn, ctx: ctx}
	c.coordStore, c.aStore, c.bStore = tn.join(t, "coordinator"), tn.join(t, "laptop"), tn.join(t, "masaustu")
	startChaosCoordinator(t, c)
	aPort, bPort := freeUDPPort(t), freeUDPPort(t)
	c.aBind = testnet.NewChaosBind(testnet.NewLoopbackBind(), 17)
	c.bBind = testnet.NewChaosBind(testnet.NewLoopbackBind(), 19)
	c.aBind.BlockPort(uint16(bPort), true)
	c.bBind.BlockPort(uint16(aPort), true)
	c.aTUN, c.bTUN = tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	c.a, _ = startEngine(ctx, t, Config{Store: c.aStore, Secrets: tn.aKey, TUN: c.aTUN.TUN(), Bind: c.aBind, ListenPort: aPort, RelayAfter: time.Second})
	c.b, _ = startEngine(ctx, t, Config{Store: c.bStore, Secrets: tn.bKey, TUN: c.bTUN.TUN(), Bind: c.bBind, ListenPort: bPort, RelayAfter: time.Second})
	c.aSelf, _ = c.a.Self()
	c.bSelf, _ = c.b.Self()
	if !c.ping(t, true, 40*time.Second) {
		t.Fatal("laptop -> masaustu did not arrive across the split")
	}
	stats, err := c.a.PeerStats()
	if err != nil {
		t.Fatal(err)
	}
	if !stats[c.bSelf.WireGuardKey].Relayed {
		t.Fatalf("split traffic is not relayed: %+v", stats[c.bSelf.WireGuardKey])
	}
}
