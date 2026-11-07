package node

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
)

// toggleBind drops every packet sent to one UDP port while blocked is set.
type toggleBind struct {
	conn.Bind
	port    string
	blocked atomic.Bool
}

func (b *toggleBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.blocked.Load() && strings.HasSuffix(ep.DstToString(), ":"+b.port) {
		return nil
	}
	return b.Bind.Send(bufs, ep)
}

func startCoordinator(ctx context.Context, t *testing.T, tn *testNet) {
	t.Helper()
	store := tn.join(t, "koordinator")
	c, err := coordinator.New(coordinator.Config{Store: store, Secrets: tn.coordSecrets, ListenPort: tn.coordPort, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Run(ctx) }()
	<-c.Ready()
}

// A document change reaches a device through the pushed notice long before
// its next poll, and is downloaded compressed (ADR-0026).
func TestPushedNoticeSyncsAtOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	// laptop watches the owner's network directory and publishes changes.
	startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t), NetworkDir: filepath.Join(tn.base, "ag")})
	// masaustu polls only once a minute.
	b, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t), PollInterval: time.Minute})

	waitFor(t, 10*time.Second, "masaustu learns the coordinator features", func() bool {
		// ADR-0025/0026 features plus the membership ones (ADR-0028).
		f := b.CoordinatorFeatures()
		return len(f) >= 4
	})
	before := bStore.Document().Version
	// Let the first poll pass so only the push can explain a quick update.
	time.Sleep(500 * time.Millisecond)
	commit(t, tn.n, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}})
	})
	waitFor(t, 15*time.Second, "masaustu adopts the new document without polling", func() bool {
		return b.Status().DocumentVersion > before
	})
}

// A relayed peer moves to a direct path as soon as a signed probe proves it
// works, long before the scheduled direct retry (ADR-0025).
func TestProbeLeavesRelayWhenDirectWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	allowLoopbackProbes = true
	defer func() { allowLoopbackProbes = false }()
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCoordinator(ctx, t, tn)
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aPort, bPort := freeUDPPort(t), freeUDPPort(t)
	aBind := &toggleBind{Bind: testnet.NewLoopbackBind(), port: strconv.Itoa(bPort)}
	bBind := &toggleBind{Bind: testnet.NewLoopbackBind(), port: strconv.Itoa(aPort)}
	aBind.blocked.Store(true)
	bBind.blocked.Store(true)
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, err := New(Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: aPort, Bind: aBind,
		PollInterval: 300 * time.Millisecond, RelayAfter: time.Second, DirectRetry: 24 * time.Hour, Logger: testLogger(t, "[laptop]")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: bPort, Bind: bBind,
		PollInterval: 300 * time.Millisecond, RelayAfter: time.Second, DirectRetry: 24 * time.Hour, Logger: testLogger(t, "[masaustu]")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*Engine{a, b} {
		e.probe.interval, e.probe.maxWait = 300*time.Millisecond, 600*time.Millisecond
		go func(e *Engine) { _ = e.Run(ctx) }(e)
	}
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 30*time.Second) {
		t.Fatal("no traffic through the relay")
	}
	waitFor(t, 10*time.Second, "laptop on the relay", func() bool {
		st, err := a.PeerStats()
		return err == nil && st[bSelf.WireGuardKey].Relayed
	})
	// The relay test works while relayed.
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	if _, err := a.TestRelay(rctx, "masaustu"); err != nil {
		t.Fatalf("relay test: %v", err)
	}
	rcancel()

	// The NAT "opens": only probes can notice before the 24 h retry.
	aBind.blocked.Store(false)
	bBind.blocked.Store(false)
	waitFor(t, 20*time.Second, "laptop moves to the direct path", func() bool {
		st, err := a.PeerStats()
		p := st[bSelf.WireGuardKey]
		return err == nil && !p.Relayed && p.Endpoint.IsValid() && p.LastHandshakeUnix > 0
	})
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 10*time.Second) {
		t.Fatal("no traffic on the direct path")
	}
	paths, err := a.PeerPaths()
	if err != nil || len(paths) != 1 || paths[0].BestProbed == "" || len(paths[0].History) < 2 {
		t.Fatalf("peer paths = %+v %v", paths, err)
	}
	rep, err := a.NetCheck(ctx)
	if err != nil || !rep.CoordinatorReachable || rep.MappedEndpoint == "" || rep.DirectPeers != 1 {
		t.Fatalf("netcheck = %+v %v", rep, err)
	}
}

func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
