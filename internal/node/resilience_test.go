package node

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// testNet is a network with a coordinator key and two devices that may
// ping each other.
type testNet struct {
	n            *admin.Network
	base         string
	coordSecrets *trust.DeviceSecrets
	coordPort    int
	aKey, bKey   *trust.DeviceSecrets
}

func newTestNet(t *testing.T, coordEndpoint func(port int) string) *testNet {
	t.Helper()
	tn := &testNet{base: t.TempDir()}
	var err error
	tn.n, err = admin.Init(filepath.Join(tn.base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tn.coordSecrets, err = trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := tn.coordSecrets.PublicKeys()
	tn.coordPort = freeUDPPort(t)
	commit(t, tn.n, func(doc *trust.Document) error {
		return doc.SetCoordinator(coordEndpoint(tn.coordPort), coordWG)
	})
	tn.aKey = enroll(t, tn.n, "laptop")
	tn.bKey = enroll(t, tn.n, "masaustu")
	commit(t, tn.n, func(doc *trust.Document) error {
		if err := doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP}); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"masaustu"}, To: []string{"laptop"}, Protocol: trust.ProtocolICMP})
	})
	return tn
}

func (tn *testNet) join(t *testing.T, name string) *member.Store {
	return join(t, tn.n, filepath.Join(tn.base, name))
}

func startEngine(ctx context.Context, t *testing.T, cfg Config) (*Engine, chan error) {
	t.Helper()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 300 * time.Millisecond
	}
	cfg.Logger = testLogger(t, "["+filepath.Base(cfg.Store.Dir())+"]")
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	return e, done
}

// TestOfflineStartWithCachedEndpoints: the coordinator's name does not
// resolve and nothing answers, yet two devices reach each other with the
// stored document and the endpoints cached from an earlier run (F-005).
func TestOfflineStartWithCachedEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "koordinator.openscale.invalid:" + strconv.Itoa(port) })
	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aSelf, err := selfOf(aStore, tn.aKey)
	if err != nil {
		t.Fatal(err)
	}
	bSelf, err := selfOf(bStore, tn.bKey)
	if err != nil {
		t.Fatal(err)
	}
	aPort, bPort := freeUDPPort(t), freeUDPPort(t)
	now := time.Now()
	writeCache := func(store *member.Store, peer trust.Key, port int) {
		c := endpointCache{Version: endpointCacheVersion, NetworkID: store.Document().NetworkID, Peers: map[string]cachedEndpoint{
			hexKey(peer): {Endpoint: "127.0.0.1:" + strconv.Itoa(port), Seen: now.Add(-time.Hour)},
		}}
		if err := writeEndpointCache(filepath.Join(store.Dir(), endpointCacheFile), c); err != nil {
			t.Fatal(err)
		}
	}
	writeCache(aStore, bSelf.WireGuardKey, bPort)
	writeCache(bStore, aSelf.WireGuardKey, aPort)

	noDNS := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no network") }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, aDone := startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: aPort, Resolve: noDNS})
	_, bDone := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: bPort, Resolve: noDNS})

	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("laptop -> masaustu did not arrive without the coordinator")
	}
	if !expectPacket(t, bTUN, aTUN, bSelf.IPv4, aSelf.IPv4, 10*time.Second) {
		t.Fatal("masaustu -> laptop did not arrive without the coordinator")
	}
	for deadline := time.Now().Add(15 * time.Second); a.Status().LastSyncError == ""; {
		if time.Now().After(deadline) {
			t.Fatal("sync reported success without a coordinator")
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case err := <-aDone:
		t.Fatalf("laptop engine stopped: %v", err)
	case err := <-bDone:
		t.Fatalf("masaustu engine stopped: %v", err)
	default:
	}
}

func selfOf(store *member.Store, secrets *trust.DeviceSecrets) (trust.Device, error) {
	_, wg, err := secrets.PublicKeys()
	if err != nil {
		return trust.Device{}, err
	}
	for _, d := range store.Document().Devices {
		if d.WireGuardKey == wg {
			return d, nil
		}
	}
	return trust.Device{}, ErrNotMember
}

// TestEndpointsCachedWhileOnline: a working tunnel writes its endpoints so
// the next start can do without the coordinator.
func TestEndpointsCachedWhileOnline(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	coordStore, aStore, bStore := tn.join(t, "coordinator"), tn.join(t, "laptop"), tn.join(t, "masaustu")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: tn.coordSecrets, ListenPort: tn.coordPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()

	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, _ := startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN()})
	b, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN()})
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("tunnel did not come up")
	}
	path := filepath.Join(aStore.Dir(), endpointCacheFile)
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := readEndpointCache(path, aStore.Document().NetworkID, time.Now())
		if err == nil && c.Coordinator != nil && c.Peers[hexKey(bSelf.WireGuardKey)].Endpoint != "" {
			if !strings.HasPrefix(c.Peers[hexKey(bSelf.WireGuardKey)].Endpoint, "127.0.0.1:") {
				t.Fatalf("cached %+v", c.Peers)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("endpoints not cached: %+v %v", c, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestForceRelayEndToEnd: with relaying forced on both devices traffic
// flows through the coordinator although the direct path works (F-022).
func TestForceRelayEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	coordStore, aStore, bStore := tn.join(t, "coordinator"), tn.join(t, "laptop"), tn.join(t, "masaustu")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: tn.coordSecrets, ListenPort: tn.coordPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()

	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, _ := startEngine(ctx, t, Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ForceRelay: true})
	b, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ForceRelay: true})
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 20*time.Second) {
		t.Fatal("laptop -> masaustu did not arrive through the forced relay")
	}
	if !expectPacket(t, bTUN, aTUN, bSelf.IPv4, aSelf.IPv4, 10*time.Second) {
		t.Fatal("masaustu -> laptop did not arrive through the forced relay")
	}
	for _, c := range []struct {
		e    *Engine
		peer trust.Key
	}{{a, bSelf.WireGuardKey}, {b, aSelf.WireGuardKey}} {
		stats, err := c.e.PeerStats()
		if err != nil {
			t.Fatal(err)
		}
		if !stats[c.peer].Relayed {
			t.Fatalf("peer not relayed: %+v", stats[c.peer])
		}
	}
	rs := coord.RelayStats()
	if rs[aSelf.ID].Bytes == 0 || rs[bSelf.ID].Bytes == 0 {
		t.Fatalf("coordinator relayed nothing: %+v", rs)
	}
}

// TestRunStopsWhenTunnelInterfaceIsLost (F-146).
func TestRunStopsWhenTunnelInterfaceIsLost(t *testing.T) {
	if testing.Short() {
		t.Skip("engine test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	store := tn.join(t, "laptop")
	f := newFailingTUN()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, done := startEngine(ctx, t, Config{Store: store, Secrets: tn.aKey, TUN: f})
	time.Sleep(500 * time.Millisecond) // up and syncing (no coordinator answers)
	f.setReadErr(os.ErrClosed)
	select {
	case err := <-done:
		if !errors.Is(err, ErrTunnelLost) {
			t.Fatalf("Run returned %v, want ErrTunnelLost", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("engine kept running on a lost interface")
	}
}

// markRouter records the marks an ExitRouter sets, like the Linux router.
type markRouter struct {
	mu   sync.Mutex
	bind conn.Bind
}

func (r *markRouter) Enable(_ trust.Device, _ *trust.Document, _ string, bind conn.Bind) error {
	r.mu.Lock()
	r.bind = bind
	r.mu.Unlock()
	return bind.SetMark(0x4f53)
}

func (r *markRouter) Disable() error {
	r.mu.Lock()
	b := r.bind
	r.mu.Unlock()
	if b == nil {
		return nil
	}
	return b.SetMark(0)
}

// TestExitMarkSurvivesSocketOpen: the exit node is enabled before
// WireGuard opens its sockets, yet the mark is in place once they are open
// (the Linux fix: no more re-marking every second).
func TestExitMarkSurvivesSocketOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("engine test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	commit(t, tn.n, func(doc *trust.Document) error { return doc.SetExitNode("masaustu", true) })
	store := tn.join(t, "laptop")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := &markRouter{}
	e, _ := startEngine(ctx, t, Config{Store: store, Secrets: tn.aKey, TUN: tuntest.NewChannelTUN().TUN(), ExitNode: "masaustu", ExitRouter: router})
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.Lock()
		dev := e.dev
		e.mu.Unlock()
		if dev != nil {
			if raw, err := dev.IpcGet(); err == nil && strings.Contains(raw, "fwmark=20307") && e.ExitNode() == "masaustu" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("WireGuard device does not keep the exit node mark")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestConfigValidation(t *testing.T) {
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	store := tn.join(t, "laptop")
	base := Config{Store: store, Secrets: tn.aKey, TUN: tuntest.NewChannelTUN().TUN()}
	for _, c := range []struct {
		name string
		mod  func(*Config)
		ok   bool
	}{
		{"defaults", func(*Config) {}, true},
		{"MTU 1280", func(c *Config) { c.MTU = 1280 }, true},
		{"MTU 1420", func(c *Config) { c.MTU = 1420 }, true},
		{"MTU 1279", func(c *Config) { c.MTU = 1279 }, false},
		{"MTU 1421", func(c *Config) { c.MTU = 1421 }, false},
		{"MTU 9000", func(c *Config) { c.MTU = 9000 }, false},
		{"relay after 1h", func(c *Config) { c.RelayAfter = time.Hour }, false},
		{"relay after 10s", func(c *Config) { c.RelayAfter = 10 * time.Second }, true},
		{"direct retry 1s", func(c *Config) { c.DirectRetry = time.Second }, false},
		{"direct retry 2m", func(c *Config) { c.DirectRetry = 2 * time.Minute }, true},
		{"direct retry 2d", func(c *Config) { c.DirectRetry = 48 * time.Hour }, false},
		{"forced relay MTU 1280", func(c *Config) { c.ForceRelay, c.MTU = true, 1280 }, true},
		{"forced relay MTU 1420", func(c *Config) { c.ForceRelay, c.MTU = true, 1420 }, false},
		{"static endpoint", func(c *Config) { c.StaticEndpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:41641")} }, true},
		{"static loopback", func(c *Config) { c.StaticEndpoints = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:41641")} }, false},
		{"static port 0", func(c *Config) { c.StaticEndpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:0")} }, false},
		{"too many static", func(c *Config) { c.StaticEndpoints = make([]netip.AddrPort, 9) }, false},
		{"conntrack ok", func(c *Config) { c.ConnTrack.UDPTimeout = time.Minute }, true},
		{"conntrack bad", func(c *Config) { c.ConnTrack.MaxFlows = 1 }, false},
	} {
		cfg := base
		c.mod(&cfg)
		e, err := New(cfg)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if err == nil && c.name == "defaults" && e.cfg.MTU != DefaultMTU {
			t.Errorf("default MTU %d", e.cfg.MTU)
		}
	}
}

// TestNetworkChangeSyncsAtOnce: a network change wakes the run loop, which
// talks to the coordinator right away instead of at the next poll (F-004).
func TestNetworkChangeSyncsAtOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	coordStore, aStore := tn.join(t, "coordinator"), tn.join(t, "laptop")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: tn.coordSecrets, ListenPort: tn.coordPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()

	e, err := New(Config{Store: aStore, Secrets: tn.aKey, TUN: tuntest.NewChannelTUN().TUN(), PollInterval: time.Hour,
		Logger: testLogger(t, "[laptop]")})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	fp := "wlan0|192.168.1.5"
	e.netProbe = func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return fp, nil
	}
	e.netEvery = 50 * time.Millisecond
	go func() { _ = e.Run(ctx) }()

	waitSync := func(after time.Time, within time.Duration) bool {
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			if st := e.Status(); st.LastSync.After(after) && st.LastSyncError == "" {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}
	if !waitSync(time.Time{}, 15*time.Second) {
		t.Fatalf("first sync did not succeed: %+v", e.Status())
	}
	first := e.Status().LastSync
	time.Sleep(300 * time.Millisecond)
	if e.Status().LastSync != first {
		t.Fatal("synced again without a reason")
	}
	mu.Lock()
	fp = "eth0|10.0.0.7"
	mu.Unlock()
	if !waitSync(first, 10*time.Second) {
		t.Fatal("network change did not trigger a sync")
	}
}
