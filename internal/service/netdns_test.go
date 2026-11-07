package service

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func dnsDoc() *trust.Document {
	return &trust.Document{
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd12:3456:789a::/48"),
		DNS: &trust.DNSSettings{
			Nameservers: addrs("100.80.0.5"),
			Split:       []trust.SplitDNS{{Domain: "ev.lan", Nameservers: addrs("100.80.0.5")}},
		},
	}
}

func TestNetworkDNSForFollowsExitNode(t *testing.T) {
	doc := dnsDoc()
	n := NetworkDNSFor(doc, false)
	if len(n.Nameservers) != 1 || len(n.Split) != 1 || len(n.Overlay) != 2 {
		t.Fatalf("without exit node: %+v", n)
	}
	n = NetworkDNSFor(doc, true)
	if len(n.Nameservers) != 0 || len(n.Split) != 1 {
		t.Fatalf("with exit node the catch-all resolver must be left out: %+v", n)
	}
	if !NetworkDNSFor(&trust.Document{}, false).Empty() || !NetworkDNSFor(nil, false).Empty() {
		t.Fatal("no dns section must apply nothing")
	}
}

// recordedApply records what a DNSWatch applies.
type recordedApply struct {
	mu    sync.Mutex
	calls []osnet.NetworkDNS
	fail  error
}

func (a *recordedApply) apply(_ context.Context, _ osnet.DNSConfig, n osnet.NetworkDNS) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, n)
	return a.fail
}

func (a *recordedApply) snapshot() []osnet.NetworkDNS {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]osnet.NetworkDNS{}, a.calls...)
}

func TestDNSWatchAppliesChanges(t *testing.T) {
	var (
		mu     sync.Mutex
		doc    = dnsDoc()
		exit   bool
		accept = true
	)
	get := func(f func()) { mu.Lock(); f(); mu.Unlock() }
	rec := &recordedApply{}
	var reports []bool
	w := DNSWatch{
		Magic:      osnet.DNSConfig{Interface: "OpenScale", Server: netip.MustParseAddr("100.80.255.254"), Domain: "openscale.internal"},
		Document:   func() (d *trust.Document) { get(func() { d = doc }); return d },
		ExitActive: func() (b bool) { get(func() { b = exit }); return b },
		Accept:     func() (b bool) { get(func() { b = accept }); return b },
		Apply:      rec.apply,
		Report:     func(active bool, _ error) { get(func() { reports = append(reports, active) }) },
		Every:      5 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "first apply", 2*time.Second, func() bool { return len(rec.snapshot()) == 1 })
	if c := rec.snapshot()[0]; len(c.Nameservers) != 1 || len(c.Split) != 1 {
		t.Fatalf("first apply: %+v", c)
	}
	// Unchanged settings are not applied again.
	time.Sleep(30 * time.Millisecond)
	if n := len(rec.snapshot()); n != 1 {
		t.Fatalf("re-applied unchanged settings: %d calls", n)
	}
	get(func() { exit = true })
	waitFor(t, "exit node drops the catch-all", 2*time.Second, func() bool {
		c := rec.snapshot()
		return len(c) == 2 && len(c[1].Nameservers) == 0 && len(c[1].Split) == 1
	})
	get(func() { accept = false })
	waitFor(t, "refusal removes everything", 2*time.Second, func() bool {
		c := rec.snapshot()
		return len(c) == 3 && c[2].Empty()
	})
	// The exit node stays in use: a change of it alone is applied too, on
	// Linux every name then goes through MagicDNS (ADR-0034).
	get(func() {
		accept = true
		doc = &trust.Document{IPv4Prefix: doc.IPv4Prefix, IPv6Prefix: doc.IPv6Prefix}
	})
	time.Sleep(30 * time.Millisecond)
	if n := len(rec.snapshot()); n != 3 {
		t.Fatalf("empty to empty applied again: %d calls", n)
	}
	get(func() {
		if len(reports) != 3 || !reports[0] || !reports[1] || reports[2] {
			t.Errorf("reports = %v", reports)
		}
	})
}

func TestDNSWatchWaitsAfterFailure(t *testing.T) {
	rec := &recordedApply{fail: errors.New("powershell yok")}
	now := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	w := DNSWatch{
		Magic:    osnet.DNSConfig{Interface: "OpenScale", Server: netip.MustParseAddr("100.80.255.254"), Domain: "openscale.internal"},
		Document: dnsDoc,
		Apply:    rec.apply,
		Every:    2 * time.Millisecond,
		Now:      func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "first try", 2*time.Second, func() bool { return len(rec.snapshot()) == 1 })
	time.Sleep(30 * time.Millisecond)
	if n := len(rec.snapshot()); n != 1 {
		t.Fatalf("retried before the delay: %d calls", n)
	}
	clockMu.Lock()
	now = now.Add(dnsRetryAfter)
	clockMu.Unlock()
	waitFor(t, "retry after the delay", 2*time.Second, func() bool { return len(rec.snapshot()) == 2 })
}

func TestPromoteRotatedKey(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	old, err := trust.GenerateDeviceSecrets(rand.Reader, now)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, s *trust.DeviceSecrets) {
		data, err := trust.MarshalDeviceSecrets(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := securefile.Replace(filepath.Join(dir, name), data); err != nil {
			t.Fatal(err)
		}
	}
	write(deviceKeyFile, old)
	next, _, _, err := old.NewKeyRotation(rand.Reader, "0123456789abcdef0123456789abcdef", now)
	if err != nil {
		t.Fatal(err)
	}
	_, oldWG, _ := old.PublicKeys()
	_, nextWG, _ := next.PublicKeys()
	docWith := func(k trust.Key) *trust.Document {
		return &trust.Document{Devices: []trust.Device{{Name: "laptop", WireGuardKey: k}}}
	}

	// Nothing pending.
	if _, ok, err := PromoteRotatedKey(dir, docWith(nextWG)); ok || err != nil {
		t.Fatalf("nothing pending: %v %v", ok, err)
	}
	write(NextKeyFile, next)
	// Not approved yet: the document still lists the old key.
	if _, ok, err := PromoteRotatedKey(dir, docWith(oldWG)); ok || err != nil {
		t.Fatalf("before approval: %v %v", ok, err)
	}
	got, ok, err := PromoteRotatedKey(dir, docWith(nextWG))
	if !ok || err != nil {
		t.Fatalf("after approval: %v %v", ok, err)
	}
	if _, wg, _ := got.PublicKeys(); wg != nextWG {
		t.Fatal("returned the wrong keys")
	}
	cur, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, wg, _ := cur.PublicKeys(); wg != nextWG {
		t.Fatal("device.key was not replaced")
	}
	if _, err := os.Stat(filepath.Join(dir, NextKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("device.key.next left behind")
	}
	kept, err := readSecrets(filepath.Join(dir, deviceKeyFile+".old-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, wg, _ := kept.PublicKeys(); wg != oldWG {
		t.Fatal("old key not kept")
	}
}

func TestTunnelMTUAndRelaySettings(t *testing.T) {
	if got := tunnelMTUFor(settings{}); got != 1280 {
		t.Fatalf("default MTU %d", got)
	}
	if got := tunnelMTUFor(settings{MTU: 1400}); got != 1400 {
		t.Fatalf("saved MTU %d", got)
	}
	if got := tunnelMTUFor(settings{MTU: 9000}); got != 1280 {
		t.Fatalf("unusable MTU %d", got)
	}
	if err := validRelayLimits(0, 0); err != nil {
		t.Fatal(err)
	}
	if validRelayLimits(10, 0) == nil || validRelayLimits(0, 10) == nil {
		t.Fatal("tiny relay limits accepted")
	}
}

func TestSetAdvancedNeedsMembership(t *testing.T) {
	r, _, _ := ksRuntime(t, settings{})
	mtu := 1400
	if err := r.SetAdvanced(panel.AdvancedSettings{MTU: &mtu}); err == nil {
		t.Fatal("accepted without a membership")
	}
	rate := int64(1 << 20)
	if err := r.SetAdvanced(panel.AdvancedSettings{RelayRate: &rate}); err == nil {
		t.Fatal("relay limits accepted without a coordinator")
	}
	if err := r.SetAcceptNetworkDNS(false); err == nil {
		t.Fatal("DNS choice accepted without a membership")
	}
}

// TestServiceAppliesNetworkSettings runs a whole network on loopback and
// checks that the service follows the signed dns section, the local DNS
// choice, the advanced settings and the network name.
func TestServiceAppliesNetworkSettings(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &recordedApply{}
	var mtuMu sync.Mutex
	var mtus []int
	owner := newRuntime(t, ctx, filepath.Join(t.TempDir(), "owner"), "Masaustu", func(c *Config) {
		c.Hooks.ConfigureDNS = func(context.Context, osnet.DNSConfig) error { return nil }
		c.Hooks.RemoveDNS = func(context.Context, osnet.DNSConfig) error { return nil }
		c.Hooks.ConfigureNetworkDNS = rec.apply
		c.Hooks.OpenTunnel = func(_ context.Context, _ trust.Device, _ *trust.Document, mtu int) (tun.Device, error) {
			mtuMu.Lock()
			mtus = append(mtus, mtu)
			mtuMu.Unlock()
			return tuntest.NewChannelTUN().TUN(), nil
		}
	})
	n, err := owner.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "owner tunnel", 10*time.Second, func() bool {
		st := owner.Status()
		return st.Device != nil && st.Device.Running
	})
	st := owner.Status()
	if !st.Device.AcceptNetworkDNS || st.Device.MTU != 0 || st.NetworkName != "" {
		t.Fatalf("defaults: %+v", st.Device)
	}

	doc, _ := n.Document()
	self, _ := doc.DeviceByName("masaustu")
	if _, err := n.SetDNS(testPass, &trust.DNSSettings{Split: []trust.SplitDNS{{Domain: "ev.lan", Nameservers: []netip.Addr{self.IPv4}}}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SetDisplayName(testPass, "Ev ağı", time.Now()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "split DNS applied", 15*time.Second, func() bool {
		c := rec.snapshot()
		return len(c) > 0 && len(c[len(c)-1].Split) == 1 && owner.Status().Device.NetworkDNSActive
	})
	if got := owner.Status().NetworkName; got != "Ev ağı" {
		t.Fatalf("network name %q", got)
	}

	if err := owner.SetAcceptNetworkDNS(false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "network DNS removed", 10*time.Second, func() bool {
		c := rec.snapshot()
		return c[len(c)-1].Empty() && !owner.Status().Device.AcceptNetworkDNS
	})

	mtu, force := 1400, true
	if err := owner.SetAdvanced(panel.AdvancedSettings{MTU: &mtu, ForceRelay: &force}); err == nil {
		t.Fatal("forced relay with MTU 1400 accepted")
	}
	if err := owner.SetAdvanced(panel.AdvancedSettings{MTU: &mtu}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel restarted with the new MTU", 15*time.Second, func() bool {
		mtuMu.Lock()
		defer mtuMu.Unlock()
		return len(mtus) >= 2 && mtus[len(mtus)-1] == 1400 && owner.Status().Device.Running
	})
	if owner.Status().Device.MTU != 1400 {
		t.Fatal("MTU not reported")
	}
	rate := int64(1 << 20)
	if err := owner.SetAdvanced(panel.AdvancedSettings{RelayRate: &rate}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "coordinator restarted", 15*time.Second, func() bool {
		c := owner.Status().Coordinator
		return c != nil && c.Running && c.RelayRate == rate
	})
}

// lostTUN fails every read with os.ErrClosed once lost is set, like a
// Wintun adapter removed underneath the service.
type lostTUN struct {
	tun.Device
	lost *atomic.Bool
}

func (l lostTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if l.lost.Load() {
		return 0, os.ErrClosed
	}
	return l.Device.Read(bufs, sizes, offset)
}

// TestTunnelLostRecreatesInterface checks F-146: when the interface dies,
// the service opens a new one after a short delay.
func TestTunnelLostRecreatesInterface(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lost atomic.Bool
	var opened atomic.Int32
	var current atomic.Pointer[tuntest.ChannelTUN]
	owner := newRuntime(t, ctx, filepath.Join(t.TempDir(), "owner"), "Masaustu", func(c *Config) {
		c.Hooks.OpenTunnel = func(context.Context, trust.Device, *trust.Document, int) (tun.Device, error) {
			opened.Add(1)
			ch := tuntest.NewChannelTUN()
			current.Store(ch)
			return lostTUN{Device: ch.TUN(), lost: &lost}, nil
		}
	})
	if _, err := owner.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel", 10*time.Second, func() bool { st := owner.Status(); return st.Device != nil && st.Device.Running })
	first := opened.Load()
	lost.Store(true)
	// Wake the blocked read so it sees the failure.
	select {
	case current.Load().Outbound <- []byte{0x45}:
	case <-time.After(20 * time.Second): // generous: the full suite runs packages in parallel
		t.Fatal("tunnel read did not take the packet")
	}
	waitFor(t, "interface failure noticed", 10*time.Second, func() bool { return opened.Load() > first })
	lost.Store(false)
	waitFor(t, "tunnel back", 10*time.Second, func() bool { st := owner.Status(); return st.Device != nil && st.Device.Running })
}
