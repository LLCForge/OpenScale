package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/support"
	"github.com/openscale/openscale/internal/testnet/evilcoord"
	"github.com/openscale/openscale/internal/trust"
)

// Remote support toolbox end to end over 127.0.0.1 (#852, ADR-0232): the
// helper's Apps asks the target's Apps, the person at the target approves,
// the notice shows, and only the root-signed rules grant anything, even
// with a coordinator that forges, alters or replays documents.

type supportFake struct{ killed atomic.Int32 }

func (f *supportFake) Processes(context.Context) ([]support.Process, error) {
	return []support.Process{{PID: 4242, Name: "notepad.exe", MemoryKB: 10}}, nil
}
func (f *supportFake) Services(context.Context) ([]support.Service, error) { return nil, nil }
func (f *supportFake) Events(context.Context) ([]support.Event, error) {
	return []support.Event{{Time: time.Now(), Level: "error", Source: "x", Message: `C:\Users\ali\a.txt`}}, nil
}
func (f *supportFake) Disks(context.Context) ([]support.Disk, error)          { return nil, nil }
func (f *supportFake) Startup(context.Context) ([]support.StartupItem, error) { return nil, nil }
func (f *supportFake) Kill(context.Context, int, string) error {
	f.killed.Add(1)
	return nil
}

type fakeFrame struct{ closed *atomic.Int32 }

func (f fakeFrame) Close() error { f.closed.Add(1); return nil }

// supportNet is a root-signed network: laptop may read nas, vps may also
// end processes on nas, tv has no rule.
func supportNet(t *testing.T) (*compromiseNet, map[string]trust.Device) {
	t.Helper()
	pub, priv, err := trust.GenerateRootKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := trust.NewNetworkID(rand.Reader)
	doc, err := trust.NewDocument(id, "ev.test", netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64"), compromiseNow, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"nas", "laptop", "tv", "vps"} {
		compromiseAddDevice(t, doc, n)
	}
	for _, r := range []trust.Rule{
		{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSupport},
		{From: []string{"vps"}, To: []string{"nas"}, Service: trust.ServiceSupport, AllowKill: true},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	devs := map[string]trust.Device{}
	for _, d := range doc.Devices {
		devs[d.Name] = d
	}
	return &compromiseNet{root: priv, anchor: trust.Anchor{RootKey: pub, NetworkID: id}, doc: doc, env: signEnv(t, doc, priv)}, devs
}

func installSupportFakes(t *testing.T) (*supportFake, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	coll := &supportFake{}
	opened, closed := &atomic.Int32{}, &atomic.Int32{}
	prevColl, prevFrame := supportCollector, newSupportFrame
	supportCollector = coll
	newSupportFrame = func(support.SessionInfo) (rdesk.SessionFrame, error) {
		opened.Add(1)
		return fakeFrame{closed}, nil
	}
	t.Cleanup(func() { supportCollector, newSupportFrame = prevColl, prevFrame })
	return coll, opened, closed
}

func TestSupportEndToEnd(t *testing.T) {
	coll, opened, closed := installSupportFakes(t)
	n, devs := supportNet(t)
	store, err := member.JoinAnchor(t.TempDir(), n.anchor, n.env, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	// The target, nas: every connection comes from the address in from.
	var from atomic.Value
	from.Store(devs["laptop"].IPv4)
	nas := NewApps(AppsConfig{Dir: t.TempDir(), Engine: func() AppEngine { return &storeEngine{store: store, self: "nas"} }, Interval: 20 * time.Millisecond})
	nas.listenHost, nas.anyPort = appsLoopback, true
	nas.mapPeer = func(netip.Addr) netip.Addr { return from.Load().(netip.Addr) }
	var mu sync.Mutex
	var notes []string
	nas.SetSupportNotify(func(kind, peer, msg string) { mu.Lock(); notes = append(notes, kind); mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { nas.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	addr := boundAddr(t, nas, trust.ServiceSupport)

	// The person at nas approves every request in this test.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			for _, p := range nas.SupportLocal().Pending {
				_ = nas.SupportDecide(p.ID, true)
			}
		}
	}()

	// The helper, laptop, through its own Apps.
	helperStore, err := member.JoinAnchor(t.TempDir(), n.anchor, n.env, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	laptop := NewApps(AppsConfig{Dir: t.TempDir(), Engine: func() AppEngine { return &storeEngine{store: helperStore, self: "laptop"} }})
	laptop.supportState().target = func(trust.Device) netip.AddrPort { return addr }
	snap, err := laptop.SupportSnapshot(ctx, "nas", support.KindEvents)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Events[0].Message != `C:\Users\***\a.txt` {
		t.Fatalf("masked event: %q", snap.Events[0].Message)
	}
	if opened.Load() != 1 || len(nas.SupportLocal().Sessions) != 1 {
		t.Fatal("the notice must be open while the session lasts")
	}
	mu.Lock()
	gotNotes := append([]string(nil), notes...)
	mu.Unlock()
	if len(gotNotes) < 2 || gotNotes[0] != "support_request" || gotNotes[1] != "support_connected" {
		t.Fatalf("notifications: %v", gotNotes)
	}
	// laptop's rule only reads: the helper refuses and so does the target.
	if err := laptop.SupportKill(ctx, "nas", 4242, "notepad.exe"); err == nil {
		t.Fatal("kill without support.kill")
	}
	c := support.NewClient(nil)
	var re *support.RemoteError
	if err := c.Kill(ctx, addr, 4242, "notepad.exe"); !errors.As(err, &re) || re.Status != 403 {
		t.Fatalf("target must refuse kill: %v", err)
	}
	// vps holds support.kill.
	from.Store(devs["vps"].IPv4)
	if err := c.Kill(ctx, addr, 4242, "notepad.exe"); err != nil || coll.killed.Load() != 1 {
		t.Fatalf("vps kill: %v", err)
	}
	// The person at nas ends everything.
	if n := nas.SupportEndAll(); n != 2 || closed.Load() != 2 {
		t.Fatalf("ended %d, closed %d", n, closed.Load())
	}
	// tv has no rule.
	from.Store(devs["tv"].IPv4)
	if _, err := c.Snapshot(ctx, addr, support.KindProcesses); !errors.As(err, &re) || re.Status != 403 {
		t.Fatalf("tv: %v", err)
	}
}

func TestSupportCompromisedCoordinatorGrantsNothing(t *testing.T) {
	_, _, _ = installSupportFakes(t)
	n, devs := supportNet(t)
	store, err := member.JoinAnchor(t.TempDir(), n.anchor, n.env, compromiseNow)
	if err != nil {
		t.Fatal(err)
	}
	// What a compromised coordinator can send: forged, altered, stripped
	// and foreign documents, and its own document that adds an attacker
	// device with support.kill on nas and gives tv the same.
	coord, err := evilcoord.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	coord.Publish(n.env)
	var attacks [][]byte
	for _, b := range []evilcoord.Behavior{evilcoord.Forge, evilcoord.Tamper, evilcoord.Strip, evilcoord.Foreign} {
		coord.SetBehavior(b)
		data, err := coord.Serve("nas")
		if err != nil {
			t.Fatal(err)
		}
		attacks = append(attacks, data)
	}
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	next, err := n.doc.Next(compromiseNow, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	compromiseAddDevice(t, next, "saldirgan")
	for _, r := range []trust.Rule{
		{From: []string{"saldirgan", "tv"}, To: []string{"nas"}, Service: trust.ServiceSupport, AllowKill: true},
	} {
		if err := next.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	attacks = append(attacks, signEnv(t, next, attacker))
	for i, data := range attacks {
		if changed, err := store.Accept(data, compromiseNow.Add(time.Minute)); err == nil || changed {
			t.Fatalf("attack %d accepted", i)
		}
	}
	nas := NewApps(AppsConfig{Dir: t.TempDir(), Engine: func() AppEngine { return &storeEngine{store: store, self: "nas"} }})
	attackerDev, _ := next.DeviceByName("saldirgan")
	// The legitimate rules still work.
	if d := nas.authorizeSupport(devs["vps"].IPv4, support.ModeKill); !d.Allowed {
		t.Fatalf("vps refused: %+v", d)
	}
	for _, from := range []netip.Addr{attackerDev.IPv4, devs["tv"].IPv4, devs["nas"].IPv4, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.9")} {
		for _, mode := range []support.Mode{support.ModeRead, support.ModeKill} {
			if d := nas.authorizeSupport(from, mode); d.Allowed {
				t.Errorf("support %s from %v allowed", mode, from)
			}
		}
	}
	if d := nas.authorizeSupport(devs["laptop"].IPv4, support.ModeKill); d.Allowed {
		t.Fatal("laptop's read rule must not grant kill")
	}
	// Over the wire too: the attacker's address gets 403, never a consent
	// question.
	nas.listenHost, nas.anyPort = appsLoopback, true
	nas.mapPeer = func(netip.Addr) netip.Addr { return attackerDev.IPv4 }
	nas.cfg.Interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { nas.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	addr := boundAddr(t, nas, trust.ServiceSupport)
	var re *support.RemoteError
	if _, err := support.NewClient(nil).Snapshot(ctx, addr, support.KindProcesses); !errors.As(err, &re) || re.Status != 403 {
		t.Fatalf("attacker over the wire: %v", err)
	}
	if v := nas.SupportLocal(); len(v.Pending) != 0 || len(v.Sessions) != 0 {
		t.Fatal("an unauthorized request must not reach the person at the device")
	}
}
