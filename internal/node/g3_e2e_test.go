package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/trust"
)

// TestEndToEndObfuscated runs two devices with the disguise on ("on",
// padding and jitter) and a coordinator that accepts it ("auto"), all on
// 127.0.0.1 (#612, #615, #616).
func TestEndToEndObfuscated(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordSecrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := coordSecrets.PublicKeys()
	coordPort := freeUDPPort(t)
	commit(t, n, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(coordPort), coordWG)
	})
	laptopKey := enroll(t, n, "laptop")
	masaustuKey := enroll(t, n, "masaustu")
	commit(t, n, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP})
	})
	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	laptopStore := join(t, n, filepath.Join(base, "laptop"))
	masaustuStore := join(t, n, filepath.Join(base, "masaustu"))

	ctx, cancel := context.WithCancel(context.Background())
	var stopped []chan struct{}
	// Engines and the coordinator write their state directories while
	// stopping; wait for them before the temporary directory goes.
	defer func() {
		cancel()
		for _, c := range stopped {
			select {
			case <-c:
			case <-time.After(10 * time.Second):
			}
		}
	}()

	key, err := obfs.DeriveKey(coordStore.Document().NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	coordBind, err := obfs.NewBind(coordinator.DefaultBind(), obfs.Options{Mode: obfs.ModeAuto, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort, Bind: coordBind, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	coordDone := make(chan error, 1)
	coordStopped := make(chan struct{})
	stopped = append(stopped, coordStopped)
	go func() { defer close(coordStopped); coordDone <- coord.Run(ctx) }()
	select {
	case <-coord.Ready():
	case err := <-coordDone:
		t.Fatalf("coordinator stopped: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not start")
	}

	g3 := G3Config{Obfs: ObfsConfig{Mode: obfs.ModeOn, Jitter: obfs.Jitter{Max: 2 * time.Millisecond}}}
	laptopTUN, masaustuTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), PollInterval: 300 * time.Millisecond,
			G3: g3, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatalf("node.New: %v", err)
		}
		done := make(chan struct{})
		stopped = append(stopped, done)
		go func() {
			defer close(done)
			if err := e.Run(ctx); err != nil && ctx.Err() == nil {
				t.Errorf("engine stopped: %v", err)
			}
		}()
		return e
	}
	laptop := start(laptopStore, laptopKey, laptopTUN)
	masaustu := start(masaustuStore, masaustuKey, masaustuTUN)
	laptopSelf, _ := laptop.Self()
	masaustuSelf, _ := masaustu.Self()
	if !expectPacket(t, laptopTUN, masaustuTUN, laptopSelf.IPv4, masaustuSelf.IPv4, 25*time.Second) {
		t.Fatal("laptop -> masaustu ICMP did not arrive through the disguised tunnel")
	}
	st := laptop.ObfsStatus()
	if st.Mode != "on" || st.Stats.Wrapped == 0 || st.Stats.Unwrapped == 0 || st.Stats.Plain != 0 {
		t.Fatalf("laptop disguise stats %+v", st)
	}
	if cs := coordBind.Stats(); cs.Unwrapped == 0 || cs.Wrapped == 0 {
		t.Fatalf("coordinator did not answer disguised: %+v", cs)
	}
}

// TestLostModeAndQuarantineFile checks the node side of lost mode (#609)
// and that a quarantine survives a restart (#626).
func TestLostModeAndQuarantineFile(t *testing.T) {
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordSecrets, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, coordWG, _ := coordSecrets.PublicKeys()
	commit(t, n, func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:9", coordWG) })
	laptopKey := enroll(t, n, "laptop")
	_ = enroll(t, n, "masaustu")
	store := join(t, n, filepath.Join(base, "laptop"))

	lost := false
	onLost := make(chan struct{}, 1)
	alerts := make(chan G3Alert, 4)
	newEngine := func() *Engine {
		e, err := New(Config{Store: store, Secrets: laptopKey, TUN: tuntest.NewChannelTUN().TUN(),
			G3: G3Config{
				Lost:    func(*trust.Document, trust.Device) bool { return lost },
				OnLost:  func() { onLost <- struct{}{} },
				OnAlert: func(a G3Alert) { alerts <- a },
				Decoys:  filter.G3Config{DecoyPorts: []uint16{22}},
			}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := newEngine()
	e.checkLost()
	if e.LostStatus().Lost || e.filter.Isolated() {
		t.Fatal("lost without being marked")
	}
	lost = true
	e.checkLost()
	if !e.LostStatus().Lost || !e.filter.Isolated() {
		t.Fatal("lost mode not applied")
	}
	select {
	case <-onLost:
	case <-time.After(5 * time.Second):
		t.Fatal("OnLost not called")
	}
	if a := <-alerts; a.Kind != "lost_mode" {
		t.Fatalf("alert %+v", a)
	}
	lost = false
	e.checkLost()
	if e.LostStatus().Lost || e.filter.Isolated() {
		t.Fatal("lost mode not lifted")
	}

	if err := e.Quarantine("yok", 0); err == nil {
		t.Fatal("unknown device quarantined")
	}
	if err := e.Quarantine("masaustu", 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Dir(), QuarantineFile)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l, err := loadQuarantine(path); err == nil && len(l) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("quarantine file not written")
		}
		time.Sleep(20 * time.Millisecond)
	}
	e2 := newEngine()
	if q := e2.Quarantined(); len(q) != 1 || q[0].Peer != "masaustu" {
		t.Fatalf("restart lost the quarantine: %+v", q)
	}
	if !e2.ReleaseQuarantine("masaustu") {
		t.Fatal("release")
	}
	// Let the asynchronous save finish before the directory is removed.
	for deadline = time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if l, err := loadQuarantine(path); err == nil && len(l) == 0 {
			break
		}
	}
}
