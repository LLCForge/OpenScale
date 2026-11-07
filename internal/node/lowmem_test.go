package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/memprofile"
	"github.com/openscale/openscale/internal/trust"
)

// TestLowMemoryProfileBudget guards the low memory profile (#392): with
// the profile applied, a coordinator and two devices in this one process
// on 127.0.0.1 bring a tunnel up and pass traffic, and the live Go memory
// of the whole process (heap in use and goroutine stacks) stays under
// memprofile.LowBudget, the budget of a single device on a Raspberry Pi
// Zero. Three components under the budget of one leaves room for the
// test framework and is a strict upper bound for a device alone.
func TestLowMemoryProfileBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	low, err := memprofile.Lookup(memprofile.NameLow)
	if err != nil {
		t.Fatal(err)
	}
	oldLimit := debug.SetMemoryLimit(-1)
	oldGC := debug.SetGCPercent(-1)
	debug.SetGCPercent(oldGC)
	memprofile.Apply(low, func(string) string { return "" })
	t.Cleanup(func() {
		memprofile.Apply(memprofile.Profile{Name: memprofile.NameDefault}, func(string) string { return "" })
		debug.SetMemoryLimit(oldLimit)
		debug.SetGCPercent(oldGC)
	})

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
	aKey := enroll(t, n, "kucuk")
	bKey := enroll(t, n, "sunucu")
	commit(t, n, func(doc *trust.Document) error {
		if err := doc.AddRule(trust.Rule{From: []string{"kucuk"}, To: []string{"sunucu"}, Protocol: trust.ProtocolICMP}); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"sunucu"}, To: []string{"kucuk"}, Protocol: trust.ProtocolICMP})
	})
	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	aStore := join(t, n, filepath.Join(base, "kucuk"))
	bStore := join(t, n, filepath.Join(base, "sunucu"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	select {
	case <-coord.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("coordinator did not start")
	}
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), PollInterval: 2 * time.Second, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = e.Run(ctx) }()
		return e
	}
	a := start(aStore, aKey, aTUN)
	b := start(bStore, bKey, bTUN)
	as, _ := a.Self()
	bs, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, as.IPv4, bs.IPv4, 30*time.Second) {
		t.Fatal("tunnel did not come up")
	}
	for i := 0; i < 20; i++ {
		if !expectPacket(t, aTUN, bTUN, as.IPv4, bs.IPv4, 10*time.Second) || !expectPacket(t, bTUN, aTUN, bs.IPv4, as.IPv4, 10*time.Second) {
			t.Fatalf("traffic lost at round %d", i)
		}
	}
	if got := a.filter.Limits().MaxFlows; got != low.ConnTrack.MaxFlows {
		t.Fatalf("engine flow table limit %d, want the profile's %d", got, low.ConnTrack.MaxFlows)
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	live := ms.HeapInuse + ms.StackInuse
	t.Logf("düşük profil: yığın %d KiB, yığıt %d KiB, toplam %d KiB (bütçe %d KiB)", ms.HeapInuse>>10, ms.StackInuse>>10, live>>10, memprofile.LowBudget>>10)
	if live > memprofile.LowBudget {
		t.Fatalf("live memory %d KiB exceeds the low profile budget of %d KiB", live>>10, memprofile.LowBudget>>10)
	}
}
