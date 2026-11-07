package node

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
)

// TestSoak is the long-running stability test (#575). It runs a
// coordinator and two devices in this process on 127.0.0.1, keeps traffic
// flowing both ways and publishes a new document regularly, and samples
// goroutines, heap and open file descriptors. A steady upward trend fails
// (testnet.DefaultSoakLimits); the release gate is a 72-hour run:
//
//	OPENSCALE_SOAK=72h go test -run TestSoak -timeout 0 ./internal/node
//
// OPENSCALE_SOAK_INTERVAL (default 1m) sets the sampling interval. Without
// OPENSCALE_SOAK the test is skipped.
func TestSoak(t *testing.T) {
	durText := os.Getenv("OPENSCALE_SOAK")
	if durText == "" {
		t.Skip("OPENSCALE_SOAK=<süre> ile çalışır (sürüm kapısı: 72h)")
	}
	dur, err := time.ParseDuration(durText)
	if err != nil || dur < time.Minute {
		t.Fatalf("OPENSCALE_SOAK %q: en az 1m bir süre olmalı", durText)
	}
	interval := time.Minute
	if v := os.Getenv("OPENSCALE_SOAK_INTERVAL"); v != "" {
		if interval, err = time.ParseDuration(v); err != nil || interval < time.Second {
			t.Fatalf("OPENSCALE_SOAK_INTERVAL %q geçersiz", v)
		}
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
		if err := doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP}); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"masaustu"}, To: []string{"laptop"}, Protocol: trust.ProtocolICMP})
	})
	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	laptopStore := join(t, n, filepath.Join(base, "laptop"))
	masaustuStore := join(t, n, filepath.Join(base, "masaustu"))

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
	laptopTUN, masaustuTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, networkDir string) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), NetworkDir: networkDir, PollInterval: 2 * time.Second, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = e.Run(ctx) }()
		return e
	}
	laptop := start(laptopStore, laptopKey, laptopTUN, netDir)
	masaustu := start(masaustuStore, masaustuKey, masaustuTUN, "")
	ls, _ := laptop.Self()
	ms, _ := masaustu.Self()
	if !expectPacket(t, laptopTUN, masaustuTUN, ls.IPv4, ms.IPv4, 30*time.Second) {
		t.Fatal("tunnel did not come up")
	}

	var soak testnet.Soak
	deadline := time.Now().Add(dur)
	lost := 0
	for i := 0; time.Now().Before(deadline); i++ {
		if !expectPacket(t, laptopTUN, masaustuTUN, ls.IPv4, ms.IPv4, 20*time.Second) ||
			!expectPacket(t, masaustuTUN, laptopTUN, ms.IPv4, ls.IPv4, 20*time.Second) {
			lost++
			if lost > 3 {
				t.Fatalf("tunnel lost for %d rounds in a row at round %d", lost, i)
			}
		} else {
			lost = 0
		}
		if i%10 == 9 {
			// A new document version travels through the network.
			commit(t, n, func(doc *trust.Document) error {
				return doc.SetDeviceTags("masaustu", []string{"tur" + strconv.Itoa(i%3)})
			})
		}
		soak.Take(time.Now())
		time.Sleep(interval)
	}
	samples := soak.Samples()
	first, last := samples[0], samples[len(samples)-1]
	t.Logf("%d örnek: goroutine %d -> %d, yığın %d -> %d MiB, fd %d -> %d", len(samples),
		first.Goroutines, last.Goroutines, first.HeapBytes>>20, last.HeapBytes>>20, first.FDs, last.FDs)
	if err := soak.Check(testnet.DefaultSoakLimits); err != nil {
		t.Fatal(err)
	}
}
