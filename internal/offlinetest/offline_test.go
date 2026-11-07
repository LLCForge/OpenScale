package offlinetest_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/offlinetest"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

func TestAllowed(t *testing.T) {
	for _, a := range []string{"127.0.0.1:80", "[::1]:443", "localhost:9", "127.8.9.10:1", "[::ffff:127.0.0.1]:5"} {
		if !offlinetest.Allowed("tcp", a) {
			t.Errorf("%s refused", a)
		}
	}
	if !offlinetest.Allowed("unix", "/run/openscale.sock") {
		t.Error("unix socket refused")
	}
	for _, a := range []string{"192.0.2.1:443", "[2001:db8::1]:53", "10.0.0.1:53", "example.invalid:80", "100.64.0.1:41820", "0.0.0.0:80"} {
		if offlinetest.Allowed("tcp", a) {
			t.Errorf("%s allowed", a)
		}
	}
}

func TestGuardRefusesAndRecords(t *testing.T) {
	g := offlinetest.New()
	if _, err := g.Dialer().Dial("udp", "192.0.2.1:53"); !errors.Is(err, offlinetest.ErrBlocked) {
		t.Fatalf("outside dial: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := g.Dialer().Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial: %v", err)
	}
	c.Close()
	if a := g.Attempts(); len(a) != 1 || a[0] != "udp4 192.0.2.1:53" {
		t.Fatalf("attempts %v", a)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestServiceAndPanelStayLocal starts the service with its panel, creates
// a network (tunnel and coordinator on loopback), uses the panel and
// requires that nothing tried to reach an outside address.
func TestServiceAndPanelStayLocal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the service with real loopback sockets")
	}
	if offlinetest.Isolated() {
		if err := offlinetest.CheckIsolated(); err != nil {
			t.Fatal(err)
		}
	}
	g := offlinetest.Install()
	t.Cleanup(g.Restore)

	ctx, cancel := context.WithCancel(context.Background())
	port := freePort(t)
	r, err := service.New(service.Config{
		DataDir:   t.TempDir(),
		PanelPort: port,
		Argon2:    trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1},
		Random:    rand.Reader,
		Hostname:  func() (string, error) { return "cevrimdisi", nil },
		Hooks: service.Hooks{
			OpenTunnel: func(context.Context, trust.Device, *trust.Document, int) (tun.Device, error) {
				return tuntest.NewChannelTUN().TUN(), nil
			},
			AllowTraffic: func(netip.Prefix) error { return nil },
		},
		PanelFiles:   fstest.MapFS{},
		PollInterval: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("service did not stop")
		}
	})
	select {
	case <-r.Ready():
	case err := <-done:
		t.Fatalf("service stopped: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("service did not start")
	}

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	get := func(path string) {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	get("/")
	if _, err := r.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: []byte("çevrimdışı test parolası 35"), EndpointHost: "127.0.0.1"}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		st := r.Status()
		if st.Device != nil && st.Device.Running && st.Coordinator != nil && st.Coordinator.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel and coordinator did not start: %+v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Let the background work (sync, health checks, history) run a while.
	for range 3 {
		get("/")
		get("/api/status")
		time.Sleep(700 * time.Millisecond)
	}
	if a := g.Attempts(); len(a) > 0 {
		t.Fatalf("outside connections attempted (#35): %v", a)
	}
}
