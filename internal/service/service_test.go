package service

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

var testPass = []byte("servis testi parolası 42")

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func newRuntime(t *testing.T, ctx context.Context, dir, host string, opts ...func(*Config)) *Runtime {
	t.Helper()
	cfg := Config{
		DataDir:   dir,
		PanelPort: freeTCPPort(t),
		Argon2:    trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1},
		Random:    rand.Reader,
		Hostname:  func() (string, error) { return host, nil },
		Hooks: Hooks{
			OpenTunnel: func(context.Context, trust.Device, *trust.Document, int) (tun.Device, error) {
				return tuntest.NewChannelTUN().TUN(), nil
			},
			AllowTraffic: func(netip.Prefix) error { return nil },
		},
		PanelFiles:   fstest.MapFS{},
		PollInterval: 500 * time.Millisecond,
	}
	for _, o := range opts {
		o(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("service did not stop")
		}
	})
	select {
	case <-r.Ready():
	case err := <-done:
		t.Fatalf("service stopped: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("service did not start")
	}
	return r
}

func waitFor(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestCreateNetworkAndJoinByInvite(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	base := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	owner := newRuntime(t, ctx, filepath.Join(base, "owner"), "Masaustu-PC")
	if st := owner.Status(); st.Mode != panel.ModeSetup || st.Hostname != "masaustu-pc" {
		t.Fatalf("unexpected initial status %+v", st)
	}
	n, err := owner.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if _, err := owner.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass}); err == nil {
		t.Fatal("second network accepted")
	}
	waitFor(t, "owner tunnel and coordinator", 10*time.Second, func() bool {
		st := owner.Status()
		return st.Mode == panel.ModeAdmin && st.Device != nil && st.Device.Running && st.Coordinator != nil && st.Coordinator.Running
	})
	if st := owner.Status(); st.Device.Name != "masaustu-pc" {
		t.Fatalf("device name %q", st.Device.Name)
	}

	created, err := n.CreateInvite(testPass, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	laptop := newRuntime(t, ctx, filepath.Join(base, "laptop"), "Laptop")
	if err := laptop.JoinNetwork("garbage", ""); err == nil {
		t.Fatal("bad code accepted")
	}
	if err := laptop.JoinNetwork(created.Code, ""); err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}
	var code string
	waitFor(t, "short code on the new device", 20*time.Second, func() bool {
		st := laptop.Status()
		if st.Joining != nil {
			code = st.Joining.ShortCode
		}
		return code != ""
	})

	var signed []trust.SignedInviteEnrollment
	waitFor(t, "pending enrollment at the owner", 20*time.Second, func() bool {
		list, err := owner.Pending(ctx)
		signed = list
		return err == nil && len(list) == 1
	})
	pending := n.VerifyPending(signed, time.Now())
	if len(pending) != 1 || !trust.SameShortCode(pending[0].ShortCode, code) {
		t.Fatal("pending enrollment does not match the code on the new device")
	}
	if _, err := n.ApproveInvite(testPass, pending[0].Signed, "laptop", nil, time.Now()); err != nil {
		t.Fatalf("ApproveInvite: %v", err)
	}
	waitFor(t, "new device tunnel", 30*time.Second, func() bool {
		st := laptop.Status()
		return st.Mode == panel.ModeMember && st.Device != nil && st.Device.Running && len(st.Device.Peers) == 1
	})
	if st := laptop.Status(); st.Device.Peers[0].Name != "masaustu-pc" {
		t.Fatalf("laptop peers %+v", st.Device.Peers)
	}

	// Turning the tunnel off stops it and survives restarts; turning it on
	// brings it back.
	if err := laptop.SetConnected(false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel off", 10*time.Second, func() bool {
		st := laptop.Status()
		return !st.Device.Connected && !st.Device.Running
	})
	if err := laptop.SetConnected(true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel back on", 20*time.Second, func() bool {
		st := laptop.Status()
		return st.Device.Connected && st.Device.Running
	})

	// The owner moves the coordinator to a server. The old coordinator keeps
	// serving the new document, so the laptop follows without any action.
	vpsKey, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, vpsWG, _ := vpsKey.PublicKeys()
	vpsPort := freeUDPPort(t)
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(vpsPort), vpsWG)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	vpsStore, err := member.Join(filepath.Join(base, "vps"), bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	vps, err := coordinator.New(coordinator.Config{Store: vpsStore, Secrets: vpsKey, ListenPort: vpsPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = vps.Run(ctx) }()
	<-vps.Ready()

	ownerKey, laptopKey := deviceWG(t, owner), deviceWG(t, laptop)
	waitFor(t, "both devices at the new coordinator", 60*time.Second, func() bool {
		st, err := vps.PeerStats()
		if err != nil {
			return false
		}
		return st[ownerKey].LastHandshakeUnix > 0 && st[laptopKey].LastHandshakeUnix > 0
	})
	if st := owner.Status(); st.Coordinator == nil || !st.Coordinator.Handoff {
		t.Fatalf("old coordinator not in handoff: %+v", st.Coordinator)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func deviceWG(t *testing.T, r *Runtime) trust.Key {
	t.Helper()
	s, err := readSecrets(r.path(DeviceDir, deviceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	_, wg, err := s.PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	return wg
}
