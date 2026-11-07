package upstream

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/wgconf"
)

// fakeRouter records what the manager asks of the OS.
type fakeRouter struct {
	mu      sync.Mutex
	applied []osnet.UpstreamRoute
	direct  []bool
	removed int
	fail    bool
}

func (r *fakeRouter) Apply(_ context.Context, rt osnet.UpstreamRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return fmt.Errorf("nft failed")
	}
	r.applied = append(r.applied, rt)
	return nil
}

func (r *fakeRouter) SetDirect(_ context.Context, d bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.direct = append(r.direct, d)
	return nil
}

func (r *fakeRouter) Remove(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed++
	return nil
}

func (r *fakeRouter) snapshot() ([]osnet.UpstreamRoute, []bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]osnet.UpstreamRoute(nil), r.applied...), append([]bool(nil), r.direct...), r.removed
}

// provider is a wireguard-go device on 127.0.0.1 in the provider's role.
type provider struct {
	dev  *device.Device
	ch   *tuntest.ChannelTUN
	pub  string
	port uint16
}

func newProvider(t *testing.T, clientPub string, clientAddr netip.Addr) *provider {
	t.Helper()
	priv, pub := testKeys(t)
	ch := tuntest.NewChannelTUN()
	dev := device.NewDevice(ch.TUN(), testnet.NewLoopbackBind(), device.NewLogger(device.LogLevelSilent, ""))
	privRaw, _ := base64.StdEncoding.DecodeString(priv)
	clientRaw, _ := base64.StdEncoding.DecodeString(clientPub)
	uapi := "private_key=" + hex.EncodeToString(privRaw) + "\nlisten_port=0\n" +
		"public_key=" + hex.EncodeToString(clientRaw) + "\nallowed_ip=" + netip.PrefixFrom(clientAddr, 32).String() + "\n"
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	raw, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	st, err := wgconf.ParseStatus(raw)
	if err != nil || st.ListenPort == 0 {
		t.Fatalf("provider port: %v", err)
	}
	p := &provider{dev: dev, ch: ch, pub: pub, port: uint16(st.ListenPort)}
	t.Cleanup(dev.Close)
	return p
}

type harness struct {
	m      *Manager
	store  *Store
	router *fakeRouter
	offset atomic.Int64
	mu     sync.Mutex
	tuns   []*tuntest.ChannelTUN
}

func (h *harness) lastTUN() *tuntest.ChannelTUN {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tuns[len(h.tuns)-1]
}

func (h *harness) advance(d time.Duration) { h.offset.Add(int64(d)) }

func newHarness(t *testing.T, conf string) *harness {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Import("se-got", "Mullvad · İsveç", []byte(conf), false); err != nil {
		t.Fatal(err)
	}
	h := &harness{store: st, router: &fakeRouter{}}
	deps := Deps{
		NewTUN: func(string, int) (tun.Device, error) {
			ch := tuntest.NewChannelTUN()
			h.mu.Lock()
			h.tuns = append(h.tuns, ch)
			h.mu.Unlock()
			return ch.TUN(), nil
		},
		NewBind: func() conn.Bind { return testnet.NewLoopbackBind() },
		Router:  h.router,
		Now:     func() time.Time { return time.Now().Add(time.Duration(h.offset.Load())) },
	}
	h.m, err = NewManager(ManagerConfig{Store: st, Deps: deps, Overlay: func() (Overlay, error) {
		return Overlay{Interface: "OpenScale", V4: netip.MustParsePrefix("100.80.0.0/16"), V6: netip.MustParsePrefix("fd7a:1:2::/48")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.m.Close)
	return h
}

func waitConnected(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h.m.Tick()
		if h.m.Status().Connected {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no handshake with the provider: %+v", h.m.Status())
}

func expectPacket(t *testing.T, ch <-chan []byte, want []byte) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-ch:
			if bytes.Equal(got, want) {
				return
			}
		case <-timeout:
			t.Fatal("packet did not arrive")
		}
	}
}

// TestUpstreamEndToEnd runs the upstream tunnel against a second
// wireguard-go device in the provider's role on 127.0.0.1: handshake,
// packets both ways, DNS through the tunnel, a lost tunnel that stays
// closed, fail-open, and turning it off.
func TestUpstreamEndToEnd(t *testing.T) {
	clientPriv, clientPub := testKeys(t)
	addr := netip.MustParseAddr("10.68.12.34")
	prov := newProvider(t, clientPub, addr)
	h := newHarness(t, mullvadStyle(clientPriv, prov.pub, "127.0.0.1:"+strconv.Itoa(int(prov.port))))

	// Not an exit node yet, or no profile chosen: nothing happens.
	h.m.SetRole(true)
	if applied, _, _ := h.router.snapshot(); len(applied) != 0 {
		t.Fatal("routing installed without an active profile")
	}
	if _, _, ok := h.m.DNS(); ok {
		t.Fatal("DNS redirected without an upstream")
	}
	if err := h.store.Use("se-got"); err != nil {
		t.Fatal(err)
	}
	h.m.Tick()

	// The drop routing comes first, then the tunnel's.
	applied, _, _ := h.router.snapshot()
	if len(applied) != 2 || applied[0].TunnelUp() || !applied[1].TunnelUp() {
		t.Fatalf("routing order %+v", applied)
	}
	rt := applied[1]
	if rt.Address4 != addr || rt.Address6 != netip.MustParseAddr("fc00:bbbb:bbbb:bb01::5:c21") || rt.Overlay != "OpenScale" || rt.FailOpen || rt.MTU != DefaultMTU || rt.Interface == "" {
		t.Fatalf("route %+v", rt)
	}
	waitConnected(t, h)

	server, source, ok := h.m.DNS()
	if !ok || server != netip.MustParseAddrPort("10.64.0.1:53") || source != addr {
		t.Fatalf("DNS via %v from %v (%v)", server, source, ok)
	}

	// A member's packet (after NAT) leaves through the provider, and the
	// answer comes back.
	out := tuntest.Ping(netip.MustParseAddr("192.0.2.80"), addr)
	h.lastTUN().Outbound <- out
	expectPacket(t, prov.ch.Inbound, out)
	back := tuntest.Ping(addr, netip.MustParseAddr("192.0.2.80"))
	prov.ch.Outbound <- back
	expectPacket(t, h.lastTUN().Inbound, back)

	h.m.Tick()
	st, okStatus, err := h.store.ReadStatus()
	if err != nil || !okStatus || st.Mode != ModeTunnel || !st.Connected || st.LastHandshake == 0 || st.TxBytes == 0 || st.Label != "Mullvad · İsveç" {
		t.Fatalf("status %+v %v %v", st, okStatus, err)
	}

	// The provider goes away and the handshake gets old: fail closed means
	// blocked, never direct, and a reconnect is attempted.
	prov.dev.Close()
	h.advance(staleAfter + time.Minute)
	h.m.Tick()
	h.advance(time.Minute)
	h.m.Tick()
	s := h.m.Status()
	if s.Connected || s.Mode != ModeBlocked || s.Reconnects == 0 {
		t.Fatalf("after loss %+v", s)
	}
	if _, direct, _ := h.router.snapshot(); len(direct) != 0 {
		t.Fatalf("fail-closed upstream switched to direct: %v", direct)
	}
	if server, _, ok := h.m.DNS(); !ok || !server.IsValid() {
		t.Fatal("DNS left the tunnel while it was down")
	}

	// Fail-open: the tunnel is rebuilt with the new choice; after the
	// grace period members leave directly, and DNS uses the normal path.
	if err := h.store.UpdateSettings(func(s *Settings) error { s.OnDown = OnDownDirect; return nil }); err != nil {
		t.Fatal(err)
	}
	h.m.Tick()
	applied, _, _ = h.router.snapshot()
	if last := applied[len(applied)-1]; !last.FailOpen || !last.TunnelUp() {
		t.Fatalf("fail-open route %+v", last)
	}
	h.advance(failOpenGrace + time.Second)
	h.m.Tick()
	if _, direct, _ := h.router.snapshot(); len(direct) != 1 || !direct[0] {
		t.Fatalf("direct switches %v", direct)
	}
	if s := h.m.Status(); s.Mode != ModeDirect {
		t.Fatalf("mode %q", s.Mode)
	}
	if _, _, ok := h.m.DNS(); ok {
		t.Fatal("DNS still forced into a dead fail-open tunnel")
	}

	// "off": everything is removed.
	if err := h.store.UpdateSettings(func(s *Settings) error { s.Active = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	h.m.Tick()
	if _, _, removed := h.router.snapshot(); removed != 1 {
		t.Fatalf("routing removed %d times", removed)
	}
	if s := h.m.Status(); s.Mode != ModeOff {
		t.Fatalf("mode after off %q", s.Mode)
	}
}

// TestUpstreamFailClosedWithoutRouting: when the drop routing cannot be
// installed the exit node must stay off and members' DNS is dropped.
func TestUpstreamFailClosedWithoutRouting(t *testing.T) {
	clientPriv, _ := testKeys(t)
	_, peer := testKeys(t)
	h := newHarness(t, mullvadStyle(clientPriv, peer, "127.0.0.1:9"))
	if err := h.store.Use("se-got"); err != nil {
		t.Fatal(err)
	}
	h.router.mu.Lock()
	h.router.fail = true
	h.router.mu.Unlock()
	h.m.SetRole(true)
	if err := h.m.Ready(); err == nil {
		t.Fatal("ready without routing")
	}
	if server, _, ok := h.m.DNS(); !ok || server.IsValid() {
		t.Fatal("DNS not dropped while routing is missing")
	}
	h.mu.Lock()
	n := len(h.tuns)
	h.mu.Unlock()
	if n != 0 {
		t.Fatal("tunnel started without drop routing")
	}

	// Routing works again: the next tick installs it and starts the tunnel.
	h.router.mu.Lock()
	h.router.fail = false
	h.router.mu.Unlock()
	h.m.Tick()
	if err := h.m.Ready(); err != nil {
		t.Fatal(err)
	}
	h.m.SetRole(false)
	if _, _, removed := h.router.snapshot(); removed != 1 {
		t.Fatal("role off did not remove the routing")
	}
}

// TestUpstreamBadProfileStaysBlocked: an unreadable profile leaves the
// drop routing in place and reports the error.
func TestUpstreamBadProfileStaysBlocked(t *testing.T) {
	clientPriv, _ := testKeys(t)
	_, peer := testKeys(t)
	h := newHarness(t, mullvadStyle(clientPriv, peer, "127.0.0.1:9"))
	if err := h.store.Use("se-got"); err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpdateSettings(func(s *Settings) error { s.Active = "baska"; return nil }); err != nil {
		t.Fatal(err)
	}
	h.m.SetRole(true)
	applied, _, _ := h.router.snapshot()
	if len(applied) != 1 || applied[0].TunnelUp() {
		t.Fatalf("routing %+v", applied)
	}
	s := h.m.Status()
	if s.Mode != ModeBlocked || s.Error == "" {
		t.Fatalf("status %+v", s)
	}
	if server, _, ok := h.m.DNS(); !ok || server.IsValid() {
		t.Fatal("DNS not dropped without a tunnel")
	}
}

// TestUpstreamReimportRebuilds: replacing the running profile's file
// rebuilds the tunnel with the new configuration.
func TestUpstreamReimportRebuilds(t *testing.T) {
	clientPriv, _ := testKeys(t)
	_, peer := testKeys(t)
	h := newHarness(t, mullvadStyle(clientPriv, peer, "127.0.0.1:9"))
	if err := h.store.Use("se-got"); err != nil {
		t.Fatal(err)
	}
	h.m.SetRole(true)
	if applied, _, _ := h.router.snapshot(); len(applied) != 2 {
		t.Fatalf("routing %+v", applied)
	}
	h.m.Tick()
	if applied, _, _ := h.router.snapshot(); len(applied) != 2 {
		t.Fatal("tunnel rebuilt without a change")
	}
	if _, err := h.store.Import("se-got", "", []byte(mullvadStyle(clientPriv, peer, "127.0.0.1:10")), true); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(h.store.Dir(), "se-got.conf"), later, later); err != nil {
		t.Fatal(err)
	}
	h.m.Tick()
	if applied, _, _ := h.router.snapshot(); len(applied) != 4 || applied[2].TunnelUp() || !applied[3].TunnelUp() {
		t.Fatalf("re-import did not rebuild: %+v", applied)
	}
	if s := h.m.Status(); s.Endpoint != "127.0.0.1:10" {
		t.Fatalf("endpoint %q", s.Endpoint)
	}
}
