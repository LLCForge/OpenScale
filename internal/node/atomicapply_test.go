package node

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func randomKey(t *testing.T) trust.Key {
	t.Helper()
	var k trust.Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestValidatePeerSet(t *testing.T) {
	a, b := randomKey(t), randomKey(t)
	pa := wgconf.Peer{PublicKey: a, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	pb := wgconf.Peer{PublicKey: b, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}}
	if err := validatePeerSet(map[trust.Key]wgconf.Peer{a: pa, b: pb}); err != nil {
		t.Fatal(err)
	}
	dup := pb
	dup.AllowedIPs = pa.AllowedIPs
	if err := validatePeerSet(map[trust.Key]wgconf.Peer{a: pa, b: dup}); err == nil {
		t.Fatal("an address given to two peers was accepted")
	}
	bad := pa
	bad.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/24")}
	if err := validatePeerSet(map[trust.Key]wgconf.Peer{a: bad}); err == nil {
		t.Fatal("unmasked prefix accepted")
	}
	if err := validatePeerSet(map[trust.Key]wgconf.Peer{b: pa}); err == nil {
		t.Fatal("key mismatch accepted")
	}
}

// configLines keeps the configuration part of IpcGet output, sorted per
// peer, so two dumps can be compared.
func configLines(raw string) string {
	peers, _ := parsePeerConfig(raw)
	var out []string
	for k, p := range peers {
		allowed := slices.Clone(p.allowed)
		slices.Sort(allowed)
		out = append(out, hex.EncodeToString(k[:])+" "+p.psk+" "+p.endpoint+" "+p.keepalive+" "+strings.Join(allowed, ","))
	}
	slices.Sort(out)
	return strings.Join(out, "\n")
}

// TestHalfAppliedPeersRestored: wireguard-go applies UAPI line by line, so
// a failing set leaves a mix; rollbackPeers restores the exact previous
// peers (#199).
func TestHalfAppliedPeersRestored(t *testing.T) {
	ch := tuntest.NewChannelTUN()
	dev := device.NewDevice(ch.TUN(), testnet.NewLoopbackBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	priv := randomKey(t)
	if err := dev.IpcSet(wgconf.Interface(priv[:], 0)); err != nil {
		t.Fatal(err)
	}
	a, b, c := randomKey(t), randomKey(t), randomKey(t)
	psk := randomKey(t)
	initial := wgconf.AddOrUpdate(wgconf.Peer{PublicKey: a, AllowedIPs: wgconf.HostPrefixes(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd00::2")), Endpoint: netip.MustParseAddrPort("127.0.0.1:41001"), Keepalive: 25}) +
		"public_key=" + hex.EncodeToString(b[:]) + "\npreshared_key=" + hex.EncodeToString(psk[:]) + "\nreplace_allowed_ips=true\nallowed_ip=100.64.0.3/32\n"
	if err := dev.IpcSet(initial); err != nil {
		t.Fatal(err)
	}
	before, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	// Remove a, change b's addresses, add c, then fail on a bad line.
	broken := wgconf.Remove(a) +
		wgconf.AddOrUpdate(wgconf.Peer{PublicKey: b, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")}}) +
		wgconf.AddOrUpdate(wgconf.Peer{PublicKey: c, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")}}) +
		"public_key=" + hex.EncodeToString(c[:]) + "\nallowed_ip=bozuk\n"
	setErr := dev.IpcSet(broken)
	if setErr == nil {
		t.Fatal("the broken UAPI was accepted")
	}
	mid, _ := dev.IpcGet()
	if configLines(mid) == configLines(before) {
		t.Fatal("the failed set changed nothing; the test does not exercise a partial apply")
	}
	e := &Engine{dev: dev, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := e.rollbackPeers(before, setErr); err == nil || !strings.Contains(err.Error(), errPeersRolledBack.Error()) {
		t.Fatalf("rollbackPeers = %v", err)
	}
	after, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if configLines(after) != configLines(before) {
		t.Fatalf("peers not restored:\nbefore:\n%s\nafter:\n%s", configLines(before), configLines(after))
	}
}
