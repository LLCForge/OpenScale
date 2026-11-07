package evilcoord

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
)

// --- document path ---

type network struct {
	anchor trust.Anchor
	envs   [][]byte // v1, v2, v3
	now    time.Time
}

func newNetwork(t *testing.T, validity time.Duration) *network {
	t.Helper()
	pub, priv, err := trust.GenerateRootKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := trust.NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ula, err := trust.RandomULAPrefix(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	doc, err := trust.NewDocument(id, trust.DefaultDNSDomain, trust.DefaultIPv4Prefix, ula, now, validity)
	if err != nil {
		t.Fatal(err)
	}
	n := &network{anchor: trust.Anchor{RootKey: pub, NetworkID: id}, now: now}
	for i := range 3 {
		if i > 0 {
			if doc, err = doc.Next(now, validity); err != nil {
				t.Fatal(err)
			}
		}
		env, err := trust.SignDocument(doc, priv)
		if err != nil {
			t.Fatal(err)
		}
		data, err := trust.MarshalEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		n.envs = append(n.envs, data)
	}
	return n
}

func (n *network) join(t *testing.T, env []byte) *member.Store {
	t.Helper()
	st, err := member.JoinAnchor(t.TempDir(), n.anchor, env, n.now)
	if err != nil {
		t.Fatalf("JoinAnchor: %v", err)
	}
	return st
}

// foreignEnvelope is a valid document of another network.
func foreignEnvelope(t *testing.T) []byte {
	t.Helper()
	return newNetwork(t, trust.DefaultValidity).envs[2]
}

// Every forging behaviour is refused and leaves the device's document
// untouched; the honest coordinator is the control that shows the device
// does accept updates.
func TestDevicesRefuseForgedDocuments(t *testing.T) {
	n := newNetwork(t, trust.DefaultValidity)
	for _, b := range []Behavior{Honest, Forge, Tamper, Strip, Foreign} {
		t.Run(b.String(), func(t *testing.T) {
			c, err := New(foreignEnvelope(t))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range n.envs {
				c.Publish(e)
			}
			dev := n.join(t, n.envs[0])
			c.SetBehavior(b)
			served, err := c.Serve("laptop")
			if err != nil {
				t.Fatal(err)
			}
			changed, err := dev.Accept(served, n.now)
			if b == Honest {
				if err != nil || !changed || dev.Document().Version != 3 {
					t.Fatalf("honest update refused: changed=%v err=%v", changed, err)
				}
				return
			}
			if err == nil || changed {
				t.Fatalf("%s accepted: changed=%v err=%v", b, changed, err)
			}
			if v := dev.Document().Version; v != 1 {
				t.Fatalf("%s moved the device to version %d", b, v)
			}
			// The refused document is not persisted either.
			reopened, err := member.Open(dev.Dir())
			if err != nil || reopened.Document().Version != 1 {
				t.Fatalf("after %s the stored document is %v (%v)", b, reopened, err)
			}
		})
	}
}

// Rollback: a device never moves back, whatever the coordinator serves.
func TestDevicesRefuseRollback(t *testing.T) {
	n := newNetwork(t, trust.DefaultValidity)
	c, _ := New(nil)
	for _, e := range n.envs {
		c.Publish(e)
	}
	dev := n.join(t, n.envs[2])
	c.SetBehavior(Rollback)
	served, _ := c.Serve("laptop")
	if _, err := dev.Accept(served, n.now); err == nil {
		t.Fatal("rollback to version 1 accepted")
	}
	if v := dev.Document().Version; v != 3 {
		t.Fatalf("device moved to version %d", v)
	}
}

// Split view: the coordinator keeps one device on an old version. The
// device cannot be kept there once a peer shows it the newer document,
// and after that the coordinator cannot push it back.
func TestSplitViewEndsWithGossip(t *testing.T) {
	n := newNetwork(t, trust.DefaultValidity)
	c, _ := New(nil)
	for _, e := range n.envs {
		c.Publish(e)
	}
	c.SetBehavior(SplitView)
	c.Favour("laptop")
	laptop, phone := n.join(t, n.envs[0]), n.join(t, n.envs[0])
	for name, st := range map[string]*member.Store{"laptop": laptop, "telefon": phone} {
		env, _ := c.Serve(name)
		if _, err := st.Accept(env, n.now); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if laptop.Document().Version != 3 || phone.Document().Version != 1 {
		t.Fatalf("split view not set up: %d / %d", laptop.Document().Version, phone.Document().Version)
	}
	// The views differ; devices that compare digests see it (#571, the
	// integrity cross-check of internal/node does exactly this).
	_, d1 := laptop.Envelope()
	_, d2 := phone.Envelope()
	if d1 == d2 {
		t.Fatal("different versions with the same digest")
	}
	// A peer hands over its envelope (gossip); it verifies on its own.
	env, _ := laptop.Envelope()
	if changed, err := phone.Accept(env, n.now); err != nil || !changed {
		t.Fatalf("gossiped document refused: %v", err)
	}
	served, _ := c.Serve("telefon")
	if _, err := phone.Accept(served, n.now); err == nil || phone.Document().Version != 3 {
		t.Fatalf("coordinator pushed the phone back: %v, version %d", err, phone.Document().Version)
	}
}

// Withholding: the coordinator freezes the device on a document. The
// freeze cannot outlast the document's validity: after it expires the
// device refuses the document, so it stops trusting the frozen view.
func TestWithholdingEndsAtExpiry(t *testing.T) {
	const validity = 2 * time.Hour
	n := newNetwork(t, validity)
	c, _ := New(nil)
	c.Publish(n.envs[0])
	c.SetBehavior(Withhold)
	for _, e := range n.envs[1:] {
		c.Publish(e)
	}
	dev := n.join(t, n.envs[0])
	served, _ := c.Serve("laptop")
	if !bytes.Equal(served, n.envs[0]) {
		t.Fatal("withholding coordinator served a newer document")
	}
	if changed, err := dev.Accept(served, n.now.Add(time.Hour)); err != nil || changed {
		t.Fatalf("within validity: changed=%v err=%v", changed, err)
	}
	later := n.now.Add(validity + time.Minute)
	if _, err := dev.Accept(served, later); err == nil {
		t.Fatal("expired frozen document accepted")
	}
	if doc := dev.Document(); later.Before(doc.ExpiresAt) {
		t.Fatalf("stored document still valid at %s (expires %s)", later, doc.ExpiresAt)
	}
}

// --- data path ---

type wgNode struct {
	dev  *device.Device
	tun  *tuntest.ChannelTUN
	pub  []byte
	priv []byte
	port uint16
	ip   netip.Addr
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func newWG(t *testing.T, ip string) *wgNode {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := &wgNode{tun: tuntest.NewChannelTUN(), priv: k.Bytes(), pub: k.PublicKey().Bytes(), port: freePort(t), ip: netip.MustParseAddr(ip)}
	n.dev = device.NewDevice(n.tun.TUN(), testnet.NewLoopbackBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(n.dev.Close)
	if err := n.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(n.priv), n.port)); err != nil {
		t.Fatal(err)
	}
	if err := n.dev.Up(); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *wgNode) addr() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), n.port)
}

// peer configures pub with allowed ip at endpoint.
func (n *wgNode) peer(t *testing.T, pub []byte, ip netip.Addr, endpoint netip.AddrPort) {
	t.Helper()
	cfg := fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=1\n", hex.EncodeToString(pub), endpoint, ip)
	if err := n.dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
}

// delivered pings from src to dst until it arrives or within passes.
func delivered(from, to *wgNode, within time.Duration) bool {
	deadline := time.After(within)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			select {
			case from.tun.Outbound <- tuntest.Ping(to.ip, from.ip):
			default:
			}
		case pkt := <-to.tun.Inbound:
			if len(pkt) >= 20 && pkt[0]>>4 == 4 && netip.AddrFrom4([4]byte(pkt[12:16])) == from.ip {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// Endpoint spoofing: the coordinator tells the laptop that the desktop is
// at an address it controls. Without the desktop's private key it can
// neither answer the handshake nor send traffic the laptop accepts.
func TestSpoofedEndpointGetsNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets on 127.0.0.1")
	}
	laptop, desktop, evil := newWG(t, "10.77.0.1"), newWG(t, "10.77.0.2"), newWG(t, "10.77.0.2")
	// The evil node claims the desktop's address and knows the laptop's
	// public key; the laptop points to it, as the coordinator said.
	laptop.peer(t, desktop.pub, desktop.ip, evil.addr())
	evil.peer(t, laptop.pub, laptop.ip, laptop.addr())
	desktop.peer(t, laptop.pub, laptop.ip, laptop.addr())
	if delivered(laptop, evil, 3*time.Second) {
		t.Fatal("traffic for the desktop reached the impostor")
	}
	if delivered(evil, laptop, 3*time.Second) {
		t.Fatal("the impostor's traffic was accepted as the desktop's")
	}
	// Control: with the true endpoint the same configuration works.
	laptop.peer(t, desktop.pub, desktop.ip, desktop.addr())
	if !delivered(laptop, desktop, 15*time.Second) {
		t.Fatal("control: tunnel with the true endpoint did not work")
	}
}

// Relay tampering: a relaying coordinator that alters packets cannot make
// a device accept altered data; WireGuard drops them.
func TestTamperingRelayIsDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets on 127.0.0.1")
	}
	laptop, desktop := newWG(t, "10.78.0.1"), newWG(t, "10.78.0.2")
	r, err := NewRelay(laptop.addr(), desktop.addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	laptop.peer(t, desktop.pub, desktop.ip, r.Addr())
	desktop.peer(t, laptop.pub, laptop.ip, r.Addr())

	for _, m := range []RelayMode{FlipAll, FlipData} {
		r.SetMode(m)
		if delivered(laptop, desktop, 3*time.Second) {
			t.Fatalf("mode %d: altered packet was delivered", m)
		}
		if _, altered := r.Stats(); altered == 0 && m == FlipAll {
			t.Fatalf("mode %d: relay altered nothing; the test proves nothing", m)
		}
	}
	// Control: the same relay passing packets unchanged works.
	r.SetMode(Pass)
	if !delivered(laptop, desktop, 15*time.Second) {
		t.Fatal("control: unchanged relay did not carry traffic")
	}
}
