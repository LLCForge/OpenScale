package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// probeNet connects probers in memory: a datagram sent to an address is
// delivered to the prober owning it, unless the address is blocked.
type probeNet struct {
	mu      sync.Mutex
	owners  map[netip.AddrPort]*prober
	blocked map[netip.AddrPort]bool
	// natAs rewrites the source address a prober's packets arrive from.
	natAs map[*prober]netip.AddrPort
}

func newProbeNet() *probeNet {
	return &probeNet{owners: map[netip.AddrPort]*prober{}, blocked: map[netip.AddrPort]bool{}, natAs: map[*prober]netip.AddrPort{}}
}

type probeNode struct {
	dev     trust.Device
	secrets *trust.DeviceSecrets
	p       *prober
	addrs   []netip.AddrPort
	relayed chan []byte
	better  chan struct{}
}

func newProbeNode(t *testing.T, pn *probeNet, now func() time.Time, name string, addrs ...string) *probeNode {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, wg, err := s.PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	n := &probeNode{secrets: s, relayed: make(chan []byte, 16), better: make(chan struct{}, 16)}
	n.dev = trust.Device{ID: s.DeviceID, Name: name, SigningKey: sig, WireGuardKey: wg, ExpiresAt: time.Now().Add(time.Hour)}
	n.p = newProber(now, testLogger(t, name), s.SigningKey())
	n.p.improved = func() { n.better <- struct{}{} }
	n.p.sendRelay = func(_ [control.RelayIDLen]byte, pkt []byte) bool { n.relayed <- pkt; return true }
	for _, a := range addrs {
		ap := netip.MustParseAddrPort(a)
		n.addrs = append(n.addrs, ap)
		pn.owners[ap] = n.p
	}
	n.p.sendDirect = func(pkt []byte, to netip.AddrPort) error {
		pn.mu.Lock()
		dst, ok := pn.owners[to]
		blocked := pn.blocked[to]
		from, nat := pn.natAs[n.p]
		pn.mu.Unlock()
		if !ok || blocked {
			return nil
		}
		if !nat {
			// Answer from the address on the same "network" as the target.
			from = n.addrs[0]
			for _, a := range n.addrs {
				if classify(a) == classify(to) {
					from = a
				}
			}
		}
		dst.handle(probeIn{data: append([]byte(nil), pkt...), from: from})
		return nil
	}
	return n
}

func pair(a, b *probeNode) {
	a.p.setPeers(a.dev, []trust.Device{b.dev})
	b.p.setPeers(b.dev, []trust.Device{a.dev})
}

func statusOf(peers ...trust.Device) wgconf.Status {
	st := wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{}}
	for _, d := range peers {
		st.Peers[d.WireGuardKey] = wgconf.PeerStatus{Relayed: true}
	}
	return st
}

func TestProbeEncodingAndSignature(t *testing.T) {
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, _, _ := s.PublicKeys()
	m := probeMsg{kind: probePong, txid: [12]byte{1, 2, 3}, clock: 1700000000, observed: netip.MustParseAddrPort("203.0.113.4:9")}
	m.from[0], m.to[0] = 1, 2
	pkt, err := encodeProbe(m, s.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != probePongLen || !isProbe(pkt) {
		t.Fatalf("len %d", len(pkt))
	}
	got, err := parseProbe(pkt)
	if err != nil || got != m {
		t.Fatalf("parse: %+v %v", got, err)
	}
	if !verifyProbe(pkt, sig) {
		t.Fatal("signature refused")
	}
	for i := range pkt {
		bad := append([]byte(nil), pkt...)
		bad[i] ^= 0x01
		if p, err := parseProbe(bad); err == nil && p == m && verifyProbe(bad, sig) {
			t.Fatalf("flipped byte %d still verifies", i)
		}
	}
	// A WireGuard message is never taken for a probe.
	if isProbe([]byte{1, 0, 0, 0, 5, 6, 7, 8}) {
		t.Fatal("WireGuard initiation looks like a probe")
	}
	// IPv6 observed addresses survive.
	m.observed = netip.MustParseAddrPort("[2001:db8::7]:41641")
	pkt, _ = encodeProbe(m, s.SigningKey())
	if got, _ := parseProbe(pkt); got.observed != m.observed {
		t.Fatalf("observed %v", got.observed)
	}
}

func FuzzParseProbe(f *testing.F) {
	s, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	ping, _ := encodeProbe(probeMsg{kind: probePing, clock: 5}, s.SigningKey())
	pong, _ := encodeProbe(probeMsg{kind: probePong, clock: 5, observed: netip.MustParseAddrPort("1.2.3.4:5")}, s.SigningKey())
	f.Add(ping)
	f.Add(pong)
	f.Add([]byte(probeMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseProbe(b)
		if err != nil {
			return
		}
		if m.kind != probePing && m.kind != probePong && m.kind != probeReset {
			t.Fatalf("kind %d accepted", m.kind)
		}
		if (m.kind != probePong && len(b) != probePingLen) || (m.kind == probePong && len(b) != probePongLen) {
			t.Fatalf("length %d accepted for kind %d", len(b), m.kind)
		}
	})
}

// Probes find the best working path: the LAN candidate wins over IPv6 and
// the observed public endpoint; a blocked LAN falls back to the next class.
func TestProbePicksBestWorkingPath(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	pn := newProbeNet()
	a := newProbeNode(t, pn, clock, "a", "192.168.1.10:41641", "[2001:db8::10]:41641", "203.0.113.10:41641")
	b := newProbeNode(t, pn, clock, "b", "192.168.1.20:41641", "[2001:db8::20]:41641", "203.0.113.20:5555")
	pair(a, b)
	a.p.setInfo(b.dev.WireGuardKey, netip.MustParseAddrPort("203.0.113.20:5555"),
		[]netip.AddrPort{netip.MustParseAddrPort("192.168.1.20:41641"), netip.MustParseAddrPort("[2001:db8::20]:41641")})

	calls := a.p.round(statusOf(b.dev), staleHandshake)
	if len(calls) != 1 || calls[0] != b.dev.ID {
		t.Fatalf("calls = %v", calls)
	}
	best, ok := a.p.validated(b.dev.WireGuardKey, probeFresh)
	if !ok || best != netip.MustParseAddrPort("192.168.1.20:41641") {
		t.Fatalf("best = %v %v", best, ok)
	}
	select {
	case <-a.better:
	default:
		t.Fatal("engine not woken for the better path")
	}
	snap, _ := a.p.snapshot(b.dev.WireGuardKey)
	if snap.seenAs != netip.MustParseAddrPort("203.0.113.10:41641") {
		t.Fatalf("seenAs = %v", snap.seenAs)
	}

	// Another day, another network: the LAN address is someone else's.
	pn.blocked[netip.MustParseAddrPort("192.168.1.20:41641")] = true
	a.p.reset()
	now = now.Add(time.Minute)
	a.p.round(statusOf(b.dev), staleHandshake)
	best, ok = a.p.validated(b.dev.WireGuardKey, probeFresh)
	if !ok || best != netip.MustParseAddrPort("[2001:db8::20]:41641") {
		t.Fatalf("fallback best = %v %v", best, ok)
	}
	// Results age out.
	now = now.Add(probeBestTTL + time.Second)
	if _, ok := a.p.validated(b.dev.WireGuardKey, probeBestTTL); ok {
		t.Fatal("old result still valid")
	}
}

// Probing backs off while it finds nothing and stops for healthy peers.
func TestProbeBackoffAndHealthyPeers(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	pn := newProbeNet()
	a := newProbeNode(t, pn, clock, "a", "192.168.1.10:41641")
	b := newProbeNode(t, pn, clock, "b", "192.168.7.20:41641")
	pair(a, b)
	cand := netip.MustParseAddrPort("192.168.7.20:41641")
	pn.blocked[cand] = true
	a.p.setInfo(b.dev.WireGuardKey, netip.AddrPort{}, []netip.AddrPort{cand})
	sent := 0
	a.p.sendDirect = func([]byte, netip.AddrPort) error { sent++; return nil }
	var at []time.Duration
	start := now
	for i := 0; i < 400; i++ {
		before := sent
		a.p.round(statusOf(b.dev), staleHandshake)
		if sent > before {
			at = append(at, now.Sub(start))
		}
		now = now.Add(5 * time.Second)
	}
	// 0, 20 s, then 40, 80, 160, 320 and 600 s gaps.
	if len(at) < 6 || at[1]-at[0] != 20*time.Second || at[2]-at[1] != 40*time.Second || at[5]-at[4] != 320*time.Second {
		t.Fatalf("probe times %v", at)
	}
	if gap := at[len(at)-1] - at[len(at)-2]; gap != probeMaxWait {
		t.Fatalf("last gap %v", gap)
	}
	// A peer on its best path with a fresh handshake is left alone.
	st := wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{b.dev.WireGuardKey: {Endpoint: cand, LastHandshakeUnix: now.Unix()}}}
	before := sent
	a.p.round(st, staleHandshake)
	if sent != before {
		t.Fatal("healthy peer probed")
	}
}

// Pings from unknown devices, for another receiver, replayed, too old or
// badly signed get no answer.
func TestProbeRefusesBadPings(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	pn := newProbeNet()
	a := newProbeNode(t, pn, clock, "a", "192.168.1.10:41641")
	b := newProbeNode(t, pn, clock, "b", "192.168.1.20:41641")
	c := newProbeNode(t, pn, clock, "c", "192.168.1.30:41641") // not paired
	pair(a, b)
	c.p.setPeers(c.dev, []trust.Device{b.dev})

	var pongs int
	b.p.sendDirect = func(pkt []byte, _ netip.AddrPort) error {
		if m, err := parseProbe(pkt); err == nil && m.kind == probePong {
			pongs++
		}
		return nil
	}
	from := netip.MustParseAddrPort("192.168.1.10:41641")
	ping := func(sender *probeNode, to trust.Device, clockAt time.Time, txid byte) []byte {
		var m probeMsg
		m.kind, m.clock, m.txid[0] = probePing, clockAt.Unix(), txid
		m.from, _ = decodeID(sender.dev.ID)
		m.to, _ = decodeID(to.ID)
		pkt, err := encodeProbe(m, sender.secrets.SigningKey())
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}
	good := ping(a, b.dev, now, 1)
	b.p.handle(probeIn{data: good, from: from})
	if pongs != 1 {
		t.Fatalf("valid ping: %d pongs", pongs)
	}
	b.p.handle(probeIn{data: good, from: from})
	if pongs != 1 {
		t.Fatal("replayed ping answered")
	}
	cases := map[string][]byte{
		"not a tunnel peer":  ping(c, b.dev, now, 2),
		"other receiver":     ping(a, c.dev, now, 3),
		"clock too far back": ping(a, b.dev, now.Add(-probeClockSkew-time.Minute), 4),
		"clock too far on":   ping(a, b.dev, now.Add(probeClockSkew+time.Minute), 5),
	}
	forged := ping(a, b.dev, now, 6)
	forged[len(forged)-1] ^= 1
	cases["bad signature"] = forged
	for name, pkt := range cases {
		b.p.handle(probeIn{data: pkt, from: from})
		if pongs != 1 {
			t.Fatalf("%s: answered", name)
		}
	}
	// Relayed probes must come from the device they claim to be.
	var wrongID [control.RelayIDLen]byte
	b.p.handle(probeIn{data: ping(a, b.dev, now, 7), relay: true, relID: wrongID})
	if len(b.relayed) != 0 {
		t.Fatal("relayed ping with a mismatching relay id answered")
	}
	// The verification budget caps signature checks.
	b.p.mu.Lock()
	b.p.tokens, b.p.tokenAt = 0, now
	b.p.mu.Unlock()
	b.p.handle(probeIn{data: ping(a, b.dev, now, 8), from: from})
	if pongs != 1 {
		t.Fatal("ping verified without budget")
	}
}

// A pong counts only for the address the ping went to, within the reply
// timeout.
func TestPongMustMatchPing(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	pn := newProbeNet()
	a := newProbeNode(t, pn, clock, "a", "192.168.1.10:41641")
	b := newProbeNode(t, pn, clock, "b", "198.51.100.20:41641")
	pair(a, b)
	// b's NAT answers from another port (endpoint-dependent mapping).
	pn.natAs[b.p] = netip.MustParseAddrPort("198.51.100.20:60000")
	a.p.setInfo(b.dev.WireGuardKey, netip.MustParseAddrPort("198.51.100.20:41641"), nil)
	a.p.round(statusOf(b.dev), staleHandshake)
	if _, ok := a.p.validated(b.dev.WireGuardKey, probeFresh); ok {
		t.Fatal("pong from another address validated the path")
	}
	delete(pn.natAs, b.p)
	a.p.called(b.dev.ID, netip.AddrPort{}, nil)
	if _, ok := a.p.validated(b.dev.WireGuardKey, probeFresh); ok {
		t.Fatal("called() probed again within calledMinInterval")
	}
	now = now.Add(calledMinInterval)
	a.p.called(b.dev.ID, netip.AddrPort{}, nil)
	if _, ok := a.p.validated(b.dev.WireGuardKey, probeFresh); !ok {
		t.Fatal("call did not probe")
	}
}

func TestRelayPing(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	pn := newProbeNet()
	a := newProbeNode(t, pn, clock, "a", "192.168.1.10:41641")
	b := newProbeNode(t, pn, clock, "b", "192.168.1.20:41641")
	pair(a, b)
	aID, _ := decodeID(a.dev.ID)
	bID, _ := decodeID(b.dev.ID)
	go func() {
		// The "coordinator": deliver a's relayed ping to b and b's pong to a.
		ping := <-a.relayed
		b.p.handle(probeIn{data: ping, relay: true, relID: aID})
		pong := <-b.relayed
		a.p.handle(probeIn{data: pong, relay: true, relID: bID})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := a.p.pingRelay(ctx, b.dev.ID); err != nil {
		t.Fatal(err)
	}
	// A relayed pong never validates a direct path.
	if _, ok := a.p.validated(b.dev.WireGuardKey, probeFresh); ok {
		t.Fatal("relay pong validated a direct path")
	}
	if _, err := a.p.pingRelay(ctx, hex.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("ping to an unknown peer")
	}
}

// choosePaths moves a relayed peer to a validated direct path at once and
// upgrades a direct peer to a better validated class.
func TestChoosePathsUsesValidatedProbes(t *testing.T) {
	r := newPathRig(t, false)
	r.e.probe = newProber(r.e.cfg.Now, testLogger(t, "x"), nil)
	r.peer.ID = hex.EncodeToString(append(make([]byte, 15), 9))
	r.e.probe.setPeers(trust.Device{ID: hex.EncodeToString(make([]byte, 16))}, []trust.Device{r.peer})
	lan := netip.MustParseAddrPort("192.168.1.9:41641")
	validate := func(ap netip.AddrPort) {
		r.e.probe.mu.Lock()
		r.e.probe.peers[r.peer.ID].valid[ap] = validPath{at: r.now, rtt: time.Millisecond}
		r.e.probe.mu.Unlock()
	}

	// On the relay with a long retry wait.
	r.cur = wgconf.PeerStatus{Relayed: true}
	r.step()
	validate(lan)
	uapi := r.step()
	if !contains(uapi, "endpoint="+lan.String()) {
		t.Fatalf("relayed peer not moved to the validated path: %q", uapi)
	}

	// Direct on the public endpoint with a fresh handshake: a validated
	// LAN path is better.
	r2 := newPathRig(t, false)
	r2.e.probe = newProber(r2.e.cfg.Now, testLogger(t, "y"), nil)
	r2.peer.ID = r.peer.ID
	r2.e.probe.setPeers(trust.Device{ID: hex.EncodeToString(make([]byte, 16))}, []trust.Device{r2.peer})
	r2.step()
	r2.handshake()
	r2.e.probe.mu.Lock()
	r2.e.probe.peers[r2.peer.ID].valid[lan] = validPath{at: r2.now}
	r2.e.probe.mu.Unlock()
	uapi = r2.e.choosePaths([]trust.Device{r2.peer}, wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{r2.peer.WireGuardKey: r2.cur}}, r2.direct)
	if !contains(uapi, "endpoint="+lan.String()) {
		t.Fatalf("no upgrade to the LAN path: %q", uapi)
	}
	// A validated path of the same class as the working one is no reason
	// to move.
	r3 := newPathRig(t, false)
	r3.e.probe = newProber(r3.e.cfg.Now, testLogger(t, "z"), nil)
	r3.peer.ID = r.peer.ID
	r3.e.probe.setPeers(trust.Device{ID: hex.EncodeToString(make([]byte, 16))}, []trust.Device{r3.peer})
	r3.step()
	r3.handshake()
	r3.e.probe.mu.Lock()
	r3.e.probe.peers[r3.peer.ID].valid[netip.MustParseAddrPort("203.0.113.77:1")] = validPath{at: r3.now}
	r3.e.probe.mu.Unlock()
	if uapi := r3.e.choosePaths([]trust.Device{r3.peer}, wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{r3.peer.WireGuardKey: r3.cur}}, r3.direct); uapi != "" {
		t.Fatalf("moved between equal paths: %q", uapi)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
