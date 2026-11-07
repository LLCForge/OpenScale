package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// pqClock is a manual clock shared by the managers of a test.
type pqClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *pqClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *pqClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// pqNode is one device with a fake WireGuard: its PSKs and the time of the
// last handshake with each peer.
type pqNode struct {
	dev     trust.Device
	secrets *trust.DeviceSecrets
	m       *pqManager
	mu      sync.Mutex
	psks    map[trust.Key][32]byte
	last    map[trust.Key]time.Time
	sets    int
	hints   []string
}

// pqWire connects managers in memory; drop, when set, decides which
// datagrams are lost (by sender and kind).
type pqWire struct {
	mu    sync.Mutex
	nodes map[netip.Addr]*pqNode
	drop  func(from *pqNode, kind byte) bool
}

func newPQNode(t *testing.T, w *pqWire, clock *pqClock, name string, ip string) *pqNode {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, wg, err := s.PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	n := &pqNode{secrets: s, psks: map[trust.Key][32]byte{}, last: map[trust.Key]time.Time{}}
	n.dev = trust.Device{ID: s.DeviceID, Name: name, SigningKey: sig, WireGuardKey: wg, IPv4: netip.MustParseAddr(ip), ExpiresAt: time.Now().Add(24 * time.Hour)}
	n.m = newPQManager(clock.now, testLogger(t, name), s.SigningKey(), wg, DefaultPSKRotation, func() float64 { return 0.5 })
	n.m.setPSK = func(peer trust.Key, psk [32]byte) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.psks[peer] = psk
		n.sets++
		return nil
	}
	n.m.status = func() (pqStatus, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		ps := pqStatus{st: wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{}}, psks: map[trust.Key][32]byte{}}
		for k, at := range n.last {
			var unix int64
			if !at.IsZero() {
				unix = at.Unix()
			}
			ps.st.Peers[k] = wgconf.PeerStatus{LastHandshakeUnix: unix}
			ps.psks[k] = n.psks[k]
		}
		return ps, nil
	}
	n.m.hint = func(id string) {
		n.mu.Lock()
		n.hints = append(n.hints, id)
		n.mu.Unlock()
	}
	n.m.send = func(dst netip.Addr, d []byte) bool {
		w.mu.Lock()
		to := w.nodes[dst]
		drop := w.drop
		w.mu.Unlock()
		if to == nil || (drop != nil && drop(n, d[5])) {
			return false
		}
		to.m.receive(pqIn{src: n.dev.IPv4, data: append([]byte(nil), d...)})
		return true
	}
	w.mu.Lock()
	if w.nodes == nil {
		w.nodes = map[netip.Addr]*pqNode{}
	}
	w.nodes[n.dev.IPv4] = n
	w.mu.Unlock()
	return n
}

// pair makes a and b tunnel peers with a fresh handshake.
func pqPair(a, b *pqNode, now time.Time) {
	self := func(n *pqNode) trust.Device { return n.dev }
	a.m.setPeers(self(a), []trust.Device{b.dev})
	b.m.setPeers(self(b), []trust.Device{a.dev})
	a.handshake(b, now)
	b.handshake(a, now)
}

func (n *pqNode) handshake(peer *pqNode, at time.Time) {
	n.mu.Lock()
	n.last[peer.dev.WireGuardKey] = at
	n.mu.Unlock()
}

func (n *pqNode) psk(peer *pqNode) [32]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.psks[peer.dev.WireGuardKey]
}

// newPQPair returns the initiator first.
func newPQPair(t *testing.T) (*pqWire, *pqClock, *pqNode, *pqNode) {
	t.Helper()
	w := &pqWire{}
	clock := &pqClock{t: time.Now()}
	a := newPQNode(t, w, clock, "a", "100.64.0.1")
	b := newPQNode(t, w, clock, "b", "100.64.0.2")
	if bytes.Compare(a.dev.WireGuardKey[:], b.dev.WireGuardKey[:]) > 0 {
		a, b = b, a
	}
	pqPair(a, b, clock.now())
	return w, clock, a, b
}

func tickBoth(a, b *pqNode) {
	a.m.tick()
	b.m.tick()
}

func TestPQAgreesOnPSK(t *testing.T) {
	_, _, a, b := newPQPair(t)
	if !a.m.peers[b.dev.WireGuardKey].initiator || b.m.peers[a.dev.WireGuardKey].initiator {
		t.Fatal("the lower WireGuard key must initiate, and only it")
	}
	tickBoth(a, b)
	pa, pb := a.psk(b), b.psk(a)
	if pa == ([32]byte{}) || pa != pb {
		t.Fatalf("PSKs differ or are empty: %x %x", pa, pb)
	}
	for _, n := range []*pqNode{a, b} {
		other := b
		if n == b {
			other = a
		}
		if v := n.m.view(other.dev.WireGuardKey); v.state != PQStateActive {
			t.Fatalf("%s state %q, want %q", n.dev.Name, v.state, PQStateActive)
		}
	}
	// Nothing more happens until the rotation is due.
	setsA, setsB := a.sets, b.sets
	tickBoth(a, b)
	if a.sets != setsA || b.sets != setsB || a.psk(b) != pa {
		t.Fatal("PSK changed before the rotation was due")
	}
}

func TestPQRotatesWithoutLosingAgreement(t *testing.T) {
	_, clock, a, b := newPQPair(t)
	tickBoth(a, b)
	first := a.psk(b)
	// Rotation is due; a handshake just happened.
	clock.add(DefaultPSKRotation + time.Second)
	a.handshake(b, clock.now())
	b.handshake(a, clock.now())
	tickBoth(a, b)
	second := a.psk(b)
	if second == first || second == ([32]byte{}) || second != b.psk(a) {
		t.Fatalf("rotation failed: first %x, a %x, b %x", first, second, b.psk(a))
	}
	// A rotation waits for a fresh handshake, so the current WireGuard
	// session has time left if the next handshake races the switch.
	clock.add(DefaultPSKRotation + time.Second)
	a.handshake(b, clock.now().Add(-90*time.Second))
	b.handshake(a, clock.now().Add(-90*time.Second))
	tickBoth(a, b)
	if a.psk(b) != second {
		t.Fatal("rotated without a recent handshake")
	}
}

func TestPQLostAckKeepsOldPSKAndRetransmits(t *testing.T) {
	w, clock, a, b := newPQPair(t)
	tickBoth(a, b)
	first := a.psk(b)
	clock.add(DefaultPSKRotation + time.Second)
	a.handshake(b, clock.now())
	b.handshake(a, clock.now())
	lost := 0
	w.drop = func(from *pqNode, kind byte) bool {
		if kind == pqKindAck && lost == 0 {
			lost++
			return true
		}
		return false
	}
	tickBoth(a, b)
	if a.psk(b) != first {
		t.Fatal("initiator switched before the ack")
	}
	if b.psk(a) == first {
		t.Fatal("responder did not switch on the confirm")
	}
	// The confirm is sent again; the responder acks without a new key.
	clock.add(pqRetransmit)
	setsB := b.sets
	tickBoth(a, b)
	if a.psk(b) != b.psk(a) || b.sets != setsB {
		t.Fatalf("retransmit did not converge: a %x b %x (responder set %d times)", a.psk(b), b.psk(a), b.sets-setsB)
	}
}

func TestPQPeerWithoutSupportStaysClassical(t *testing.T) {
	w, clock, a, b := newPQPair(t)
	w.mu.Lock()
	delete(w.nodes, b.dev.IPv4) // b is an older version: nothing answers
	w.mu.Unlock()
	for i := 0; i <= pqMaxTries; i++ {
		a.m.tick()
		clock.add(pqRetransmit)
		a.handshake(b, clock.now())
	}
	if v := a.m.view(b.dev.WireGuardKey); v.state != PQStateUnsupported {
		t.Fatalf("state %q, want %q", v.state, PQStateUnsupported)
	}
	if a.psk(b) != ([32]byte{}) {
		t.Fatal("a PSK was set for a peer that never answered")
	}
	// It is asked again later (it may have been upgraded).
	w.mu.Lock()
	w.nodes[b.dev.IPv4] = b
	w.mu.Unlock()
	clock.add(pqUnsupportedRecheck)
	a.handshake(b, clock.now())
	b.handshake(a, clock.now())
	tickBoth(a, b)
	if a.psk(b) == ([32]byte{}) || a.psk(b) != b.psk(a) {
		t.Fatal("no agreement after the peer was upgraded")
	}
}

func TestPQRejectsForgedAndMisroutedMessages(t *testing.T) {
	w, clock, a, b := newPQPair(t)
	// A third party that knows the protocol but not b's signing key.
	mallory, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	aID, _ := decodeID(a.dev.ID)
	bID, _ := decodeID(b.dev.ID)
	inject := func(to *pqNode, src netip.Addr, msg []byte, kind byte, session [16]byte) {
		for _, f := range fragmentPQ(msg, kind, session) {
			to.m.receive(pqIn{src: src, data: f})
		}
	}

	// 1. An init "from a" signed with another key: b does not answer.
	dk, _ := mlkem.GenerateKey768()
	var session [16]byte
	_, _ = rand.Read(session[:])
	forged, err := encodePQ(pqMsg{kind: pqKindInit, session: session, from: aID, to: bID, clock: clock.now().Unix(), payload: dk.EncapsulationKey().Bytes()}, mallory.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	inject(b, a.dev.IPv4, forged, pqKindInit, session)
	if b.m.peers[a.dev.WireGuardKey].in != nil {
		t.Fatal("responder accepted a forged init")
	}

	// 2. A correctly signed init arriving from another tunnel address (an
	// exit node may send with any source): refused.
	genuine, err := encodePQ(pqMsg{kind: pqKindInit, session: session, from: aID, to: bID, clock: clock.now().Unix(), payload: dk.EncapsulationKey().Bytes()}, a.secrets.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	inject(b, netip.MustParseAddr("100.64.0.9"), genuine, pqKindInit, session)
	if b.m.peers[a.dev.WireGuardKey].in != nil {
		t.Fatal("responder accepted an init from the wrong address")
	}

	// 3. Too old a clock: refused.
	old, _ := encodePQ(pqMsg{kind: pqKindInit, session: session, from: aID, to: bID, clock: clock.now().Add(-time.Hour).Unix(), payload: dk.EncapsulationKey().Bytes()}, a.secrets.SigningKey())
	inject(b, a.dev.IPv4, old, pqKindInit, session)
	if b.m.peers[a.dev.WireGuardKey].in != nil {
		t.Fatal("responder accepted a stale init")
	}

	// 4. A tampered ciphertext: ML-KEM decapsulates it to another secret,
	// the confirm does not verify, nobody switches.
	w.drop = nil
	tamper := true
	b.m.send = func(dst netip.Addr, d []byte) bool {
		if tamper && d[5] == pqKindResp && d[6] == 0 {
			// Flip a bit in the first fragment's ciphertext. The signature
			// then fails, which is what a forger would face anyway.
			d = append([]byte(nil), d...)
			d[pqFragHdrLen+pqHdrLen+40] ^= 1
		}
		a.m.receive(pqIn{src: b.dev.IPv4, data: d})
		return true
	}
	a.m.tick()
	if a.psk(b) != ([32]byte{}) || b.psk(a) != ([32]byte{}) {
		t.Fatal("a PSK was set after a tampered response")
	}

	// 5. A confirm with a wrong MAC: the responder keeps the old state.
	tamper = false
	clock.add(pqRetransmit)
	a.handshake(b, clock.now())
	var gotConfirm []byte
	a.m.send = func(dst netip.Addr, d []byte) bool {
		if d[5] == pqKindConfirm {
			gotConfirm = append([]byte(nil), d...)
			return true // held back
		}
		b.m.receive(pqIn{src: a.dev.IPv4, data: d})
		return true
	}
	a.m.tick() // retransmits the init; b answers; a sends a confirm
	if gotConfirm == nil {
		t.Fatal("no confirm was produced")
	}
	pm, err := parsePQ(gotConfirm[pqFragHdrLen:])
	if err != nil {
		t.Fatal(err)
	}
	badMAC := bytes.Repeat([]byte{7}, pqMACLen)
	badConfirm, _ := encodePQ(pqMsg{kind: pqKindConfirm, session: pm.session, from: aID, to: bID, clock: clock.now().Unix(), payload: badMAC}, a.secrets.SigningKey())
	inject(b, a.dev.IPv4, badConfirm, pqKindConfirm, pm.session)
	if b.psk(a) != ([32]byte{}) {
		t.Fatal("responder switched on a confirm with a wrong MAC")
	}
	// The genuine confirm still works.
	b.m.receive(pqIn{src: a.dev.IPv4, data: gotConfirm})
	if b.psk(a) == ([32]byte{}) {
		t.Fatal("genuine confirm refused")
	}
}

func TestPQResetHintAndStaleReset(t *testing.T) {
	_, clock, a, b := newPQPair(t)
	tickBoth(a, b)
	if a.psk(b) == ([32]byte{}) {
		t.Fatal("no agreement")
	}
	bID, _ := decodeID(b.dev.ID)
	// A hint older than b's last exchange is a stale copy.
	a.m.onResetHint(bID, clock.now().Add(-time.Minute).Unix())
	if a.psk(b) == ([32]byte{}) {
		t.Fatal("stale reset hint dropped the PSK")
	}
	// b restarted and forgot the PSK: its hint makes a drop it too.
	a.m.onResetHint(bID, clock.now().Add(time.Second).Unix())
	if a.psk(b) != ([32]byte{}) {
		t.Fatal("reset hint did not drop the PSK")
	}
	if v := a.m.view(b.dev.WireGuardKey); v.state == PQStateActive {
		t.Fatal("state still active after the reset")
	}
	// Agreement starts again at once.
	clock.add(pqInitMinInterval)
	a.handshake(b, clock.now())
	b.m.mu.Lock()
	b.m.dropLocked(b.m.peers[a.dev.WireGuardKey])
	b.m.mu.Unlock()
	tickBoth(a, b)
	if a.psk(b) == ([32]byte{}) || a.psk(b) != b.psk(a) {
		t.Fatal("no new agreement after the reset")
	}

	// Without any handshake for pqStaleReset both sides drop the PSK and
	// tell each other (through the probe channel).
	clock.add(pqStaleReset + time.Second)
	tickBoth(a, b)
	if a.psk(b) != ([32]byte{}) || b.psk(a) != ([32]byte{}) {
		t.Fatal("PSK kept without a handshake")
	}
	if len(a.hints) == 0 || len(b.hints) == 0 {
		t.Fatal("no reset hint sent after the stale reset")
	}
}

func TestPQRestoresPSKAfterPeerReadded(t *testing.T) {
	_, _, a, b := newPQPair(t)
	tickBoth(a, b)
	want := a.psk(b)
	// A lazy peer removed from WireGuard and added again comes back without
	// its PSK; the manager gives it back.
	a.mu.Lock()
	a.psks[b.dev.WireGuardKey] = [32]byte{}
	a.mu.Unlock()
	a.m.tick()
	if a.psk(b) != want {
		t.Fatal("PSK not restored after the peer was re-added")
	}
}

func TestPQMessageFormat(t *testing.T) {
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sig, _, _ := s.PublicKeys()
	dk, _ := mlkem.GenerateKey768()
	m := pqMsg{kind: pqKindInit, from: [16]byte{1}, to: [16]byte{2}, clock: 42, payload: dk.EncapsulationKey().Bytes()}
	msg, err := encodePQ(m, s.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != pqInitLen || !verifyPQ(msg, sig) {
		t.Fatal("init does not verify")
	}
	frags := fragmentPQ(msg, pqKindInit, m.session)
	if len(frags) != 2 {
		t.Fatalf("%d fragments", len(frags))
	}
	for _, f := range frags {
		// Every datagram stays well under the tunnel MTU (1280) with its
		// IPv4 and UDP headers.
		if len(f)+28 > 1100 {
			t.Fatalf("fragment of %d bytes", len(f))
		}
	}
	// Wrong length, wrong kind and a signature under another context fail.
	if _, err := parsePQ(msg[:len(msg)-1]); err == nil {
		t.Fatal("short message parsed")
	}
	bad := append([]byte(nil), msg...)
	bad[5] = 9
	if _, err := parsePQ(bad); err == nil {
		t.Fatal("unknown kind parsed")
	}
	other := s.SigningKey()
	n := len(msg) - ed25519.SignatureSize
	sigProbe, _ := other.Sign(nil, msg[:n], &ed25519.Options{Context: probeContext})
	cross := append(append([]byte(nil), msg[:n]...), sigProbe...)
	if verifyPQ(cross, sig) {
		t.Fatal("a signature from another context verified")
	}
}

func TestParsePSKs(t *testing.T) {
	raw := "private_key=00\nlisten_port=1\npublic_key=" + hexKey(trust.Key{1}) + "\npreshared_key=" + hexKey(trust.Key{9}) +
		"\nprotocol_version=1\npublic_key=" + hexKey(trust.Key{2}) + "\npreshared_key=zz\n"
	got := parsePSKs(raw)
	if got[trust.Key{1}] != [32]byte{9} || len(got) != 1 {
		t.Fatalf("parsePSKs = %v", got)
	}
}

func FuzzPQReceive(f *testing.F) {
	clock := &pqClock{t: time.Now()}
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	_, wg, _ := s.PublicKeys()
	m := newPQManager(clock.now, nil, s.SigningKey(), wg, DefaultPSKRotation, func() float64 { return 0.5 })
	m.send = func(netip.Addr, []byte) bool { return true }
	m.setPSK = func(trust.Key, [32]byte) error { return nil }
	f.Add([]byte("OSPQ\x01\x01\x00\x02"))
	f.Add(append([]byte("OSPQ\x01\x03\x00\x01"), make([]byte, 16+pqConfirmLen)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		m.receive(pqIn{src: netip.MustParseAddr("100.64.0.2"), data: data})
		_, _ = parsePQ(data)
	})
}
