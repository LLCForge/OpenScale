package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Hybrid post-quantum pre-shared keys (ADR-0033, F-127, #1, #2).
//
// Every pair of devices runs an ML-KEM-768 exchange inside its own
// WireGuard tunnel and gives the result to WireGuard as the pair's
// preshared_key. WireGuard mixes the PSK into every later handshake together
// with its X25519 results, so the session stays secret unless both X25519
// and ML-KEM-768 are broken: traffic recorded today cannot be decrypted by
// a future quantum computer alone.
//
// The device with the lower WireGuard public key (bytewise) is the
// initiator; the other only answers. Four messages, each signed with the
// sender's device signing key from the root-signed document (Ed25519ctx,
// context pqContext):
//
//	init    I -> R  session, ML-KEM-768 encapsulation key
//	resp    R -> I  session, SHA-256 of init, ciphertext
//	confirm I -> R  session, HMAC proving I derived the same keys
//	ack     R -> I  session, HMAC proving R derived the same keys
//
// R hands the PSK to WireGuard when the confirm arrives, I when the ack
// arrives; WireGuard keeps using its current session keys and uses the PSK
// from its next handshake on, so the switch does not interrupt traffic.
// A peer that never answers (older version, post-quantum turned off) stays
// "classical": no PSK, exactly as before.
//
// Signed message (all integers big-endian):
//
//	0   magic "OSPQ" (4)
//	4   version 1 (1)
//	5   kind: 1 init, 2 resp, 3 confirm, 4 ack (1)
//	6   session id (16)
//	22  sender device id (16)
//	38  receiver device id (16)
//	54  sender clock, unix seconds (8)
//	62  payload (kind dependent)
//	..  Ed25519ctx signature of everything before it (64)
//
// Messages are carried in at most two UDP datagrams (the encapsulation key
// alone is 1184 bytes), each with a fragment header: magic "OSPQ" (4),
// version (1), kind (1), fragment index (1), fragment count (1), session
// id (16), then up to pqFragMax bytes of the signed message.
const (
	pqMagic       = "OSPQ"
	pqVersion     = 1
	pqContext     = "openscale/pq-psk/v1"
	pqKindInit    = 1
	pqKindResp    = 2
	pqKindConfirm = 3
	pqKindAck     = 4
	pqHdrLen      = 62
	pqFragHdrLen  = 24
	pqFragMax     = 1000
	pqMACLen      = sha256.Size
	pqInitLen     = pqHdrLen + mlkem.EncapsulationKeySize768 + ed25519.SignatureSize
	pqRespLen     = pqHdrLen + sha256.Size + mlkem.CiphertextSize768 + ed25519.SignatureSize
	pqConfirmLen  = pqHdrLen + pqMACLen + ed25519.SignatureSize
	pqMaxMsgLen   = pqInitLen
)

// Post-quantum timing.
const (
	// DefaultPSKRotation is how often the initiator agrees on a new PSK.
	DefaultPSKRotation = 10 * time.Minute
	MinPSKRotation     = 2 * time.Minute
	MaxPSKRotation     = 24 * time.Hour
	pqRotationJitter   = 0.1
	// pqRetransmit and pqMaxTries: an unanswered message is sent again.
	pqRetransmit = 2 * time.Second
	pqMaxTries   = 4
	// pqUnsupportedRecheck: a peer that never answered is asked again
	// after this long (it may have been upgraded).
	pqUnsupportedRecheck = 10 * time.Minute
	// pqRetryAfter: a failed rotation of a peer that answered before.
	pqRetryAfter = time.Minute
	// pqRotateFreshness: a rotation starts only right after a handshake,
	// so the current WireGuard session has two minutes left in which a
	// handshake that fails during the switch is simply retried.
	pqRotateFreshness = time.Minute
	// pqFresh: a handshake this recent means the tunnel works.
	pqFresh = staleHandshake + 30*time.Second
	// pqStaleReset: a PSK without a handshake for this long is dropped (the
	// peer restarted and forgot it, or the last message of a rotation was
	// lost); both sides then fall back to classical and agree again.
	pqStaleReset = 3 * time.Minute
	// pqResponderTimeout drops an unconfirmed responder exchange.
	pqResponderTimeout = 30 * time.Second
	// pqInitMinInterval rate-limits key encapsulation per peer.
	pqInitMinInterval = time.Second
	// Reset hints (sent through the path probe channel, outside the
	// tunnel): first wait, then doubling up to the maximum.
	pqHintFirst = 15 * time.Second
	pqHintMax   = 10 * time.Minute
	// Bounds of received state.
	pqQueue        = 64
	pqMaxFrags     = 64
	pqFragTimeout  = 5 * time.Second
	pqMaxSeen      = 64
	pqSeenWindow   = 2 * probeClockSkew
	pqVerifyRate   = 50
	pqVerifyBurst  = 100
	pqTickInterval = time.Second
)

// PostQuantumMode turns the post-quantum PSK on or off (ADR-0033).
type PostQuantumMode uint8

const (
	// PostQuantumDefault is the zero value: on.
	PostQuantumDefault PostQuantumMode = iota
	// PostQuantumOn agrees on a PSK with every peer that supports it.
	PostQuantumOn
	// PostQuantumOff never agrees on a PSK and ignores peers' requests;
	// to them this device looks like an older version (classical).
	PostQuantumOff
)

// Enabled reports whether the mode agrees on PSKs.
func (m PostQuantumMode) Enabled() bool { return m != PostQuantumOff }

// Post-quantum state of a peer, as PeerPath.PostQuantum reports it.
const (
	PQStateActive      = "pq"          // a PSK is in use
	PQStateNegotiating = "negotiating" // agreeing on the first PSK
	PQStateClassical   = "classical"   // no PSK (peer did not answer yet)
	PQStateUnsupported = "unsupported" // peer did not answer: older version or turned off
	PQStateOff         = "off"         // turned off on this device
)

var errPQFormat = errors.New("malformed post-quantum message")

// pqMsg is a parsed signed message.
type pqMsg struct {
	kind     byte
	session  [16]byte
	from, to [16]byte
	clock    int64
	payload  []byte
}

func pqExpectedLen(kind byte) int {
	switch kind {
	case pqKindInit:
		return pqInitLen
	case pqKindResp:
		return pqRespLen
	case pqKindConfirm, pqKindAck:
		return pqConfirmLen
	}
	return 0
}

func encodePQ(m pqMsg, key ed25519.PrivateKey) ([]byte, error) {
	b := make([]byte, pqHdrLen, pqHdrLen+len(m.payload)+ed25519.SignatureSize)
	copy(b, pqMagic)
	b[4], b[5] = pqVersion, m.kind
	copy(b[6:22], m.session[:])
	copy(b[22:38], m.from[:])
	copy(b[38:54], m.to[:])
	binary.BigEndian.PutUint64(b[54:62], uint64(m.clock)) //nolint:gosec // two's complement round trip
	b = append(b, m.payload...)
	if len(b)+ed25519.SignatureSize != pqExpectedLen(m.kind) {
		return nil, errPQFormat
	}
	sig, err := key.Sign(nil, b, &ed25519.Options{Context: pqContext})
	if err != nil {
		return nil, err
	}
	return append(b, sig...), nil
}

// parsePQ checks the layout only; verifyPQ checks the signature.
func parsePQ(b []byte) (pqMsg, error) {
	var m pqMsg
	if len(b) < pqHdrLen+ed25519.SignatureSize || string(b[:4]) != pqMagic || b[4] != pqVersion {
		return m, errPQFormat
	}
	m.kind = b[5]
	if want := pqExpectedLen(m.kind); want == 0 || len(b) != want {
		return m, errPQFormat
	}
	copy(m.session[:], b[6:22])
	copy(m.from[:], b[22:38])
	copy(m.to[:], b[38:54])
	m.clock = int64(binary.BigEndian.Uint64(b[54:62])) //nolint:gosec // two's complement round trip
	m.payload = b[pqHdrLen : len(b)-ed25519.SignatureSize]
	return m, nil
}

func verifyPQ(b []byte, signing trust.Key) bool {
	n := len(b) - ed25519.SignatureSize
	if n <= 0 {
		return false
	}
	return ed25519.VerifyWithOptions(ed25519.PublicKey(signing[:]), b[:n], b[n:], &ed25519.Options{Context: pqContext}) == nil
}

// fragmentPQ splits a signed message into datagrams.
func fragmentPQ(msg []byte, kind byte, session [16]byte) [][]byte {
	count := (len(msg) + pqFragMax - 1) / pqFragMax
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		part := msg[i*pqFragMax : min((i+1)*pqFragMax, len(msg))]
		d := make([]byte, pqFragHdrLen, pqFragHdrLen+len(part))
		copy(d, pqMagic)
		d[4], d[5], d[6], d[7] = pqVersion, kind, byte(i), byte(count) //nolint:gosec // count <= 2
		copy(d[8:24], session[:])
		out = append(out, append(d, part...))
	}
	return out
}

type pqFragKey struct {
	src     netip.Addr
	kind    byte
	session [16]byte
}

type pqFragBuf struct {
	parts [][]byte
	have  int
	at    time.Time
}

// pqKeys derives the PSK and the key-confirmation key. The shared secret is
// bound to the session, both WireGuard static keys (in a fixed order) and
// the two signed messages that produced it.
func pqKeys(shared []byte, session [16]byte, a, b trust.Key, initHash, respHash [32]byte) (psk, kc [32]byte, err error) {
	lo, hi := a, b
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	var info strings.Builder
	info.WriteString(pqContext)
	info.WriteString("/psk")
	info.Write(lo[:])
	info.Write(hi[:])
	info.Write(initHash[:])
	info.Write(respHash[:])
	out, err := hkdf.Key(sha256.New, shared, session[:], info.String(), 64)
	if err != nil {
		return psk, kc, err
	}
	copy(psk[:], out[:32])
	copy(kc[:], out[32:])
	clear(out)
	return psk, kc, nil
}

func pqMAC(kc [32]byte, role string, session [16]byte) []byte {
	h := hmac.New(sha256.New, kc[:])
	h.Write([]byte(pqContext + "/confirm/" + role))
	h.Write(session[:])
	return h.Sum(nil)
}

// pqOutgoing is the initiator's exchange in progress.
type pqOutgoing struct {
	session  [16]byte
	dk       *mlkem.DecapsulationKey768
	initMsg  []byte
	initHash [32]byte
	// stage 1 waits for resp, stage 2 for ack.
	stage      int
	tries      int
	nextSend   time.Time
	psk, kc    [32]byte
	confirmMsg []byte
}

// pqIncoming is the responder's exchange waiting for the confirm.
type pqIncoming struct {
	session [16]byte
	psk, kc [32]byte
	respMsg []byte
	ackMsg  []byte
	applied bool
	at      time.Time
}

// pqPeer is the post-quantum state of one tunnel peer.
type pqPeer struct {
	dev       trust.Device
	id        [16]byte
	initiator bool

	hasPSK    bool
	psk       [32]byte
	appliedAt time.Time

	out         *pqOutgoing
	nextAt      time.Time
	everOK      bool
	unsupported bool

	in       *pqIncoming
	seen     map[[16]byte]time.Time
	lastInit time.Time
	// peerClock is the sender clock of the peer's latest verified message;
	// older reset hints are ignored.
	peerClock int64

	hintAt   time.Time
	hintWait time.Duration
}

type pqIn struct {
	src  netip.Addr
	data []byte
}

// pqStatus is WireGuard's view the manager works from.
type pqStatus struct {
	st   wgconf.Status
	psks map[trust.Key][32]byte
}

// pqManager runs the exchanges of an engine. Its mutex is never held while
// calling into WireGuard or the network.
type pqManager struct {
	now      func() time.Time
	logger   *slog.Logger
	key      ed25519.PrivateKey
	wgKey    trust.Key
	rotation time.Duration
	rand     func() float64

	// send injects one datagram into the tunnel to dst; setPSK hands a PSK
	// (zero: none) to WireGuard; status reads WireGuard; hint asks a peer,
	// outside the tunnel, to drop its PSK.
	send   func(dst netip.Addr, datagram []byte) bool
	setPSK func(peer trust.Key, psk [32]byte) error
	status func() (pqStatus, error)
	hint   func(peerID string)

	in chan pqIn

	mu      sync.Mutex
	self    trust.Device
	selfID  [16]byte
	peers   map[trust.Key]*pqPeer
	byID    map[[16]byte]trust.Key
	frags   map[pqFragKey]*pqFragBuf
	tokens  float64
	tokenAt time.Time
}

func newPQManager(now func() time.Time, logger *slog.Logger, key ed25519.PrivateKey, wgKey trust.Key, rotation time.Duration, rnd func() float64) *pqManager {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &pqManager{now: now, logger: logger, key: key, wgKey: wgKey, rotation: rotation, rand: rnd,
		in: make(chan pqIn, pqQueue), peers: map[trust.Key]*pqPeer{}, byID: map[[16]byte]trust.Key{},
		frags: map[pqFragKey]*pqFragBuf{}, tokens: pqVerifyBurst}
}

// setPeers installs the current tunnel peers. State of unchanged peers is
// kept, also while a lazy peer is out of WireGuard (ADR-0032 F-020), so its
// PSK is given back when it returns.
func (m *pqManager) setPeers(self trust.Device, peers []trust.Device) {
	selfID, _ := decodeID(self.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.self, m.selfID = self, selfID
	next := make(map[trust.Key]*pqPeer, len(peers))
	m.byID = make(map[[16]byte]trust.Key, len(peers))
	for _, d := range peers {
		id, ok := decodeID(d.ID)
		if !ok {
			continue
		}
		p := m.peers[d.WireGuardKey]
		if p == nil || p.dev.SigningKey != d.SigningKey || p.dev.ID != d.ID {
			p = &pqPeer{id: id, initiator: bytes.Compare(m.wgKey[:], d.WireGuardKey[:]) < 0, seen: map[[16]byte]time.Time{}}
		}
		p.dev = d
		next[d.WireGuardKey] = p
		m.byID[id] = d.WireGuardKey
	}
	m.peers = next
}

// deliver queues a received datagram without blocking WireGuard.
func (m *pqManager) deliver(src netip.Addr, data []byte) {
	select {
	case m.in <- pqIn{src: src, data: append([]byte(nil), data...)}:
	default:
	}
}

// run processes datagrams and timers until ctx ends.
func (m *pqManager) run(ctx context.Context) {
	t := time.NewTicker(pqTickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case in := <-m.in:
			m.receive(in)
		case <-t.C:
			m.tick()
		}
	}
}

// tick drives retransmits, rotations, stale resets and reset hints.
func (m *pqManager) tick() {
	ps, err := m.status()
	if err != nil {
		return
	}
	now := m.now()
	type action struct {
		frags  [][]byte
		dst    netip.Addr
		setPSK *[32]byte
		key    trust.Key
		hint   string
		log    string
	}
	var acts []action
	m.mu.Lock()
	m.expireFragsLocked(now)
	for key, p := range m.peers {
		cur, configured := ps.st.Peers[key]
		if !configured {
			continue
		}
		wgPSK := ps.psks[key]
		var last time.Time
		if cur.LastHandshakeUnix > 0 {
			last = time.Unix(cur.LastHandshakeUnix, 0)
		}
		fresh := !last.IsZero() && now.Sub(last) < pqFresh
		if fresh {
			p.hintWait, p.hintAt = 0, time.Time{}
		}
		// WireGuard must hold what we agreed on (a lazy peer re-added, a
		// peer update) and nothing else.
		switch {
		case p.hasPSK && wgPSK != p.psk:
			psk := p.psk
			acts = append(acts, action{setPSK: &psk, key: key})
		case !p.hasPSK && wgPSK != [32]byte{}:
			acts = append(acts, action{setPSK: &[32]byte{}, key: key})
		}
		if p.hasPSK {
			since := p.appliedAt
			if last.After(since) {
				since = last
			}
			if now.Sub(since) >= pqStaleReset {
				m.dropLocked(p)
				acts = append(acts, action{setPSK: &[32]byte{}, key: key, hint: p.dev.ID, log: "no handshake with the post-quantum PSK; back to classical"})
				p.hintWait = pqHintFirst
				p.hintAt = now.Add(p.hintWait)
				continue
			}
		} else if !fresh && !now.Before(p.hintAt) {
			// We hold no PSK and cannot reach the peer: it may still hold
			// one from before our restart. Ask it to drop it.
			acts = append(acts, action{hint: p.dev.ID})
			p.hintWait = min(max(2*p.hintWait, pqHintFirst), pqHintMax)
			p.hintAt = now.Add(p.hintWait)
		}
		if p.in != nil && !p.in.applied && now.Sub(p.in.at) > pqResponderTimeout {
			p.in = nil
		}
		if !p.initiator {
			continue
		}
		if o := p.out; o != nil {
			if now.Before(o.nextSend) {
				continue
			}
			if o.tries >= pqMaxTries {
				p.out = nil
				if p.everOK {
					p.nextAt = now.Add(pqRetryAfter)
				} else {
					if !p.unsupported {
						acts = append(acts, action{key: key, log: "peer does not answer the post-quantum exchange; staying classical"})
					}
					p.unsupported = true
					p.nextAt = now.Add(pqUnsupportedRecheck)
				}
				continue
			}
			o.tries++
			o.nextSend = now.Add(pqRetransmit)
			msg := o.initMsg
			kind := byte(pqKindInit)
			if o.stage == 2 {
				msg, kind = o.confirmMsg, pqKindConfirm
			}
			acts = append(acts, action{frags: fragmentPQ(msg, kind, o.session), dst: p.dev.IPv4})
			continue
		}
		if !fresh || now.Before(p.nextAt) || (p.hasPSK && now.Sub(last) > pqRotateFreshness) {
			continue
		}
		o, err := m.startLocked(p, now)
		if err != nil {
			m.logger.Warn("post-quantum exchange", "error", err.Error())
			p.nextAt = now.Add(pqRetryAfter)
			continue
		}
		p.out = o
		acts = append(acts, action{frags: fragmentPQ(o.initMsg, pqKindInit, o.session), dst: p.dev.IPv4})
	}
	m.mu.Unlock()
	for _, a := range acts {
		if a.setPSK != nil {
			if err := m.setPSK(a.key, *a.setPSK); err != nil {
				m.logger.Warn("set preshared key", "error", err.Error())
			}
		}
		if a.log != "" {
			m.logger.Info(a.log, "peer", m.peerName(a.key))
		}
		if a.hint != "" && m.hint != nil {
			m.hint(a.hint)
		}
		for _, f := range a.frags {
			m.send(a.dst, f)
		}
	}
}

func (m *pqManager) peerName(key trust.Key) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.peers[key]; p != nil {
		return p.dev.Name
	}
	return ""
}

// dropLocked forgets the PSK and any exchange in progress; the initiator
// agrees again as soon as the tunnel works.
func (m *pqManager) dropLocked(p *pqPeer) {
	p.hasPSK, p.psk, p.appliedAt = false, [32]byte{}, time.Time{}
	p.out, p.in = nil, nil
	if p.initiator {
		p.nextAt = time.Time{}
	}
}

// startLocked begins a new exchange as the initiator.
func (m *pqManager) startLocked(p *pqPeer, now time.Time) (*pqOutgoing, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	o := &pqOutgoing{dk: dk, stage: 1, tries: 1, nextSend: now.Add(pqRetransmit)}
	if _, err := rand.Read(o.session[:]); err != nil {
		return nil, err
	}
	o.initMsg, err = encodePQ(pqMsg{kind: pqKindInit, session: o.session, from: m.selfID, to: p.id, clock: now.Unix(), payload: dk.EncapsulationKey().Bytes()}, m.key)
	if err != nil {
		return nil, err
	}
	o.initHash = sha256.Sum256(o.initMsg)
	return o, nil
}

// takeTokenLocked spends one signature check.
func (m *pqManager) takeTokenLocked(now time.Time) bool {
	if !m.tokenAt.IsZero() {
		m.tokens = min(pqVerifyBurst, m.tokens+now.Sub(m.tokenAt).Seconds()*pqVerifyRate)
	}
	m.tokenAt = now
	if m.tokens < 1 {
		return false
	}
	m.tokens--
	return true
}

func (m *pqManager) expireFragsLocked(now time.Time) {
	for k, f := range m.frags {
		if now.Sub(f.at) > pqFragTimeout {
			delete(m.frags, k)
		}
	}
}

// reassemble adds one datagram and returns the complete message, if any.
func (m *pqManager) reassemble(src netip.Addr, d []byte, now time.Time) []byte {
	if len(d) <= pqFragHdrLen || string(d[:4]) != pqMagic || d[4] != pqVersion {
		return nil
	}
	kind, idx, count := d[5], int(d[6]), int(d[7])
	want := pqExpectedLen(kind)
	if want == 0 || count != (want+pqFragMax-1)/pqFragMax || idx >= count {
		return nil
	}
	part := d[pqFragHdrLen:]
	if wantPart := min(pqFragMax, want-idx*pqFragMax); len(part) != wantPart {
		return nil
	}
	if count == 1 {
		return part
	}
	k := pqFragKey{src: src, kind: kind, session: [16]byte(d[8:24])}
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.frags[k]
	if f == nil {
		if len(m.frags) >= pqMaxFrags {
			m.expireFragsLocked(now)
			if len(m.frags) >= pqMaxFrags {
				return nil // fail closed: bounded memory
			}
		}
		f = &pqFragBuf{parts: make([][]byte, count), at: now}
		m.frags[k] = f
	}
	if f.parts[idx] == nil {
		f.parts[idx] = part
		f.have++
	}
	if f.have < count {
		return nil
	}
	delete(m.frags, k)
	return bytes.Join(f.parts, nil)
}

// receive handles one datagram from the tunnel.
func (m *pqManager) receive(in pqIn) {
	now := m.now()
	msg := m.reassemble(in.src, in.data, now)
	if msg == nil {
		return
	}
	pm, err := parsePQ(msg)
	if err != nil {
		return
	}
	m.mu.Lock()
	key, known := m.byID[pm.from]
	p := m.peers[key]
	ok := known && p != nil && pm.to == m.selfID && p.dev.IPv4 == in.src && now.Before(p.dev.ExpiresAt)
	if ok {
		skew := now.Sub(time.Unix(pm.clock, 0))
		ok = skew <= probeClockSkew && skew >= -probeClockSkew
	}
	if ok {
		ok = m.takeTokenLocked(now)
	}
	var signing trust.Key
	if ok {
		signing = p.dev.SigningKey
	}
	m.mu.Unlock()
	if !ok || !verifyPQ(msg, signing) {
		return
	}
	switch pm.kind {
	case pqKindInit:
		m.onInit(key, pm, msg, now)
	case pqKindResp:
		m.onResp(key, pm, msg, now)
	case pqKindConfirm:
		m.onConfirm(key, pm, now)
	case pqKindAck:
		m.onAck(key, pm, now)
	}
}

// onInit answers an initiator: encapsulate, derive, keep the keys until the
// confirm proves the initiator has them too.
func (m *pqManager) onInit(key trust.Key, pm pqMsg, msg []byte, now time.Time) {
	m.mu.Lock()
	p := m.peers[key]
	if p == nil || p.initiator {
		m.mu.Unlock()
		return // only the peer with the lower key initiates
	}
	if _, seen := p.seen[pm.session]; seen {
		var resend []byte
		if p.in != nil && p.in.session == pm.session && !p.in.applied {
			resend = p.in.respMsg // our resp was lost
		}
		m.mu.Unlock()
		if resend != nil {
			m.sendFrags(p.dev.IPv4, resend, pqKindResp, pm.session)
		}
		return
	}
	if now.Sub(p.lastInit) < pqInitMinInterval {
		m.mu.Unlock()
		return
	}
	if len(p.seen) >= pqMaxSeen {
		for s, at := range p.seen {
			if now.Sub(at) > pqSeenWindow {
				delete(p.seen, s)
			}
		}
		if len(p.seen) >= pqMaxSeen {
			m.mu.Unlock()
			return
		}
	}
	p.seen[pm.session] = now
	p.lastInit = now
	p.peerClock = max(p.peerClock, pm.clock)
	selfID, peerID, dst := m.selfID, p.id, p.dev.IPv4
	m.mu.Unlock()

	ek, err := mlkem.NewEncapsulationKey768(pm.payload)
	if err != nil {
		return
	}
	shared, ct := ek.Encapsulate()
	initHash := sha256.Sum256(msg)
	payload := append(initHash[:], ct...)
	resp, err := encodePQ(pqMsg{kind: pqKindResp, session: pm.session, from: selfID, to: peerID, clock: now.Unix(), payload: payload}, m.key)
	if err != nil {
		return
	}
	psk, kc, err := pqKeys(shared, pm.session, m.wgKey, key, initHash, sha256.Sum256(resp))
	clear(shared)
	if err != nil {
		return
	}
	m.mu.Lock()
	if p := m.peers[key]; p != nil {
		p.in = &pqIncoming{session: pm.session, psk: psk, kc: kc, respMsg: resp, at: now}
	}
	m.mu.Unlock()
	m.sendFrags(dst, resp, pqKindResp, pm.session)
}

// onResp completes the initiator's side and sends the confirm.
func (m *pqManager) onResp(key trust.Key, pm pqMsg, msg []byte, now time.Time) {
	m.mu.Lock()
	p := m.peers[key]
	if p == nil || p.out == nil || p.out.stage != 1 || p.out.session != pm.session {
		m.mu.Unlock()
		return
	}
	o := p.out
	m.mu.Unlock()
	if subtle.ConstantTimeCompare(pm.payload[:sha256.Size], o.initHash[:]) != 1 {
		return
	}
	shared, err := o.dk.Decapsulate(pm.payload[sha256.Size:])
	if err != nil {
		return
	}
	psk, kc, err := pqKeys(shared, pm.session, m.wgKey, key, o.initHash, sha256.Sum256(msg))
	clear(shared)
	if err != nil {
		return
	}
	m.mu.Lock()
	p = m.peers[key]
	if p == nil || p.out != o || o.stage != 1 {
		m.mu.Unlock()
		return
	}
	confirm, err := encodePQ(pqMsg{kind: pqKindConfirm, session: pm.session, from: m.selfID, to: p.id, clock: now.Unix(), payload: pqMAC(kc, "initiator", pm.session)}, m.key)
	if err != nil {
		m.mu.Unlock()
		return
	}
	o.stage, o.tries, o.nextSend = 2, 1, now.Add(pqRetransmit)
	o.psk, o.kc, o.confirmMsg, o.dk = psk, kc, confirm, nil
	p.peerClock = max(p.peerClock, pm.clock)
	dst := p.dev.IPv4
	m.mu.Unlock()
	m.sendFrags(dst, confirm, pqKindConfirm, pm.session)
}

// onConfirm: the initiator proved it holds the keys. The responder hands
// the PSK to WireGuard and acknowledges.
func (m *pqManager) onConfirm(key trust.Key, pm pqMsg, now time.Time) {
	m.mu.Lock()
	p := m.peers[key]
	if p == nil || p.in == nil || p.in.session != pm.session {
		m.mu.Unlock()
		return
	}
	in := p.in
	if !hmac.Equal(pm.payload, pqMAC(in.kc, "initiator", pm.session)) {
		m.mu.Unlock()
		return
	}
	apply := !in.applied
	if apply {
		ack, err := encodePQ(pqMsg{kind: pqKindAck, session: pm.session, from: m.selfID, to: p.id, clock: now.Unix(), payload: pqMAC(in.kc, "responder", pm.session)}, m.key)
		if err != nil {
			m.mu.Unlock()
			return
		}
		in.applied, in.ackMsg = true, ack
		p.hasPSK, p.psk, p.appliedAt = true, in.psk, now
		p.peerClock = max(p.peerClock, pm.clock)
	}
	ack, dst, psk, name := in.ackMsg, p.dev.IPv4, in.psk, p.dev.Name
	m.mu.Unlock()
	if apply {
		if err := m.setPSK(key, psk); err != nil {
			m.logger.Warn("set preshared key", "error", err.Error())
		} else {
			m.logger.Info("post-quantum PSK agreed", "peer", name, "role", "responder")
		}
	}
	m.sendFrags(dst, ack, pqKindAck, pm.session)
}

// onAck: the responder holds the PSK; the initiator uses it too.
func (m *pqManager) onAck(key trust.Key, pm pqMsg, now time.Time) {
	m.mu.Lock()
	p := m.peers[key]
	if p == nil || p.out == nil || p.out.stage != 2 || p.out.session != pm.session || !hmac.Equal(pm.payload, pqMAC(p.out.kc, "responder", pm.session)) {
		m.mu.Unlock()
		return
	}
	psk := p.out.psk
	p.out = nil
	p.hasPSK, p.psk, p.appliedAt = true, psk, now
	p.everOK, p.unsupported = true, false
	p.peerClock = max(p.peerClock, pm.clock)
	jitter := 1 + pqRotationJitter*(2*m.rand()-1)
	p.nextAt = now.Add(time.Duration(float64(m.rotation) * jitter))
	name := p.dev.Name
	m.mu.Unlock()
	if err := m.setPSK(key, psk); err != nil {
		m.logger.Warn("set preshared key", "error", err.Error())
		return
	}
	m.logger.Info("post-quantum PSK agreed", "peer", name, "role", "initiator")
}

// onResetHint handles a verified reset hint from a peer (sent through the
// probe channel): the peer holds no PSK for us, so ours can only break the
// handshake. Hints older than the peer's latest exchange are stale copies.
func (m *pqManager) onResetHint(peerID [16]byte, clock int64) {
	m.mu.Lock()
	key, ok := m.byID[peerID]
	p := m.peers[key]
	if !ok || p == nil || clock <= p.peerClock || (!p.hasPSK && p.out == nil && p.in == nil) {
		m.mu.Unlock()
		return
	}
	had := p.hasPSK
	m.dropLocked(p)
	m.mu.Unlock()
	if had {
		if err := m.setPSK(key, [32]byte{}); err != nil {
			m.logger.Warn("set preshared key", "error", err.Error())
		}
		m.logger.Info("peer lost the post-quantum PSK; back to classical until agreed again", "peer", p.dev.Name)
	}
}

func (m *pqManager) sendFrags(dst netip.Addr, msg []byte, kind byte, session [16]byte) {
	for _, f := range fragmentPQ(msg, kind, session) {
		m.send(dst, f)
	}
}

// current returns the PSK agreed with a peer, if any.
func (m *pqManager) current(key trust.Key) ([32]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.peers[key]
	if p == nil || !p.hasPSK {
		return [32]byte{}, false
	}
	return p.psk, true
}

// pqView is the post-quantum state of one peer for diagnostics.
type pqView struct {
	state string
	since time.Time
}

func (m *pqManager) view(key trust.Key) pqView {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.peers[key]
	switch {
	case p == nil:
		return pqView{state: PQStateClassical}
	case p.hasPSK:
		return pqView{state: PQStateActive, since: p.appliedAt}
	case p.unsupported:
		return pqView{state: PQStateUnsupported}
	case p.out != nil || p.in != nil:
		return pqView{state: PQStateNegotiating}
	}
	return pqView{state: PQStateClassical}
}

// parsePSKs reads each peer's preshared_key from IpcGet output.
func parsePSKs(raw string) map[trust.Key][32]byte {
	out := map[trust.Key][32]byte{}
	var cur *trust.Key
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			raw, err := hex.DecodeString(v)
			if err != nil || len(raw) != trust.KeySize {
				cur = nil
				continue
			}
			key := trust.Key(raw)
			cur = &key
		case "preshared_key":
			raw, err := hex.DecodeString(v)
			if cur != nil && err == nil && len(raw) == 32 {
				out[*cur] = [32]byte(raw)
			}
		}
	}
	return out
}

// pskUAPI sets one peer's preshared key (all zero: none).
func pskUAPI(key trust.Key, psk [32]byte) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\npreshared_key=%s\n", hex.EncodeToString(key[:]), hex.EncodeToString(psk[:]))
}

// receivePQ takes post-quantum datagrams from peers out of the tunnel
// before the packet filter. With post-quantum turned off they fall through
// to the filter, exactly as on an older version.
func (e *Engine) receivePQ(pkt []byte) bool {
	if e.pq == nil {
		return false
	}
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoUDP || in.Fragment || in.DstPort != control.PQPort || in.SrcPort != control.PQPort {
		return false
	}
	e.client.mu.Lock()
	self := e.client.self
	e.client.mu.Unlock()
	if in.Dst != self {
		return false
	}
	e.pq.deliver(in.Src, in.Payload)
	return true
}

// sendPQ sends one post-quantum datagram to a peer inside its tunnel.
func (e *Engine) sendPQ(dst netip.Addr, datagram []byte) bool {
	e.client.mu.Lock()
	self := e.client.self
	e.client.mu.Unlock()
	if !self.IsValid() || e.wrap == nil {
		return false
	}
	pkt, err := packet.BuildUDP4(self, dst, control.PQPort, control.PQPort, datagram)
	if err != nil {
		return false
	}
	return e.wrap.Inject(pkt)
}

// setPSK hands a peer's pre-shared key to WireGuard.
func (e *Engine) setPSK(peer trust.Key, psk [32]byte) error {
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil {
		return errors.New("tunnel is not running")
	}
	return dev.IpcSet(pskUAPI(peer, psk))
}

// pqStatus reads WireGuard's peers and their pre-shared keys.
func (e *Engine) pqStatus() (pqStatus, error) {
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil {
		return pqStatus{}, errors.New("tunnel is not running")
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return pqStatus{}, err
	}
	st, err := wgconf.ParseStatus(raw)
	if err != nil {
		return pqStatus{}, err
	}
	return pqStatus{st: st, psks: parsePSKs(raw)}, nil
}

// PostQuantumState returns the post-quantum state of a peer (PQState*) and
// since when its current PSK is in use.
func (e *Engine) PostQuantumState(peer trust.Key) (string, time.Time) {
	if e.pq == nil {
		return PQStateOff, time.Time{}
	}
	v := e.pq.view(peer)
	return v.state, v.since
}
