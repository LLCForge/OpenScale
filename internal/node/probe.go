package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Path probing (ADR-0025, F-001). A device sends small signed "ping"
// datagrams from its WireGuard socket to every candidate address of a peer;
// the peer answers each with a signed "pong" to the address the ping came
// from. A pong proves that UDP flows both ways on that path, through the
// same NAT mapping WireGuard uses, so WireGuard can be pointed there.
//
// Wire format (all integers big-endian):
//
//	0   magic "OSPATH" (6)        never a WireGuard message (type 1-4, 0, 0, 0)
//	6   kind: 1 ping, 2 pong, 3 post-quantum reset hint (1; ADR-0033)
//	7   format version 1 (1)
//	8   sender device id (16)
//	24  receiver device id (16)
//	40  transaction id (12)
//	52  sender clock, unix seconds (8)
//	60  pong only: address the ping came from: 16-byte IPv6 or mapped IPv4,
//	    2-byte port, 1-byte family (4 or 6)
//	..  Ed25519ctx signature of everything before it (64), context
//	    probeContext, by the sender's device signing key from the document.
const (
	probeMagic   = "OSPATH"
	probeVersion = 1
	probePing    = 1
	probePong    = 2
	// probeReset tells a peer this device holds no post-quantum PSK for it
	// (ADR-0033); same layout as a ping, never answered. Older versions
	// drop it as malformed.
	probeReset   = 3
	probeContext = "openscale/path-probe/v1"
	probeHdrLen  = 60
	probeAddrLen = 19
	probePingLen = probeHdrLen + ed25519.SignatureSize
	probePongLen = probeHdrLen + probeAddrLen + ed25519.SignatureSize
)

// Probe timing and bounds.
const (
	// probeReplyTimeout: a pong later than this does not count.
	probeReplyTimeout = 5 * time.Second
	// probeFresh: a path validated this recently may replace the current
	// one at once (path upgrade, or leaving the relay before DirectRetry).
	probeFresh = 30 * time.Second
	// probeBestTTL: how long a validated path is remembered as the best.
	probeBestTTL = 2 * time.Minute
	// probeInterval is the first wait between probe rounds of a peer that
	// needs a better path; each fruitless round doubles it up to probeMaxWait.
	probeInterval = 20 * time.Second
	probeMaxWait  = 10 * time.Minute
	// callEvery rate-limits asking the coordinator to make a peer probe us.
	callEvery = 30 * time.Second
	// probeClockSkew: pings with a clock further off are refused.
	probeClockSkew = 5 * time.Minute
	// replayWindow: transaction ids of answered pings are kept this long.
	replayWindow    = 2 * probeClockSkew
	maxPendingPings = 1024
	maxReplay       = 8192
	// Signature checks are rate-limited (a flood of junk must not burn
	// CPU): verifyRate per second with a burst of verifyBurst.
	verifyRate  = 100
	verifyBurst = 200
	probeQueue  = 256
	// calledMinInterval rate-limits probes caused by pushed calls.
	calledMinInterval = 2 * time.Second
)

var errProbeFormat = errors.New("malformed path probe")

// isProbe reports whether a datagram on the WireGuard socket is a probe.
func isProbe(b []byte) bool {
	return len(b) >= len(probeMagic) && string(b[:len(probeMagic)]) == probeMagic
}

type probeMsg struct {
	kind     byte
	from, to [16]byte
	txid     [12]byte
	clock    int64
	observed netip.AddrPort
}

func encodeProbe(m probeMsg, key ed25519.PrivateKey) ([]byte, error) {
	n := probeHdrLen
	if m.kind == probePong {
		n += probeAddrLen
	}
	b := make([]byte, n, n+ed25519.SignatureSize)
	copy(b, probeMagic)
	b[6], b[7] = m.kind, probeVersion
	copy(b[8:24], m.from[:])
	copy(b[24:40], m.to[:])
	copy(b[40:52], m.txid[:])
	binary.BigEndian.PutUint64(b[52:60], uint64(m.clock)) //nolint:gosec // two's complement round trip
	if m.kind == probePong {
		a := m.observed.Addr()
		raw := a.As16()
		copy(b[60:76], raw[:])
		binary.BigEndian.PutUint16(b[76:78], m.observed.Port())
		b[78] = 6
		if a.Is4() || a.Is4In6() {
			b[78] = 4
		}
		if !m.observed.IsValid() {
			b[78] = 0
		}
	}
	sig, err := key.Sign(nil, b, &ed25519.Options{Context: probeContext})
	if err != nil {
		return nil, err
	}
	return append(b, sig...), nil
}

// parseProbe checks the layout only; the signature is checked by verify.
func parseProbe(b []byte) (probeMsg, error) {
	var m probeMsg
	if !isProbe(b) || len(b) < probePingLen || b[7] != probeVersion {
		return m, errProbeFormat
	}
	m.kind = b[6]
	switch {
	case (m.kind == probePing || m.kind == probeReset) && len(b) == probePingLen:
	case m.kind == probePong && len(b) == probePongLen:
	default:
		return m, errProbeFormat
	}
	copy(m.from[:], b[8:24])
	copy(m.to[:], b[24:40])
	copy(m.txid[:], b[40:52])
	m.clock = int64(binary.BigEndian.Uint64(b[52:60])) //nolint:gosec // two's complement round trip
	if m.kind == probePong {
		raw := [16]byte(b[60:76])
		port := binary.BigEndian.Uint16(b[76:78])
		switch b[78] {
		case 4:
			m.observed = netip.AddrPortFrom(netip.AddrFrom16(raw).Unmap(), port)
		case 6:
			m.observed = netip.AddrPortFrom(netip.AddrFrom16(raw), port)
		case 0:
		default:
			return m, errProbeFormat
		}
	}
	return m, nil
}

// verifyProbe checks the signature with the sender's signing key.
func verifyProbe(b []byte, signing trust.Key) bool {
	n := len(b) - ed25519.SignatureSize
	if n <= 0 {
		return false
	}
	return ed25519.VerifyWithOptions(ed25519.PublicKey(signing[:]), b[:n], b[n:], &ed25519.Options{Context: probeContext}) == nil
}

// validPath is a candidate that answered.
type validPath struct {
	at  time.Time
	rtt time.Duration
}

// peerProbe is the probing state of one tunnel peer.
type peerProbe struct {
	dev      trust.Device
	id       [16]byte
	observed netip.AddrPort
	cands    []netip.AddrPort
	// prflx is the address the peer's last valid ping came from.
	prflx netip.AddrPort
	valid map[netip.AddrPort]validPath
	// seenAs is this device's address as the peer saw it (from its pong).
	seenAs    netip.AddrPort
	seenAt    time.Time
	lastProbe time.Time
	nextProbe time.Time
	failures  int
	lastCall  time.Time
	lastClass pathClass
	// predict adds predicted ports to the next round (ADR-0042, #54).
	predict bool
	// sealed are the candidates the peer sent end-to-end encrypted
	// (ADR-0230); peerHard and peerScan its NAT hints from the same blob.
	sealed   []netip.AddrPort
	peerHard bool
	peerScan bool
	// lastScan is the last birthday scan (ADR-0231); until scanUntil pongs
	// from another port of a probed address count.
	lastScan  time.Time
	scanUntil time.Time
}

func (pp *peerProbe) targets() []netip.AddrPort {
	var out []netip.AddrPort
	for _, ap := range slices.Concat(pp.sealed, pp.cands, []netip.AddrPort{pp.observed, pp.prflx}) {
		if usableRemote(ap) && !slices.Contains(out, ap) {
			out = append(out, ap)
		}
	}
	return out
}

// best returns the best path validated within ttl.
func (pp *peerProbe) best(now time.Time, ttl time.Duration) (netip.AddrPort, validPath, bool) {
	var (
		bestAP netip.AddrPort
		bestV  validPath
		found  bool
	)
	for ap, v := range pp.valid {
		if now.Sub(v.at) > ttl {
			continue
		}
		c, bc := classify(ap), classify(bestAP)
		if !found || c > bc || (c == bc && v.rtt < bestV.rtt) {
			bestAP, bestV, found = ap, v, true
		}
	}
	return bestAP, bestV, found
}

type pendingPing struct {
	peer  string
	to    netip.AddrPort
	relay bool
	sent  time.Time
	done  chan time.Duration
	// lenient accepts the pong from another port of to's address: during a
	// birthday scan the peer's NAT answers from a fresh mapping (ADR-0231).
	lenient bool
}

type probeIn struct {
	data  []byte
	from  netip.AddrPort
	relay bool
	relID [control.RelayIDLen]byte
}

// prober runs path probing for an engine. Its mutex is never held while
// calling into the engine; the engine may call it while holding Engine.mu.
type prober struct {
	now    func() time.Time
	logger *slog.Logger
	key    ed25519.PrivateKey
	// sendDirect sends a datagram from the WireGuard socket; sendRelay
	// through the coordinator; improved tells the engine a better path
	// answered.
	sendDirect func(pkt []byte, to netip.AddrPort) error
	sendRelay  func(id [control.RelayIDLen]byte, pkt []byte) bool
	improved   func()
	// onReset receives a verified post-quantum reset hint (ADR-0033).
	onReset func(from [16]byte, clock int64)
	in      chan probeIn
	// interval and maxWait are probeInterval and probeMaxWait (tests
	// shorten them).
	interval, maxWait time.Duration

	mu      sync.Mutex
	selfID  [16]byte
	peers   map[string]*peerProbe
	byKey   map[trust.Key]string
	pending map[[12]byte]*pendingPing
	replay  map[[12]byte]time.Time
	tokens  float64
	tokenAt time.Time

	// Birthday scan (portpredict.go, ADR-0231). selfHard estimates this
	// device's NAT; it calls into the engine, so never with mu held.
	selfHard   func() bool
	scanOff    bool
	scanProbes int
	scanPace   time.Duration
	scanRand   *mrand.Rand
	scanTokens float64
	scanAt     time.Time
	scans      int
}

func newProber(now func() time.Time, logger *slog.Logger, key ed25519.PrivateKey) *prober {
	return &prober{now: now, logger: logger, key: key, in: make(chan probeIn, probeQueue), interval: probeInterval, maxWait: probeMaxWait,
		peers: map[string]*peerProbe{}, byKey: map[trust.Key]string{}, pending: map[[12]byte]*pendingPing{},
		replay: map[[12]byte]time.Time{}, tokens: verifyBurst,
		scanProbes: DefaultBirthdayProbes, scanPace: time.Second / birthdayRate, scanRand: newScanRand(), scanTokens: birthdayBudget}
}

// setSealed installs what a peer's sealed blob said (ADR-0230). A changed
// candidate set restarts that peer's probe backoff.
func (p *prober) setSealed(peerID string, sp sealedPayload) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pp := p.peers[peerID]
	if pp == nil {
		return
	}
	if !slices.Equal(pp.sealed, sp.cands) {
		pp.failures, pp.nextProbe = 0, time.Time{}
	}
	pp.sealed, pp.peerHard, pp.peerScan = slices.Clone(sp.cands), sp.hardNAT, sp.scan
}

// seenAsAll returns this device's addresses as peers saw them within fresh.
func (p *prober) seenAsAll(fresh time.Duration) []netip.AddrPort {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []netip.AddrPort
	for _, pp := range p.peers {
		if pp.seenAs.IsValid() && now.Sub(pp.seenAt) <= fresh {
			out = append(out, pp.seenAs)
		}
	}
	return out
}

// wantsHardNAT reports whether some peer could be scanned, so the engine's
// NAT estimate is computed only then.
func (p *prober) wantsHardNAT() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scanOff || p.selfHard == nil {
		return false
	}
	for _, pp := range p.peers {
		if pp.peerHard && pp.peerScan {
			return true
		}
	}
	return false
}

func decodeID(s string) ([16]byte, bool) {
	var id [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(id) {
		return id, false
	}
	copy(id[:], raw)
	return id, true
}

// setPeers installs the current tunnel peers; state of remaining peers is
// kept.
func (p *prober) setPeers(self trust.Device, peers []trust.Device) {
	selfID, _ := decodeID(self.ID)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.selfID = selfID
	next := make(map[string]*peerProbe, len(peers))
	p.byKey = make(map[trust.Key]string, len(peers))
	for _, d := range peers {
		id, ok := decodeID(d.ID)
		if !ok {
			continue
		}
		pp := p.peers[d.ID]
		if pp == nil || pp.dev.SigningKey != d.SigningKey || pp.dev.WireGuardKey != d.WireGuardKey {
			pp = &peerProbe{id: id, valid: map[netip.AddrPort]validPath{}}
		}
		pp.dev = d
		next[d.ID] = pp
		p.byKey[d.WireGuardKey] = d.ID
	}
	p.peers = next
}

// setInfo records what the coordinator says about a peer. A changed
// candidate set restarts that peer's probe backoff.
func (p *prober) setInfo(key trust.Key, observed netip.AddrPort, cands []netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pp := p.peers[p.byKey[key]]
	if pp == nil {
		return
	}
	if pp.observed != observed || !slices.Equal(pp.cands, cands) {
		pp.failures, pp.nextProbe = 0, time.Time{}
	}
	pp.observed, pp.cands = observed, cands
}

// reset restarts every backoff (network change, forced reconnect) and
// forgets validated paths, which may be gone with the old network.
func (p *prober) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pp := range p.peers {
		pp.failures, pp.nextProbe, pp.lastCall = 0, time.Time{}, time.Time{}
		pp.valid = map[netip.AddrPort]validPath{}
		pp.prflx = netip.AddrPort{}
	}
}

// called handles a pushed call: the peer is probing us now, so probe it
// back at once (simultaneous hole punching).
func (p *prober) called(peerID string, observed netip.AddrPort, cands []netip.AddrPort) {
	hard := p.wantsHardNAT() && p.selfHard()
	now := p.now()
	p.mu.Lock()
	pp := p.peers[peerID]
	if pp == nil || !now.Before(pp.dev.ExpiresAt) || now.Sub(pp.lastProbe) < calledMinInterval {
		p.mu.Unlock()
		return
	}
	if observed.IsValid() {
		pp.observed = observed
	}
	if len(cands) > 0 {
		pp.cands = cands
	}
	pp.failures, pp.nextProbe = 0, time.Time{}
	pings := p.pingsLocked(pp, now)
	var scan []outPing
	if p.scanEligibleLocked(pp, hard, now) {
		// The caller scans too (it asked us because it is relayed).
		scan = p.scanPingsLocked(pp, now)
	}
	p.mu.Unlock()
	p.send(pings)
	p.sendPaced(scan)
}

type outPing struct {
	pkt []byte
	to  netip.AddrPort
}

// pingsLocked builds one ping per target and records them as pending.
func (p *prober) pingsLocked(pp *peerProbe, now time.Time) []outPing {
	p.expireLocked(now)
	pp.lastProbe = now
	var out []outPing
	for _, to := range pp.probeTargets() {
		if len(p.pending) >= maxPendingPings {
			break
		}
		pkt, txid, err := p.newPingLocked(pp, now)
		if err != nil {
			continue
		}
		p.pending[txid] = &pendingPing{peer: pp.dev.ID, to: to, sent: now, lenient: now.Before(pp.scanUntil)}
		out = append(out, outPing{pkt: pkt, to: to})
	}
	return out
}

func (p *prober) newPingLocked(pp *peerProbe, now time.Time) ([]byte, [12]byte, error) {
	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, txid, err
	}
	pkt, err := encodeProbe(probeMsg{kind: probePing, from: p.selfID, to: pp.id, txid: txid, clock: now.Unix()}, p.key)
	return pkt, txid, err
}

func (p *prober) send(pings []outPing) {
	if p.sendDirect == nil {
		return // the engine is not running
	}
	for _, o := range pings {
		if err := p.sendDirect(o.pkt, o.to); err != nil {
			p.logger.Debug("path probe", "error", err.Error())
		}
	}
}

// round probes the peers that need a better path and returns the ids of
// peers to call through the coordinator. st is WireGuard's current view.
func (p *prober) round(st wgconf.Status, staleAfter time.Duration) []string {
	hard := p.wantsHardNAT() && p.selfHard()
	now := p.now()
	var (
		pings []outPing
		scan  []outPing
		calls []string
	)
	p.mu.Lock()
	for _, pp := range p.peers {
		cur, ok := st.Peers[pp.dev.WireGuardKey]
		if !ok || !now.Before(pp.dev.ExpiresAt) {
			continue
		}
		var last time.Time
		if cur.LastHandshakeUnix > 0 {
			last = time.Unix(cur.LastHandshakeUnix, 0)
		}
		stale := last.IsZero() || now.Sub(last) > staleAfter
		curClass := classify(cur.Endpoint)
		if cur.Relayed {
			curClass = classRelay
		}
		targets := pp.targets()
		maxClass := classNone
		for _, t := range targets {
			maxClass = max(maxClass, classify(t))
		}
		if curClass < pp.lastClass {
			// The path got worse (lost LAN, fell back to the relay).
			pp.failures, pp.nextProbe = 0, time.Time{}
		}
		pp.lastClass = curClass
		need := len(targets) > 0 && (cur.Relayed || stale || maxClass > curClass)
		if !need {
			pp.failures, pp.nextProbe = 0, time.Time{}
			continue
		}
		if now.Before(pp.nextProbe) {
			continue
		}
		pp.predict = cur.Relayed && pp.failures > 0
		pings = append(pings, p.pingsLocked(pp, now)...)
		scanned := cur.Relayed && pp.failures >= birthdayAfter && p.scanEligibleLocked(pp, hard, now)
		if scanned {
			scan = append(scan, p.scanPingsLocked(pp, now)...)
		}
		wait := p.interval << min(pp.failures, 5)
		pp.nextProbe = now.Add(min(wait, p.maxWait))
		pp.failures++
		// A scan always calls: the peer must scan at the same time.
		if (cur.Relayed || stale) && (scanned || now.Sub(pp.lastCall) >= callEvery) {
			pp.lastCall = now
			calls = append(calls, pp.dev.ID)
		}
	}
	p.mu.Unlock()
	p.send(pings)
	p.sendPaced(scan)
	return calls
}

// expireLocked drops old pending pings and replay entries.
func (p *prober) expireLocked(now time.Time) {
	for k, pp := range p.pending {
		if now.Sub(pp.sent) > probeReplyTimeout {
			delete(p.pending, k)
		}
	}
	if len(p.replay) > maxReplay/2 {
		for k, at := range p.replay {
			if now.Sub(at) > replayWindow {
				delete(p.replay, k)
			}
		}
	}
}

// takeToken spends one signature check; false when the budget is used up.
func (p *prober) takeToken(now time.Time) bool {
	if !p.tokenAt.IsZero() {
		p.tokens = min(verifyBurst, p.tokens+now.Sub(p.tokenAt).Seconds()*verifyRate)
	}
	p.tokenAt = now
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	return true
}

// deliver queues a received probe without blocking the receive path.
func (p *prober) deliver(in probeIn) {
	select {
	case p.in <- in:
	default:
	}
}

// run processes received probes until ctx ends.
func (p *prober) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case in := <-p.in:
			p.handle(in)
		}
	}
}

// handle verifies one probe and answers a ping or records a pong.
func (p *prober) handle(in probeIn) {
	m, err := parseProbe(in.data)
	if err != nil {
		return
	}
	now := p.now()
	p.mu.Lock()
	pp := p.peers[hex.EncodeToString(m.from[:])]
	ok := pp != nil && m.to == p.selfID && now.Before(pp.dev.ExpiresAt) && (!in.relay || in.relID == m.from)
	if ok {
		skew := now.Sub(time.Unix(m.clock, 0))
		ok = skew <= probeClockSkew && skew >= -probeClockSkew
	}
	if ok {
		ok = p.takeToken(now)
	}
	var signing trust.Key
	if ok {
		signing = pp.dev.SigningKey
	}
	p.mu.Unlock()
	if !ok || !verifyProbe(in.data, signing) {
		return
	}
	switch m.kind {
	case probePing:
		p.answer(m, pp, in, now)
	case probePong:
		p.record(m, in, now)
	case probeReset:
		p.resetHint(m, now)
	}
}

// resetHint passes a verified post-quantum reset hint on, once per
// transaction id (copies arrive directly and through the relay).
func (p *prober) resetHint(m probeMsg, now time.Time) {
	p.mu.Lock()
	if _, seen := p.replay[m.txid]; seen {
		p.mu.Unlock()
		return
	}
	if len(p.replay) >= maxReplay {
		p.expireLocked(now)
		if len(p.replay) >= maxReplay {
			p.mu.Unlock()
			return
		}
	}
	p.replay[m.txid] = now
	fn := p.onReset
	p.mu.Unlock()
	if fn != nil {
		fn(m.from, m.clock)
	}
}

// sendReset sends a signed post-quantum reset hint to a peer on every known
// path and through the relay: the tunnel to it may be what is broken.
func (p *prober) sendReset(peerID string) {
	now := p.now()
	p.mu.Lock()
	pp := p.peers[peerID]
	if pp == nil {
		p.mu.Unlock()
		return
	}
	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		p.mu.Unlock()
		return
	}
	pkt, err := encodeProbe(probeMsg{kind: probeReset, from: p.selfID, to: pp.id, txid: txid, clock: now.Unix()}, p.key)
	targets, id := pp.targets(), pp.id
	p.mu.Unlock()
	if err != nil {
		return
	}
	if p.sendDirect != nil {
		for _, to := range targets {
			if err := p.sendDirect(pkt, to); err != nil {
				p.logger.Debug("post-quantum reset hint", "error", err.Error())
			}
		}
	}
	if p.sendRelay != nil {
		p.sendRelay(id, pkt)
	}
}

// answer sends a pong for a verified ping, once per transaction id.
func (p *prober) answer(m probeMsg, pp *peerProbe, in probeIn, now time.Time) {
	p.mu.Lock()
	if _, seen := p.replay[m.txid]; seen {
		p.mu.Unlock()
		return
	}
	if len(p.replay) >= maxReplay {
		p.expireLocked(now)
		if len(p.replay) >= maxReplay {
			p.mu.Unlock()
			return // fail closed: no unbounded memory, no unchecked replays
		}
	}
	p.replay[m.txid] = now
	if !in.relay && in.from.IsValid() && pp.prflx != in.from {
		// The peer reached us from here; probe it back on this address.
		pp.prflx = in.from
	}
	selfID, peerID := p.selfID, pp.id
	p.mu.Unlock()
	pong, err := encodeProbe(probeMsg{kind: probePong, from: selfID, to: peerID, txid: m.txid, clock: now.Unix(), observed: in.from}, p.key)
	if err != nil {
		return
	}
	if in.relay {
		if p.sendRelay != nil {
			p.sendRelay(peerID, pong)
		}
		return
	}
	if p.sendDirect == nil {
		return
	}
	if err := p.sendDirect(pong, in.from); err != nil {
		p.logger.Debug("path probe reply", "error", err.Error())
	}
}

// record matches a verified pong with its ping and validates the path.
func (p *prober) record(m probeMsg, in probeIn, now time.Time) {
	p.mu.Lock()
	pend, ok := p.pending[m.txid]
	if !ok || pend.peer != hex.EncodeToString(m.from[:]) || pend.relay != in.relay || now.Sub(pend.sent) > probeReplyTimeout ||
		(!in.relay && pend.to != in.from && !(pend.lenient && pend.to.Addr() == in.from.Addr())) {
		p.mu.Unlock()
		return
	}
	delete(p.pending, m.txid)
	rtt := now.Sub(pend.sent)
	if pend.done != nil {
		select {
		case pend.done <- rtt:
		default:
		}
	}
	improved := false
	if pp := p.peers[pend.peer]; pp != nil && !in.relay {
		before, _, had := pp.best(now, probeBestTTL)
		pp.valid[pend.to] = validPath{at: now, rtt: rtt}
		if o := m.observed.Addr().Unmap(); m.observed.IsValid() && !o.IsPrivate() && !o.IsLoopback() {
			// Only public views say anything about this device's NAT.
			pp.seenAs, pp.seenAt = m.observed, now
		}
		after, _, _ := pp.best(now, probeBestTTL)
		improved = !had || classify(after) > classify(before) || after == pend.to
	}
	p.mu.Unlock()
	if improved && p.improved != nil {
		p.improved()
	}
}

// validated returns the best path of a peer validated within fresh.
func (p *prober) validated(key trust.Key, fresh time.Duration) (netip.AddrPort, bool) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	pp := p.peers[p.byKey[key]]
	if pp == nil {
		return netip.AddrPort{}, false
	}
	ap, _, ok := pp.best(now, fresh)
	return ap, ok
}

// pingRelay sends one ping to a peer through the coordinator and waits for
// the pong (F-016 relay test).
func (p *prober) pingRelay(ctx context.Context, peerID string) (time.Duration, error) {
	now := p.now()
	done := make(chan time.Duration, 1)
	p.mu.Lock()
	pp := p.peers[peerID]
	if pp == nil {
		p.mu.Unlock()
		return 0, errors.New("eş bu cihazın tünel eşi değil")
	}
	p.expireLocked(now)
	pkt, txid, err := p.newPingLocked(pp, now)
	if err != nil {
		p.mu.Unlock()
		return 0, err
	}
	p.pending[txid] = &pendingPing{peer: peerID, relay: true, sent: now, done: done}
	id := pp.id
	p.mu.Unlock()
	if p.sendRelay == nil || !p.sendRelay(id, pkt) {
		return 0, errors.New("aktarıcıya gönderilemedi (koordinatör tüneli hazır değil)")
	}
	timer := time.NewTimer(probeReplyTimeout)
	defer timer.Stop()
	select {
	case rtt := <-done:
		return rtt, nil
	case <-timer.C:
		return 0, errors.New("eş aktarıcı üzerinden yanıt vermedi (eski sürüm olabilir)")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// probeSnapshot is the probing view of one peer for diagnostics.
type probeSnapshot struct {
	observed netip.AddrPort
	cands    []netip.AddrPort
	best     netip.AddrPort
	bestRTT  time.Duration
	bestAt   time.Time
	seenAs   netip.AddrPort
	seenAt   time.Time
	next     time.Time
}

func (p *prober) snapshot(key trust.Key) (probeSnapshot, bool) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	pp := p.peers[p.byKey[key]]
	if pp == nil {
		return probeSnapshot{}, false
	}
	s := probeSnapshot{observed: pp.observed, cands: slices.Concat(pp.sealed, pp.cands), seenAs: pp.seenAs, seenAt: pp.seenAt, next: pp.nextProbe}
	if ap, v, ok := pp.best(now, probeBestTTL); ok {
		s.best, s.bestRTT, s.bestAt = ap, v.rtt, v.at
	}
	return s, true
}

// intercept wraps a receive function so probes are taken out of the batch
// and handed to the prober; WireGuard sees only its own packets. Kept
// packets are moved to the front by copying (see onlyCoordinator).
func (p *prober) intercept(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for i := 0; i < n; i++ {
			data := packets[i][:sizes[i]]
			if isProbe(data) {
				in := probeIn{data: append([]byte(nil), data...)}
				switch ep := eps[i].(type) {
				case *relayEndpoint:
					in.relay, in.relID = true, ep.id
				case nil:
					continue
				default:
					ap, perr := netip.ParseAddrPort(ep.DstToString())
					if perr != nil {
						continue
					}
					in.from = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
				}
				p.deliver(in)
				continue
			}
			if kept != i {
				sizes[kept] = copy(packets[kept], packets[i][:sizes[i]])
				eps[kept] = eps[i]
			}
			kept++
		}
		return kept, err
	}
}
