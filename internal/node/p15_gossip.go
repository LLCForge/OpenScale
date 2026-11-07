package node

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Device-to-device document exchange (#25, ADR-0111). Devices that have a
// tunnel to each other compare document versions every few minutes and
// pull a newer root-signed document from each other, so a revocation or
// rule change spreads even while every coordinator is down or withholds
// it. Nothing is trusted: the document goes through Store.Accept (root
// signature, network, version order, equivocation) exactly like one from
// a coordinator, and is applied by the sync loop, never on the receive
// path. Root key transitions are left to the coordinator path.

const (
	gossipEvery = 2 * time.Minute
	// gossipSoonMin rate-limits rounds started because no coordinator
	// answered.
	gossipSoonMin = 30 * time.Second
	// gossipPeers is how many peers one round asks.
	gossipPeers = 3
	// gossipFresh: only peers with a handshake this recent are asked, so
	// lazy or offline peers are not woken up.
	gossipFresh = 3 * time.Minute
	// Serving limits: requests per second and burst per peer, and for all
	// peers together. A 1 MiB document is about 1500 chunks.
	gossipPeerRate   = 100
	gossipPeerBurst  = 2000
	gossipTotalRate  = 400
	gossipTotalBurst = 4000
	// gossipPullBackoff: a peer whose document was rejected or whose
	// transfer failed is not pulled from again for this long.
	gossipPullBackoff = 5 * time.Minute
	gossipCallTimeout = 3 * time.Second
)

// gossipInterval is gossipEvery; tests shorten it.
var gossipInterval = gossipEvery

type gossipPull struct {
	peer  trust.Device
	hello control.Message
}

type gossipPending struct {
	data []byte
	from string
}

// gossipState is guarded by its own mutex; serveGossip runs on WireGuard's
// receive path.
type gossipState struct {
	once      sync.Once
	wake      chan struct{}
	pulls     chan gossipPull
	mu        sync.Mutex
	lastRound time.Time
	buckets   map[netip.Addr]*tokenBucket
	total     tokenBucket
	failUntil map[string]time.Time
	pending   *gossipPending
	// peers by overlay IPv4 for the document version peersVer.
	peersVer uint64
	peersOf  string
	peers    map[netip.Addr]trust.Device
}

type tokenBucket struct {
	tokens float64
	at     time.Time
}

func (b *tokenBucket) take(rate, burst float64, now time.Time) bool {
	if b.at.IsZero() {
		b.tokens, b.at = burst, now
	}
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(burst, b.tokens+d.Seconds()*rate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (g *gossipState) init() {
	g.once.Do(func() {
		g.wake = make(chan struct{}, 1)
		g.pulls = make(chan gossipPull, 8)
		g.buckets = map[netip.Addr]*tokenBucket{}
		g.failUntil = map[string]time.Time{}
	})
}

// gossipSoon asks for a round now (rate-limited), used when no
// coordinator answered.
func (e *Engine) gossipSoon() {
	e.p15.gossip.init()
	select {
	case e.p15.gossip.wake <- struct{}{}:
	default:
	}
}

// runGossip runs gossip rounds until ctx ends.
func (e *Engine) runGossip(ctx context.Context) {
	g := &e.p15.gossip
	g.init()
	next := func() time.Duration {
		return time.Duration(float64(gossipInterval) * (0.75 + 0.5*e.rand()))
	}
	timer := time.NewTimer(next())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.gossipRound(ctx)
			timer.Reset(next())
		case <-g.wake:
			g.mu.Lock()
			due := e.cfg.Now().Sub(g.lastRound) >= gossipSoonMin
			g.mu.Unlock()
			if due {
				e.gossipRound(ctx)
			}
		case p := <-g.pulls:
			e.gossipPullFrom(ctx, p.peer, p.hello)
		}
	}
}

// gossipRound compares document versions with a few connected peers.
func (e *Engine) gossipRound(ctx context.Context) {
	g := &e.p15.gossip
	now := e.cfg.Now()
	g.mu.Lock()
	g.lastRound = now
	g.mu.Unlock()
	doc, env, digest := e.cfg.Store.Snapshot()
	self, err := e.selfIn(doc)
	if err != nil {
		return
	}
	st, err := e.wgStatus()
	if err != nil {
		return
	}
	var cands []trust.Device
	for _, p := range doc.TunnelPeersOf(self.Name) {
		if e.gossipCandidate(p, st, now) {
			cands = append(cands, p)
		}
	}
	// Random choice so that every peer is reached over a few rounds.
	for i := len(cands) - 1; i > 0; i-- {
		j := int(e.rand() * float64(i+1))
		if j > i {
			j = i
		}
		cands[i], cands[j] = cands[j], cands[i]
	}
	if len(cands) > gossipPeers {
		cands = cands[:gossipPeers]
	}
	views := e.ownCoordViews()
	hello := control.Message{T: control.TypeGossipHello, Version: doc.Version, Digest: hexDigest32(digest), Size: len(env), Data: views}
	for _, p := range cands {
		if ctx.Err() != nil {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, gossipCallTimeout)
		resp, err := e.client.callTo(cctx, p.IPv4, control.GossipPort, hello)
		cancel()
		if err != nil || resp.T != control.TypeGossipHello {
			if err != nil {
				e.logger.Debug("gossip hello", "peer", p.Name, "error", err.Error())
			}
			continue
		}
		e.notePeerView(p, resp)
		if resp.Version > doc.Version {
			e.gossipPullFrom(ctx, p, resp)
		}
	}
	e.logIntegrity()
}

// gossipCandidate reports whether a round may ask peer p: connected,
// unexpired, and not refused by quarantine or lost mode (exitdns_g3.go).
func (e *Engine) gossipCandidate(p trust.Device, st wgconf.Status, now time.Time) bool {
	ps, ok := st.Peers[p.WireGuardKey]
	return ok && now.Before(p.ExpiresAt) && ps.LastHandshakeUnix > 0 && now.Sub(time.Unix(ps.LastHandshakeUnix, 0)) <= gossipFresh &&
		!e.exitDNSRefused(p.Name)
}

// gossipPullFrom downloads a newer document from a peer and hands it to
// the sync loop.
func (e *Engine) gossipPullFrom(ctx context.Context, p trust.Device, hello control.Message) {
	g := &e.p15.gossip
	now := e.cfg.Now()
	g.mu.Lock()
	blocked := now.Before(g.failUntil[p.ID]) || g.pending != nil
	g.mu.Unlock()
	if blocked || hello.Version <= e.cfg.Store.Document().Version {
		return
	}
	call := func(m control.Message) (control.Message, error) {
		cctx, cancel := context.WithTimeout(ctx, gossipCallTimeout)
		defer cancel()
		return e.client.callTo(cctx, p.IPv4, control.GossipPort, m)
	}
	buf, err := fetchFrom(call, control.TypeGossipDoc, hello)
	if err != nil {
		e.gossipFailed(p.ID)
		e.logger.Debug("document from peer", "peer", p.Name, "error", err.Error())
		return
	}
	g.mu.Lock()
	g.pending = &gossipPending{data: buf, from: p.ID}
	g.mu.Unlock()
	select {
	case e.syncWake <- struct{}{}:
	default:
	}
}

func (e *Engine) gossipFailed(id string) {
	g := &e.p15.gossip
	g.mu.Lock()
	g.failUntil[id] = e.cfg.Now().Add(gossipPullBackoff)
	g.mu.Unlock()
}

// adoptGossip verifies and applies a document pulled from a peer. It runs
// in the sync loop, like adoptLocal.
func (e *Engine) adoptGossip(ctx context.Context) {
	g := &e.p15.gossip
	g.init()
	g.mu.Lock()
	p := g.pending
	g.pending = nil
	g.mu.Unlock()
	if p == nil {
		return
	}
	data, err := e.sanitizeDocument(ctx, p.data) // ADR-0233: parsed in the helper first
	if err != nil {
		e.gossipFailed(p.from)
		e.logger.Warn("gossiped document rejected", "error", err.Error())
		return
	}
	changed, err := e.cfg.Store.Accept(data, e.cfg.Now())
	if err != nil {
		e.gossipFailed(p.from)
		if errors.Is(err, trust.ErrEquivocation) {
			e.noteEquivocation(p.from)
		}
		if !errors.Is(err, trust.ErrRollback) {
			e.logger.Warn("document from a peer rejected", "error", err.Error())
		}
		return
	}
	if changed {
		e.logger.Info("new network document from a peer", "version", e.cfg.Store.Document().Version)
		if err := e.applyDoc(ctx, e.cfg.Store.Document()); err != nil {
			e.logger.Warn("apply document", "error", err.Error())
		}
	}
}

// gossipPeer returns the unexpired tunnel peer with overlay address a.
func (e *Engine) gossipPeer(a netip.Addr) (trust.Device, bool) {
	doc := e.cfg.Store.Document()
	e.mu.Lock()
	selfName := e.self.Name
	e.mu.Unlock()
	g := &e.p15.gossip
	g.mu.Lock()
	if g.peers == nil || g.peersVer != doc.Version || g.peersOf != selfName {
		g.peers = map[netip.Addr]trust.Device{}
		for _, p := range doc.TunnelPeersOf(selfName) {
			g.peers[p.IPv4] = p
		}
		g.peersVer, g.peersOf = doc.Version, selfName
	}
	p, ok := g.peers[a]
	g.mu.Unlock()
	return p, ok && e.cfg.Now().Before(p.ExpiresAt)
}

// serveGossip answers a peer's gossip request on GossipPort. WireGuard has
// authenticated the source address; only tunnel peers are answered, within
// rate limits, and only with this device's own signed document.
func (e *Engine) serveGossip(pkt []byte) bool {
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoUDP || in.Fragment || in.DstPort != control.GossipPort {
		return false
	}
	e.mu.Lock()
	self := e.self.IPv4
	e.mu.Unlock()
	if !self.IsValid() || in.Dst != self {
		return false
	}
	peer, ok := e.gossipPeer(in.Src)
	if !ok || e.exitDNSRefused(peer.Name) { // quarantine and lost mode, exitdns_g3.go
		return true
	}
	g := &e.p15.gossip
	g.init()
	now := e.cfg.Now()
	g.mu.Lock()
	b := g.buckets[in.Src]
	if b == nil {
		if len(g.buckets) > trust.MaxDevices {
			g.buckets = map[netip.Addr]*tokenBucket{}
		}
		b = &tokenBucket{}
		g.buckets[in.Src] = b
	}
	allowed := g.total.take(gossipTotalRate, gossipTotalBurst, now) && b.take(gossipPeerRate, gossipPeerBurst, now)
	g.mu.Unlock()
	if !allowed {
		return true
	}
	req, err := control.Decode(in.Payload)
	if err != nil {
		return true
	}
	doc, env, digest := e.cfg.Store.Snapshot()
	var resp control.Message
	switch req.T {
	case control.TypeGossipHello:
		e.notePeerView(peer, req)
		resp = control.Message{T: control.TypeGossipHello, Version: doc.Version, Digest: hexDigest32(digest), Size: len(env), Data: e.ownCoordViews()}
		if req.Version > doc.Version && req.Size > 0 && req.Size <= trust.MaxEnvelopeSize {
			select {
			case g.pulls <- gossipPull{peer: peer, hello: req}:
			default:
			}
		}
	case control.TypeGossipDoc:
		switch {
		case req.Version != doc.Version:
			resp = control.Message{T: control.TypeError, Error: "version changed"}
		case req.Offset > len(env):
			resp = control.Message{T: control.TypeError, Error: "offset out of range"}
		default:
			end := min(req.Offset+control.ChunkSize, len(env))
			resp = control.Message{T: control.TypeGossipDoc, Version: doc.Version, Offset: req.Offset, Total: len(env), Data: env[req.Offset:end]}
		}
	default:
		resp = control.Message{T: control.TypeError, Error: "unknown message type"}
	}
	resp.ID = req.ID
	out, err := control.Encode(resp)
	if err != nil {
		return true
	}
	reply, err := packet.BuildUDP4(self, in.Src, control.GossipPort, in.SrcPort, out)
	if err == nil {
		e.wrap.Inject(reply)
	}
	return true
}
