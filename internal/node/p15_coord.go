package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
	"github.com/openscale/openscale/internal/wgconf"
)

// Several coordinators on the device side (ADR-0111; #153, #152, #57,
// #151). Every usable coordinator in the document is a WireGuard peer with
// a persistent keepalive. Control requests go to one "active" coordinator;
// when it stops answering the device moves to the next one in the same
// sync round. The others are kept in step in the background ("fan-out"):
// they get newer documents, the device's candidates, a push subscription
// and a relay session. Relayed packets go through the coordinator with the
// lowest measured latency. With a single coordinator nothing here changes
// the protocol or the behaviour.

const (
	// fanOutEvery is how often the other coordinators are kept in step.
	fanOutEvery = 20 * time.Second
	// fanOutCallTimeout bounds one request to another coordinator.
	fanOutCallTimeout = 3 * time.Second
	// fanOutBackoffMax caps the wait after a coordinator failed to answer.
	fanOutBackoffMax = 10 * time.Minute
	// coordHealthy is how recent a reply must be for relay selection.
	coordHealthy = 2 * time.Minute
	// Relay selection hysteresis (ADR-0025 F-008 design): a coordinator
	// replaces the current relay only when it is faster by 30 % and 20 ms
	// for a whole minute.
	relaySwitchRatio = 0.3
	relaySwitchMin   = 20 * time.Millisecond
	relaySwitchAfter = time.Minute
	// rttWeight is the weight of a new sample in the latency average.
	rttWeight = 0.3
	// sessionRenew renews relay sessions this long before they end.
	sessionRenew = control.RelaySessionMaxLife / 2
)

// fanOutInterval is fanOutEvery; tests shorten it.
var fanOutInterval = fanOutEvery

// coordRuntime is the device's live view of one coordinator.
type coordRuntime struct {
	c          trust.Coordinator
	ep         netip.AddrPort
	unresolved bool
	rtt        time.Duration
	okAt       time.Time
	failures   int
	retryAt    time.Time
	features   map[string]bool
	capsAt     time.Time
	capsOld    bool
	sessionEnd time.Time
	candKey    string
	candAt     time.Time
}

// multiCoord is guarded by its own mutex.
type multiCoord struct {
	mu          sync.Mutex
	list        []*coordRuntime // usable coordinators, primary first
	active      trust.Key
	relay       trust.Key
	betterKey   trust.Key
	betterSince time.Time
	fanAt       time.Time
	// relaySince is when the relay coordinator was chosen; relayBad holds
	// coordinators excluded from relaying after relayed peers went silent
	// through them.
	relaySince time.Time
	relayBad   map[trust.Key]time.Time
}

// p15Node holds the device-side P15 state (ADR-0111).
type p15Node struct {
	mc     multiCoord
	gossip gossipState
	integ  integrityState
}

// coordinatorPeers refreshes the coordinator list from doc, resolves the
// additional coordinators and adds them to want. It returns their keys.
func (e *Engine) coordinatorPeers(ctx context.Context, doc *trust.Document, want map[trust.Key]wgconf.Peer) []trust.Key {
	now := e.cfg.Now()
	usable := doc.UsableCoordinators(now)
	// Known endpoints, read under the lock; names are resolved outside it.
	e.p15.mc.mu.Lock()
	known := map[trust.Key]netip.AddrPort{}
	for _, rt := range e.p15.mc.list {
		if rt.ep.IsValid() {
			known[rt.c.WireGuardKey] = rt.ep
		}
	}
	endpoints := map[trust.Key]string{}
	for _, rt := range e.p15.mc.list {
		endpoints[rt.c.WireGuardKey] = rt.c.Endpoint
	}
	e.p15.mc.mu.Unlock()
	resolved := map[trust.Key]netip.AddrPort{}
	var extras []trust.Key
	var addrs, extraIPs []netip.Addr
	for i, c := range usable {
		addrs = append(addrs, c.IPv4)
		if i == 0 {
			continue // the primary is configured by apply itself
		}
		ep, ok := known[c.WireGuardKey]
		if !ok || endpoints[c.WireGuardKey] != c.Endpoint {
			var err error
			if ep, err = e.resolveEndpoint(ctx, c.Endpoint); err != nil {
				ep = netip.AddrPort{}
				e.logger.Warn("additional coordinator endpoint not resolved", "coordinator", c.CoordinatorLabel(), "error", err.Error())
			}
		}
		resolved[c.WireGuardKey] = ep
		if ep.IsValid() {
			e.spa.setCoordinator(c.WireGuardKey, doc.NetworkID, ep.Addr()) // #614
			extraIPs = append(extraIPs, ep.Addr())
		}
		extras = append(extras, c.WireGuardKey)
		want[c.WireGuardKey] = wgconf.Peer{
			PublicKey:  c.WireGuardKey,
			AllowedIPs: wgconf.HostPrefixes(c.IPv4, c.IPv6),
			Endpoint:   ep,
			Keepalive:  e.keepaliveFor(c.WireGuardKey),
		}
	}
	e.p15.mc.mu.Lock()
	old := map[trust.Key]*coordRuntime{}
	for _, rt := range e.p15.mc.list {
		old[rt.c.WireGuardKey] = rt
	}
	list := make([]*coordRuntime, 0, len(usable))
	for i, c := range usable {
		rt := old[c.WireGuardKey]
		if rt == nil {
			rt = &coordRuntime{}
		}
		rt.c = c
		if i > 0 {
			rt.ep = resolved[c.WireGuardKey]
			rt.unresolved = !rt.ep.IsValid()
		}
		list = append(list, rt)
	}
	e.p15.mc.list = list
	if !e.p15.mc.hasLocked(e.p15.mc.active) && len(list) > 0 {
		e.p15.mc.active = list[0].c.WireGuardKey
	}
	if !e.p15.mc.hasLocked(e.p15.mc.relay) {
		e.p15.mc.relay = trust.Key{}
	}
	var activeAddr netip.Addr
	if rt := e.p15.mc.findLocked(e.p15.mc.active); rt != nil {
		activeAddr = rt.c.IPv4
	}
	e.p15.mc.mu.Unlock()
	e.client.setCoordinators(addrs)
	if activeAddr.IsValid() {
		e.client.mu.Lock()
		e.client.coord = activeAddr
		e.client.mu.Unlock()
	}
	if e.relay != nil {
		e.relay.setExtraCoordinators(extraIPs)
	}
	return extras
}

func (m *multiCoord) hasLocked(k trust.Key) bool {
	return m.findLocked(k) != nil
}

func (m *multiCoord) findLocked(k trust.Key) *coordRuntime {
	if k.IsZero() {
		return nil
	}
	for _, rt := range m.list {
		if rt.c.WireGuardKey == k {
			return rt
		}
	}
	return nil
}

// activeCoordinatorIPv4 is the control address of the active coordinator.
func (e *Engine) activeCoordinatorIPv4(doc *trust.Document) netip.Addr {
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	if rt := e.p15.mc.findLocked(e.p15.mc.active); rt != nil {
		return rt.c.IPv4
	}
	return doc.Coordinator.IPv4
}

// coordinatorCount is the number of usable coordinators.
func (e *Engine) coordinatorCount() int {
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	return len(e.p15.mc.list)
}

// helloAny sends hello to the active coordinator and, when it does not
// answer, to the others in document order (#153). The first one that
// answers becomes active; its features are asked for again.
func (e *Engine) helloAny(ctx context.Context, m control.Message) (control.Message, error) {
	start := e.cfg.Now()
	resp, err := e.helloWithVersion(ctx, m)
	active := e.activeKey()
	if err == nil {
		e.noteReply(active, resp, e.cfg.Now().Sub(start))
		return resp, nil
	}
	if ctx.Err() != nil || e.coordinatorCount() < 2 {
		e.noteFailure(active)
		e.gossipSoon()
		return resp, err
	}
	e.noteFailure(active)
	firstErr := err
	for _, rt := range e.otherCoordinators(active) {
		e.setActive(rt.c)
		start = e.cfg.Now()
		r, err := e.helloWithVersion(ctx, m)
		if err == nil {
			e.logger.Info("switched to another coordinator", "coordinator", rt.c.CoordinatorLabel())
			e.noteReply(rt.c.WireGuardKey, r, e.cfg.Now().Sub(start))
			return r, nil
		}
		e.noteFailure(rt.c.WireGuardKey)
		if ctx.Err() != nil {
			break
		}
	}
	// Nobody answered: go back to the coordinator we started with.
	e.p15.mc.mu.Lock()
	rt := e.p15.mc.findLocked(active)
	e.p15.mc.mu.Unlock()
	if rt != nil {
		e.setActive(rt.c)
	}
	e.gossipSoon()
	return resp, firstErr
}

func (e *Engine) activeKey() trust.Key {
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	return e.p15.mc.active
}

// otherCoordinators are the usable coordinators except k, in order.
func (e *Engine) otherCoordinators(k trust.Key) []*coordRuntime {
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	out := make([]*coordRuntime, 0, len(e.p15.mc.list))
	for _, rt := range e.p15.mc.list {
		if rt.c.WireGuardKey != k {
			out = append(out, rt)
		}
	}
	return out
}

// setActive points control requests at c and forgets the features of the
// previous coordinator, so caps is asked again.
func (e *Engine) setActive(c trust.Coordinator) {
	e.p15.mc.mu.Lock()
	changed := e.p15.mc.active != c.WireGuardKey
	e.p15.mc.active = c.WireGuardKey
	e.p15.mc.mu.Unlock()
	e.client.mu.Lock()
	e.client.coord = c.IPv4
	e.client.mu.Unlock()
	if changed {
		e.mu.Lock()
		e.caps = coordCaps{}
		e.mu.Unlock()
	}
}

// noteReply records a successful hello: latency, health and the document
// the coordinator announced (#154).
func (e *Engine) noteReply(k trust.Key, hello control.Message, rtt time.Duration) {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	if rt := e.p15.mc.findLocked(k); rt != nil {
		if rt.rtt == 0 {
			rt.rtt = rtt
		} else {
			rt.rtt = time.Duration(float64(rt.rtt)*(1-rttWeight) + float64(rtt)*rttWeight)
		}
		rt.okAt, rt.failures, rt.retryAt = now, 0, time.Time{}
	}
	e.chooseRelayLocked(now)
	e.p15.mc.mu.Unlock()
	e.noteCoordinatorView(k, hello.Version, hello.Digest, now)
}

func (e *Engine) noteFailure(k trust.Key) {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	if rt := e.p15.mc.findLocked(k); rt != nil {
		rt.failures++
		rt.retryAt = now.Add(backoffDelay(fanOutInterval, fanOutBackoffMax, rt.failures-1, 0.1, e.rand()))
	}
	e.chooseRelayLocked(now)
}

// chooseRelayLocked picks the relay coordinator (#57): the healthy one with
// the lowest latency, with hysteresis against flapping.
func (e *Engine) chooseRelayLocked(now time.Time) {
	m := &e.p15.mc
	var best *coordRuntime
	for _, rt := range m.list {
		if rt.rtt <= 0 || now.Sub(rt.okAt) > coordHealthy || now.Before(m.relayBad[rt.c.WireGuardKey]) {
			continue
		}
		if best == nil || rt.rtt < best.rtt {
			best = rt
		}
	}
	cur := m.findLocked(m.relay)
	switch {
	case best == nil:
		m.relay, m.betterKey = trust.Key{}, trust.Key{}
	case cur == nil || now.Sub(cur.okAt) > coordHealthy || now.Before(m.relayBad[cur.c.WireGuardKey]):
		m.relay, m.betterKey, m.relaySince = best.c.WireGuardKey, trust.Key{}, now
	case best == cur:
		m.betterKey = trust.Key{}
	default:
		gain := cur.rtt - best.rtt
		if gain < relaySwitchMin || float64(gain) < relaySwitchRatio*float64(cur.rtt) {
			m.betterKey = trust.Key{}
			return
		}
		if m.betterKey != best.c.WireGuardKey {
			m.betterKey, m.betterSince = best.c.WireGuardKey, now
			return
		}
		if now.Sub(m.betterSince) >= relaySwitchAfter {
			m.relay, m.betterKey, m.relaySince = best.c.WireGuardKey, trust.Key{}, now
			e.logger.Info("relay moved to a faster coordinator", "coordinator", best.c.CoordinatorLabel())
		}
	}
}

// relayCoordinatorIPv4 is where relayed packets go: the chosen relay
// coordinator, or the active one.
func (e *Engine) relayCoordinatorIPv4(active netip.Addr) netip.Addr {
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	if rt := e.p15.mc.findLocked(e.p15.mc.relay); rt != nil {
		return rt.c.IPv4
	}
	return active
}

// afterCaps runs after refreshCaps in every sync: it keeps the active
// coordinator's relay session and, when due, the other coordinators in
// step.
func (e *Engine) afterCaps(ctx context.Context) {
	active := e.activeKey()
	e.mu.Lock()
	features := e.caps.features
	e.mu.Unlock()
	e.p15.mc.mu.Lock()
	rt := e.p15.mc.findLocked(active)
	var addr netip.Addr
	if rt != nil {
		rt.features, addr = features, rt.c.IPv4
	}
	e.p15.mc.mu.Unlock()
	if rt != nil {
		e.ensureSession(ctx, rt, addr)
	}
	e.checkRelayHealth()
	e.fanOut(ctx)
}

// ensureSession opens or renews the device-signed relay session (#151) at
// a coordinator that supports sessions.
func (e *Engine) ensureSession(ctx context.Context, rt *coordRuntime, addr netip.Addr) {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	due := rt.features[control.FeatureRelaySession] && rt.sessionEnd.Sub(now) < sessionRenew
	key := rt.c.WireGuardKey
	e.p15.mc.mu.Unlock()
	if !due {
		return
	}
	self, err := e.Self()
	if err != nil {
		return
	}
	raw, err := hex.DecodeString(self.ID)
	if err != nil || len(raw) != control.RelayIDLen {
		return
	}
	end := now.Add(control.RelaySessionMaxLife).Truncate(time.Second)
	sess := control.RelaySession{Coordinator: [32]byte(key), Expires: end}
	copy(sess.Device[:], raw)
	payload, sig, err := control.SignRelaySession(e.cfg.Secrets.SigningKey(), sess)
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, fanOutCallTimeout*2)
	defer cancel()
	resp, err := e.client.callTo(cctx, addr, control.Port, control.Message{T: control.TypeRelaySession, Data: payload, Sig: sig})
	if err != nil || resp.T != control.TypeRelaySession || !resp.Complete {
		if err != nil {
			e.logger.Debug("relay session", "coordinator", rt.c.CoordinatorLabel(), "error", err.Error())
		}
		return
	}
	e.p15.mc.mu.Lock()
	rt.sessionEnd = end
	e.p15.mc.mu.Unlock()
}

// fanOut keeps the coordinators other than the active one in step: newer
// documents both ways, candidates, push subscription and relay session.
// Unreachable coordinators are skipped with a growing backoff.
func (e *Engine) fanOut(ctx context.Context) {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	if len(e.p15.mc.list) < 2 || now.Sub(e.p15.mc.fanAt) < fanOutInterval {
		e.p15.mc.mu.Unlock()
		return
	}
	e.p15.mc.fanAt = now
	e.p15.mc.mu.Unlock()
	for _, rt := range e.otherCoordinators(e.activeKey()) {
		if ctx.Err() != nil {
			return
		}
		e.p15.mc.mu.Lock()
		skip := now.Before(rt.retryAt)
		addr, key, unresolved, endpoint := rt.c.IPv4, rt.c.WireGuardKey, rt.unresolved, rt.c.Endpoint
		e.p15.mc.mu.Unlock()
		if skip {
			continue
		}
		if unresolved {
			e.resolveExtra(ctx, rt, key, endpoint)
		}
		if err := e.syncCoordinator(ctx, rt, addr); err != nil {
			e.noteFailure(key)
			e.logger.Debug("additional coordinator", "coordinator", rt.c.CoordinatorLabel(), "error", err.Error())
		}
	}
}

// resolveExtra resolves an additional coordinator's name again and points
// its WireGuard peer at the result.
func (e *Engine) resolveExtra(ctx context.Context, rt *coordRuntime, key trust.Key, endpoint string) {
	ep, err := e.resolveEndpoint(ctx, endpoint)
	if err != nil {
		return
	}
	e.p15.mc.mu.Lock()
	rt.ep, rt.unresolved = ep, false
	var ips []netip.Addr
	for _, r := range e.p15.mc.list[1:] {
		if r.ep.IsValid() {
			ips = append(ips, r.ep.Addr())
		}
	}
	e.p15.mc.mu.Unlock()
	if e.relay != nil {
		e.relay.setExtraCoordinators(ips)
	}
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev != nil {
		if err := dev.IpcSet(wgconf.SetEndpoint(key, ep)); err != nil {
			e.logger.Debug("additional coordinator endpoint", "error", err.Error())
		}
	}
}

// syncCoordinator does one fan-out exchange with an additional coordinator.
func (e *Engine) syncCoordinator(ctx context.Context, rt *coordRuntime, addr netip.Addr) error {
	call := func(m control.Message) (control.Message, error) {
		cctx, cancel := context.WithTimeout(ctx, fanOutCallTimeout)
		defer cancel()
		return e.client.callTo(cctx, addr, control.Port, m)
	}
	doc, env, digest := e.cfg.Store.Snapshot()
	start := e.cfg.Now()
	hello, err := call(control.Message{T: control.TypeHello, Version: doc.Version, Digest: hex.EncodeToString(digest[:])})
	if err != nil && strings.Contains(err.Error(), control.ErrVersionNotReported) {
		v := version.String()
		if len(v) > control.MaxClientVersionLen {
			v = v[:control.MaxClientVersionLen]
		}
		if _, verr := call(control.Message{T: control.TypeClientVersion, Data: []byte(v)}); verr == nil {
			start = e.cfg.Now()
			hello, err = call(control.Message{T: control.TypeHello, Version: doc.Version, Digest: hex.EncodeToString(digest[:])})
		}
	}
	if err != nil {
		return err
	}
	if hello.T != control.TypeHello {
		return errors.New("unexpected hello reply")
	}
	e.noteReply(rt.c.WireGuardKey, hello, e.cfg.Now().Sub(start))
	switch {
	case hello.Version < doc.Version:
		if err := uploadTo(call, env, digest); err != nil {
			return err
		}
		e.logger.Info("published network document to an additional coordinator", "coordinator", rt.c.CoordinatorLabel(), "version", doc.Version)
	case hello.Version > doc.Version:
		buf, err := fetchFrom(call, control.TypeDoc, hello)
		if err != nil {
			return err
		}
		if buf, err = e.sanitizeDocument(ctx, buf); err != nil { // ADR-0233
			return err
		}
		changed, err := e.cfg.Store.Accept(buf, e.cfg.Now())
		if err != nil {
			return err
		}
		if changed {
			e.logger.Info("new network document from an additional coordinator", "version", e.cfg.Store.Document().Version)
			if err := e.applyDoc(ctx, e.cfg.Store.Document()); err != nil {
				return err
			}
		}
	}
	e.coordCaps(rt, call)
	e.coordCandidates(rt, call)
	e.ensureSession(ctx, rt, addr)
	return nil
}

// coordCaps asks an additional coordinator for its features, which also
// subscribes this device to its pushes (notices, calls).
func (e *Engine) coordCaps(rt *coordRuntime, call func(control.Message) (control.Message, error)) {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	due := rt.capsAt.IsZero() || (rt.capsOld && now.Sub(rt.capsAt) >= oldCoordinatorRecheck) || (!rt.capsOld && now.Sub(rt.capsAt) >= capsRefresh)
	e.p15.mc.mu.Unlock()
	if !due {
		return
	}
	resp, err := call(control.Message{T: control.TypeCaps})
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	switch {
	case err == nil && resp.T == control.TypeCaps:
		f := map[string]bool{}
		for _, x := range resp.Features {
			f[x] = true
		}
		rt.features, rt.capsAt, rt.capsOld = f, now, false
	case err != nil && err.Error() == errUnknownType:
		rt.features, rt.capsAt, rt.capsOld = nil, now, true
	}
}

// coordCandidates reports the candidates last sent to the active
// coordinator, so peers that use this coordinator can probe us too.
func (e *Engine) coordCandidates(rt *coordRuntime, call func(control.Message) (control.Message, error)) {
	if e.cfg.ForceRelay {
		return
	}
	e.mu.Lock()
	key, cands := e.candKey, e.plainCands // ADR-0230: never the sealed-only ones
	e.mu.Unlock()
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	due := rt.features[control.FeatureCandidates] && key != "" && (key != rt.candKey || now.Sub(rt.candAt) >= candidateRefresh)
	e.p15.mc.mu.Unlock()
	if !due {
		return
	}
	strs := make([]string, len(cands))
	for i, c := range cands {
		strs[i] = c.String()
	}
	if resp, err := call(control.Message{T: control.TypeCandidates, Cands: strs}); err == nil && resp.T == control.TypeCandidates {
		e.p15.mc.mu.Lock()
		rt.candKey, rt.candAt = key, now
		e.p15.mc.mu.Unlock()
	}
}

// uploadTo publishes env with call, like Engine.upload.
func uploadTo(call func(control.Message) (control.Message, error), env []byte, digest [32]byte) error {
	hexDigest := hex.EncodeToString(digest[:])
	for off := 0; off < len(env); {
		end := min(off+control.ChunkSize, len(env))
		resp, err := call(control.Message{T: control.TypePut, Offset: off, Total: len(env), Digest: hexDigest, Data: env[off:end]})
		if err != nil {
			return err
		}
		if resp.Complete {
			return nil
		}
		if resp.Offset != end {
			return errors.New("coordinator acknowledged an unexpected offset")
		}
		off = end
	}
	return nil
}

// fetchFrom downloads the document announced in hello with call, in
// chunks of type typ (TypeDoc or TypeGossipDoc), and checks size and
// digest. The caller verifies the signature.
func fetchFrom(call func(control.Message) (control.Message, error), typ string, hello control.Message) ([]byte, error) {
	if hello.Size <= 0 || hello.Size > trust.MaxEnvelopeSize || hello.Version == 0 {
		return nil, errors.New("invalid announced document size")
	}
	buf := make([]byte, 0, hello.Size)
	for len(buf) < hello.Size {
		resp, err := call(control.Message{T: typ, Version: hello.Version, Offset: len(buf)})
		if err != nil {
			return nil, err
		}
		if resp.T != typ || resp.Version != hello.Version || resp.Offset != len(buf) || resp.Total != hello.Size || len(resp.Data) == 0 || len(buf)+len(resp.Data) > hello.Size {
			return nil, errors.New("unexpected document chunk")
		}
		buf = append(buf, resp.Data...)
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != hello.Digest {
		return nil, errors.New("document digest mismatch")
	}
	return buf, nil
}

// CoordinatorStatus is one coordinator as this device sees it.
type CoordinatorStatus struct {
	Name        string        `json:"name,omitempty"`
	Region      string        `json:"region,omitempty"`
	Fingerprint string        `json:"fingerprint"`
	Endpoint    string        `json:"endpoint"`
	Primary     bool          `json:"primary"`
	Active      bool          `json:"active"`
	Relay       bool          `json:"relay"`
	Until       time.Time     `json:"until,omitzero"`
	RTT         time.Duration `json:"rtt"`
	LastReply   time.Time     `json:"last_reply,omitzero"`
	Failures    int           `json:"failures"`
	Session     bool          `json:"relay_session"`
}

// Coordinators returns the usable coordinators: which one is active, which
// one relays, their latency and health (#153, #57).
func (e *Engine) Coordinators() []CoordinatorStatus {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	relay := e.p15.mc.relay
	if e.p15.mc.findLocked(relay) == nil {
		relay = e.p15.mc.active
	}
	out := make([]CoordinatorStatus, 0, len(e.p15.mc.list))
	for i, rt := range e.p15.mc.list {
		out = append(out, CoordinatorStatus{
			Name: rt.c.Name, Region: rt.c.Region, Fingerprint: trust.CoordinatorFingerprint(rt.c.WireGuardKey),
			Endpoint: rt.c.Endpoint, Primary: i == 0, Active: rt.c.WireGuardKey == e.p15.mc.active,
			Relay: rt.c.WireGuardKey == relay, Until: rt.c.Until, RTT: rt.rtt, LastReply: rt.okAt,
			Failures: rt.failures, Session: now.Before(rt.sessionEnd),
		})
	}
	return out
}

// setCoordinators records the overlay addresses of every usable
// coordinator.
func (c *client) setCoordinators(addrs []netip.Addr) {
	m := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		m[a] = true
	}
	c.mu.Lock()
	c.coords = m
	c.mu.Unlock()
}

// isCoordinator reports whether a is a usable coordinator's address.
func (c *client) isCoordinator(a netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.coords[a]
}

// setExtraCoordinators records the additional coordinators' UDP addresses.
func (b *relayBind) setExtraCoordinators(ips []netip.Addr) {
	out := make([]netip.Addr, len(ips))
	for i, a := range ips {
		out[i] = a.Unmap()
	}
	b.extraIPs.Store(&out)
}

func (b *relayBind) isExtraCoordinator(ip netip.Addr) bool {
	p := b.extraIPs.Load()
	if p == nil {
		return false
	}
	ip = ip.Unmap()
	for _, a := range *p {
		if a == ip {
			return true
		}
	}
	return false
}

// relayBadFor is how long a coordinator stays excluded from relaying after
// relayed peers went silent through it.
const relayBadFor = 10 * time.Minute

// checkRelayHealth guards against a relay coordinator that this device
// reaches but its peers do not: when it relays for longer than twice
// RelayAfter and every relayed peer's handshake is stale, it is excluded
// for relayBadFor and relaying falls back to the active coordinator.
func (e *Engine) checkRelayHealth() {
	now := e.cfg.Now()
	e.p15.mc.mu.Lock()
	relay, active, since := e.p15.mc.relay, e.p15.mc.active, e.p15.mc.relaySince
	e.p15.mc.mu.Unlock()
	if relay.IsZero() || relay == active || now.Sub(since) < max(2*e.cfg.RelayAfter, time.Minute) {
		return
	}
	st, err := e.wgStatus()
	if err != nil {
		return
	}
	good, bad := 0, 0
	for key, p := range st.Peers {
		if !p.Relayed || e.isCoordinatorKey(key) {
			continue
		}
		if p.LastHandshakeUnix > 0 && now.Sub(time.Unix(p.LastHandshakeUnix, 0)) <= staleHandshake {
			good++
		} else {
			bad++
		}
	}
	if bad == 0 || good > 0 {
		return
	}
	e.p15.mc.mu.Lock()
	if e.p15.mc.relayBad == nil {
		e.p15.mc.relayBad = map[trust.Key]time.Time{}
	}
	e.p15.mc.relayBad[relay] = now.Add(relayBadFor)
	label := ""
	if rt := e.p15.mc.findLocked(relay); rt != nil {
		label = rt.c.CoordinatorLabel()
	}
	e.p15.mc.relay = trust.Key{}
	e.chooseRelayLocked(now)
	e.p15.mc.mu.Unlock()
	e.logger.Info("relayed peers silent through this coordinator; relaying through another one", "coordinator", label)
}

func (e *Engine) isCoordinatorKey(k trust.Key) bool {
	e.p15.mc.mu.Lock()
	defer e.p15.mc.mu.Unlock()
	return e.p15.mc.findLocked(k) != nil
}
