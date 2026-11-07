// Package coordinator implements the untrusted rendezvous server
// (ADR-0005, ADR-0013). It stores the latest root-signed document, tells
// devices their observed endpoints and those of the peers their rules let
// them see, and never forwards traffic between devices.
package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/rollout"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

const (
	statusCacheTTL     = time.Second
	reconcileInterval  = time.Minute
	versionWatch       = time.Second
	uploadIdleTimeout  = 2 * time.Minute
	defaultListenPort  = 51820
	maxConcurrentLoads = 64
)

// Config configures a coordinator.
type Config struct {
	Store      *member.Store
	Secrets    *trust.DeviceSecrets
	ListenPort int
	// Bind overrides the UDP transport (tests); nil uses the default.
	Bind   conn.Bind
	Logger *slog.Logger
	Now    func() time.Time
	// Handoff lets a coordinator that is no longer pinned in the document
	// keep serving it, so devices that still talk to it learn about the new
	// coordinator. It never gains any authority: documents stay root-signed.
	Handoff bool
	// RelayRate is how many bytes per second each device may send through
	// the relay (ADR-0017, F-026); zero uses DefaultRelayRate. Allowed:
	// MinRelayRate to MaxRelayRate.
	RelayRate int64
	// RelayBurst is the token bucket size in bytes; zero uses
	// DefaultRelayBurst. Allowed: control.RelayMaxPayload to MaxRelayBurst.
	RelayBurst int64
	// TCPListen, when set, also accepts devices over TCP at this address
	// (ADR-0032), for networks that block UDP; e.g. ":443". Off by default.
	TCPListen string
	// TCPMaxConns bounds the TCP connections (zero: DefaultTCPMaxConns);
	// TCPMaxConnsPerIP bounds them per remote address (zero:
	// DefaultTCPMaxConnsPerIP).
	TCPMaxConns      int
	TCPMaxConnsPerIP int
	// P15 limits (ADR-0111, p15.go); zero uses the defaults. ControlRate
	// and ControlBurst bound control requests per device (requests per
	// second, bucket size), ControlTotalRate all of them together.
	// RelayMaxPeers bounds the distinct peers one device relays to per
	// minute; RelayTotalRate (bytes per second) bounds all relayed traffic
	// (zero: no total limit). RelayRequireSessions relays only for devices
	// with a device-signed session (#151); without it, devices that opened
	// one are held to it and old devices relay as before.
	ControlRate          int
	ControlBurst         int
	ControlTotalRate     int
	RelayMaxPeers        int
	RelayTotalRate       int64
	RelayRequireSessions bool
	// RelayAdmission, when set, enforces the owner's local admission file
	// (RelayAdmissionFile in the state directory, admission.go, F-096): a
	// pair is relayed only when the document and the file allow it. A
	// missing or invalid file stops New; later read errors relay nothing.
	RelayAdmission string
	// Sandbox restricts the process's file access to its state directory
	// with Landlock once WireGuard is up (Linux; #147, sandbox_linux.go).
	// Elsewhere, or when the kernel lacks Landlock, it is skipped and logged.
	Sandbox bool
	// Operations turns on the state-directory operations (ops.go, P09,
	// ADR-0153): monthly relay usage per device, the reach report of the
	// migration preflight and the failover drill. Off in tests by default.
	Operations bool
	// Hardening overrides the state directory's hardening file
	// (g2_hardening.go, ADR-0180..ADR-0184); nil reads the file.
	Hardening *Hardening
	// SealedPolicy tells a blind coordinator that the document's policy is
	// sealed for the members (#629, g2_blind.go); nil: never sealed.
	SealedPolicy SealedPolicyProbe
	// ReleaseMirror is the folder of the owner's published release
	// (release_mirror.go, ADR-0225); empty serves none.
	ReleaseMirror string
	// Rejections receives refused registrations for the audit log (#187,
	// rejaudit.go); nil writes none.
	Rejections RejectionSink
}

// pendingEnrollment is a verified invite enrollment kept in memory until
// the owner approves it or the invite expires. One per invite: a newer
// enrollment for the same invite replaces the older one.
type pendingEnrollment struct {
	inviteID string
	signed   trust.SignedInviteEnrollment
	// deviceID tells the enrollments of a multi-use invite apart (ADR-0028).
	deviceID string
}

type upload struct {
	total   int
	digest  string
	data    []byte
	updated time.Time
}

// Server is a running coordinator.
type Server struct {
	cfg     Config
	wgKey   trust.Key
	dev     *device.Device
	logger  *slog.Logger
	mu      sync.Mutex
	uploads map[netip.Addr]*upload
	pending map[string]pendingEnrollment
	relay   *relayer
	status  wgconf.Status
	statAt  time.Time
	ready   chan struct{}
	// ext holds candidates, push subscriptions and the compressed document
	// (ADR-0025, ADR-0026); tun is the control interface pushes go out on.
	ext *extState
	tun *controlTUN
	// tcp is the TCP transport (nil when off); tcpAddr its listen address.
	tcp     *tcpBind
	tcpAddr net.Addr
	// mem holds leave requests, rejections, reported versions and clone
	// observations (membership.go, ADR-0028).
	mem *memState
	// p15 holds control limits and relay sessions (p15.go, ADR-0111).
	p15 *p15State
	// ops holds relay usage and the failover drill (ops.go, P09).
	ops *opsState
	// g2 holds the hardening options, signed objects, port hiding and the
	// emergency priority (g2_*.go).
	g2 *g2State
	// rel is the release mirror (release_mirror.go, ADR-0225).
	rel *releaseMirror
	// rings is the update ring progress (release_rings.go, ADR-0235).
	rings *rollout.Tracker
	rej   rejectState // #187, rejaudit.go
}

// New validates the configuration. The coordinator's WireGuard key must be
// the one pinned in the document.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Secrets == nil {
		return nil, errors.New("coordinator needs a joined store and its key")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = defaultListenPort
	}
	if err := validRelayLimits(cfg.RelayRate, cfg.RelayBurst); err != nil {
		return nil, err
	}
	if err := validTCPLimits(cfg.TCPMaxConns, cfg.TCPMaxConnsPerIP); err != nil {
		return nil, err
	}
	if cfg.TCPMaxConns == 0 {
		cfg.TCPMaxConns = DefaultTCPMaxConns
	}
	if cfg.TCPMaxConnsPerIP == 0 {
		cfg.TCPMaxConnsPerIP = DefaultTCPMaxConnsPerIP
	}
	_, wg, err := cfg.Secrets.PublicKeys()
	if err != nil {
		return nil, err
	}
	limits, err := validP15Limits(&cfg)
	if err != nil {
		return nil, err
	}
	doc := cfg.Store.Document()
	// Primary or additional coordinator (ADR-0111).
	if err := checkListed(doc, wg, cfg.Handoff, cfg.Now()); err != nil {
		return nil, err
	}
	if doc.Coordinator == nil {
		return nil, errors.New("the network document has no coordinator")
	}
	srv := &Server{cfg: cfg, wgKey: wg, logger: cfg.Logger, uploads: map[netip.Addr]*upload{}, pending: map[string]pendingEnrollment{}, relay: newRelayer(cfg.Store, cfg.Now, cfg.RelayRate, cfg.RelayBurst), ready: make(chan struct{}), ext: newExtState(), mem: newMemState()}
	srv.initP15(limits)
	srv.rel = newReleaseMirror(cfg.ReleaseMirror, cfg.Logger)
	srv.rings = newRingTracker(cfg.ReleaseMirror, cfg.Logger, cfg.Now)
	if err := srv.initG2(); err != nil { // before initOps: no-metadata mode
		return nil, err
	}
	if err := srv.initOps(); err != nil {
		return nil, err
	}
	if cfg.RelayAdmission != "" {
		adm, err := loadRelayAdmission(cfg.RelayAdmission, cfg.Logger, cfg.Now())
		if err != nil {
			return nil, err
		}
		srv.relay.admit = adm.allow
	}
	return srv, nil
}

// PeerStats returns the coordinator's view of every device: the endpoint it
// was last seen from, the last handshake and byte counters.
func (s *Server) PeerStats() (map[trust.Key]wgconf.PeerStatus, error) {
	select {
	case <-s.ready:
	default:
		return nil, errors.New("coordinator is not running")
	}
	st, err := s.wgStatus(false)
	if err != nil {
		return nil, err
	}
	out := make(map[trust.Key]wgconf.PeerStatus, len(st.Peers))
	for k, v := range st.Peers {
		out[k] = v
	}
	return out, nil
}

// RelayStats returns relayed traffic per sending device id.
func (s *Server) RelayStats() map[string]RelayStats { return s.relay.Stats() }

// TCPAddr returns the TCP transport's listen address once Ready is closed,
// or nil when the transport is off.
func (s *Server) TCPAddr() net.Addr {
	select {
	case <-s.ready:
		return s.tcpAddr
	default:
		return nil
	}
}

// Ready is closed once the WireGuard device is up.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	doc := s.cfg.Store.Document()
	t := newControlTUN(s.controlAddr(doc), s.limitedHandle) // ADR-0111
	t.relay = s.relay.forward
	s.tun = t
	bind := s.cfg.Bind
	if bind == nil {
		bind = DefaultBind()
	}
	// The leak test's who-am-I echo (#77) is answered on the UDP port.
	bind = newWhoAmIBind(s.wrapSPA(bind)) // port hiding outermost (#614)
	var ln net.Listener
	if s.cfg.TCPListen != "" {
		var err error
		ln, err = net.Listen("tcp", s.cfg.TCPListen)
		if err != nil {
			return fmt.Errorf("TCP transport: %w", err)
		}
		defer ln.Close()
		s.tcp = newTCPBind(bind, s.logger, s.cfg.TCPMaxConns, s.cfg.TCPMaxConnsPerIP)
		if s.g2.spa != nil {
			s.tcp.knock = s.g2.spa.tcpKnock // #614
		}
		s.tcpAddr = ln.Addr()
		bind = s.tcp
	}
	// A failover drill silences UDP and TCP alike (ops.go, #481).
	bind = s.wrapQuiet(bind)
	s.dev = device.NewDevice(t, bind, wgLogger(s.logger))
	defer s.dev.Close()
	if err := s.dev.IpcSet(wgconf.Interface(s.cfg.Secrets.WireGuardPrivate, s.cfg.ListenPort)); err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	if err := s.reconcile(); err != nil {
		return err
	}
	if err := s.dev.Up(); err != nil {
		return fmt.Errorf("bring wireguard up: %w", err)
	}
	if ln != nil {
		go s.tcp.serve(ctx, ln)
		s.logger.Info("TCP transport listening", "address", s.tcpAddr.String())
	}
	if s.cfg.Sandbox {
		s.applySandbox() // #147
	}
	close(s.ready)
	s.logger.Info("coordinator running", "version", doc.Version, "devices", len(doc.Devices))

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	// The document can also change outside this server (the desktop service
	// feeds it during a coordinator handoff), so version changes are picked
	// up quickly instead of waiting for the next full reconcile.
	watch := time.NewTicker(versionWatch)
	defer watch.Stop()
	applied := doc.Version
	for {
		select {
		case <-ctx.Done():
			s.saveUsage()
			return nil
		case <-ticker.C:
			s.saveUsage() // #482
			s.pruneUploads()
			s.ext.prune(s.cfg.Store.Document(), s.cfg.Now())
			s.pruneMembership(s.cfg.Store.Document())
			s.g2Tick()     // objects, port hiding, no-metadata sweep
			s.rel.reload() // ADR-0225: a new publication within a minute
		case <-watch.C:
			s.opsTick()  // P09 operations (ops.go)
			s.g2Second() // emergency priority, clone sweep
			if s.cfg.Store.Document().Version == applied {
				continue
			}
		}
		changed := s.cfg.Store.Document().Version != applied
		applied = s.cfg.Store.Document().Version
		if err := s.reconcile(); err != nil {
			s.logger.Warn("reconcile peers", "error", err.Error())
		}
		if changed {
			// Push the news instead of waiting for every device's next
			// poll (ADR-0026); polling stays as the fallback.
			if n := s.notifyAll(); n > 0 {
				s.logger.Debug("document change pushed", "version", applied, "devices", n)
			}
		}
	}
}

// reconcile makes the WireGuard peer set equal to the current, unexpired
// devices and invites in the document, without touching unchanged peers.
// Invite peers get only their IPv4 address: they can reach nothing but the
// control service.
func (s *Server) reconcile() error {
	doc := s.cfg.Store.Document()
	now := s.cfg.Now()
	s.prunePending(doc, now)
	want := map[trust.Key][]netip.Prefix{}
	for _, d := range doc.Devices {
		if now.Before(d.ExpiresAt) {
			want[d.WireGuardKey] = wgconf.HostPrefixes(d.IPv4, d.IPv6)
		}
	}
	for _, inv := range doc.Invites {
		if inv.ActiveAt(now) {
			want[inv.WireGuardKey] = []netip.Prefix{netip.PrefixFrom(inv.IPv4, 32)}
		}
	}
	st, err := s.wgStatus(true)
	if err != nil {
		return err
	}
	var uapi string
	for key := range st.Peers {
		if _, ok := want[key]; !ok {
			uapi += wgconf.Remove(key)
		}
	}
	for key, prefixes := range want {
		uapi += wgconf.AddOrUpdate(wgconf.Peer{PublicKey: key, AllowedIPs: prefixes})
	}
	if uapi == "" {
		return nil
	}
	if err := s.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("update wireguard peers: %w", err)
	}
	s.mu.Lock()
	s.statAt = time.Time{}
	s.mu.Unlock()
	return nil
}

func (s *Server) wgStatus(fresh bool) (wgconf.Status, error) {
	s.mu.Lock()
	if !fresh && time.Since(s.statAt) < statusCacheTTL {
		st := s.status
		s.mu.Unlock()
		return st, nil
	}
	s.mu.Unlock()
	raw, err := s.dev.IpcGet()
	if err != nil {
		return wgconf.Status{}, err
	}
	st, err := wgconf.ParseStatus(raw)
	if err != nil {
		return wgconf.Status{}, err
	}
	s.mu.Lock()
	s.status, s.statAt = st, time.Now()
	s.mu.Unlock()
	return st, nil
}

// handle answers one control datagram. WireGuard has already authenticated
// the sender: src is inside the allowed IPs of exactly one peer.
func (s *Server) handle(src netip.Addr, payload []byte) []byte {
	req, err := control.Decode(payload)
	if err != nil {
		return nil
	}
	doc := s.cfg.Store.Document()
	var self *trust.Device
	for i := range doc.Devices {
		if doc.Devices[i].IPv4 == src {
			self = &doc.Devices[i]
			break
		}
	}
	if self == nil {
		return s.handleInvite(req, doc, src)
	}
	// Minimum client version and clone observation (membership.go).
	if msg := s.versionGate(req, doc, self); msg != "" {
		return encodeError(req, msg)
	}
	s.observeClone(self)
	if msg := s.quarantineGate(req, self); msg != "" { // #603
		return encodeError(req, msg)
	}
	if resp, ok := s.handleMembership(req, doc, self); ok {
		return encodeReply(req, resp)
	}
	if resp, ok := s.handleG2(req, doc, self, src); ok { // g2_server.go
		return encodeReply(req, resp)
	}
	var resp control.Message
	switch req.T {
	case control.TypeHello:
		resp = s.hello(req, self)
	case control.TypeDoc:
		resp = s.chunk(req)
	case control.TypePut:
		resp = s.put(req, src)
	case control.TypePeers:
		resp = s.peers(req, doc, self)
	case control.TypePending:
		if !self.HasRole(trust.RoleAdmin) {
			return encodeError(req, "not allowed")
		}
		resp = s.listPending(req, doc)
	case control.TypeCaps:
		resp = s.caps(req, self)
	case control.TypeCandidates:
		resp = s.candidates(req, doc, self)
	case control.TypePeerCandidates:
		resp = s.peerCandidates(req, doc, self)
	case control.TypeCall:
		resp = s.call(req, doc, self)
	case control.TypeSealed: // ADR-0230: stored and forwarded, never opened
		resp = s.sealedPut(req, doc, self)
	case control.TypePeerSealed:
		resp = s.peerSealed(req, doc, self)
	case control.TypeDocGzip:
		resp = s.docGzip(req)
	case control.TypeRelaySession:
		resp = s.relaySession(req, self) // #151
	case control.TypeRelease: // ADR-0225: members only, never invites
		resp = s.releaseAnnounce()
		s.releaseRings(req, &resp, doc, self) // ADR-0235: update rings
		s.releaseRings(req, &resp, doc, self) // ADR-0235
	case control.TypeReleaseFile:
		resp = s.releaseChunk(req)
	case control.TypeInfo:
		if !self.HasRole(trust.RoleAdmin) {
			return encodeError(req, "not allowed")
		}
		data, err := sysinfo.Collect(s.cfg.Now()).Encode()
		if err != nil {
			return encodeError(req, "report unavailable")
		}
		resp = control.Message{T: control.TypeInfo, Data: data}
	case control.TypeInfoDetail:
		// One chunk of the coordinator's own detailed inventory (ADR-0143).
		if !self.HasRole(trust.RoleAdmin) {
			return encodeError(req, "not allowed")
		}
		data, total, id, ok := sysinfo.DetailChunk(req.Digest, req.Offset, control.ChunkSize)
		if !ok {
			return encodeError(req, "inventory unavailable")
		}
		off := req.Offset
		if id != req.Digest {
			off = 0
		}
		resp = control.Message{T: control.TypeInfoDetail, Offset: off, Total: total, Digest: id, Data: data}
	default:
		return encodeError(req, "unknown message type")
	}
	return encodeReply(req, resp)
}

// handleInvite serves a peer that holds an invite but is not a member yet.
// It may only read the document and submit its enrollment.
func (s *Server) handleInvite(req control.Message, doc *trust.Document, src netip.Addr) []byte {
	inv, ok := doc.InviteByAddr(src)
	if !ok || !inv.ActiveAt(s.cfg.Now()) {
		s.rejected(RejectUnknown, src, nil) // #187
		return encodeError(req, "unknown device")
	}
	var resp control.Message
	switch req.T {
	case control.TypeHello:
		doc, env, digest := s.cfg.Store.Snapshot()
		resp = control.Message{T: control.TypeHello, Version: doc.Version, Digest: hex.EncodeToString(digest[:]), Size: len(env)}
	case control.TypeDoc:
		resp = s.chunk(req)
	case control.TypeEnroll:
		resp = s.auditEnroll(s.enroll(req, doc, inv), src) // #187
	default:
		return encodeError(req, "not allowed")
	}
	return encodeReply(req, resp)
}

// enroll verifies an invite enrollment and keeps it for the owner. The
// coordinator checks the signatures only to refuse garbage; the owner's
// panel verifies them again against its own copy of the document.
func (s *Server) enroll(req control.Message, doc *trust.Document, inv trust.Invite) control.Message {
	if inv.Exhausted() {
		return control.Message{T: control.TypeError, Error: "invite already used"}
	}
	signed := trust.SignedInviteEnrollment{Payload: req.Data, DeviceSignature: req.Sig, InviteSignature: req.InviteSig}
	r, got, err := trust.OpenInviteEnrollment(doc, signed, s.cfg.Now())
	if err != nil || got.ID != inv.ID || s.enrollRejected(inv.ID+"/"+r.DeviceID) {
		return control.Message{T: control.TypeError, Error: "enrollment rejected"}
	}
	// One pending enrollment per single-use invite, one per device of a
	// multi-use invite, bounded (ADR-0028, membership.go).
	key := pendingKeyFor(inv, r.DeviceID)
	s.mu.Lock()
	if !s.pendingRoomLocked(inv, key) {
		s.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "busy"}
	}
	_, existed := s.pending[key]
	s.pending[key] = pendingEnrollment{inviteID: inv.ID, signed: signed, deviceID: r.DeviceID}
	s.mu.Unlock()
	if !existed {
		s.logger.Info("invite enrollment waiting for approval")
	}
	return control.Message{T: control.TypeEnroll, Complete: true}
}

// listPending returns one pending enrollment per response, ordered by
// invite id so paging is stable.
func (s *Server) listPending(req control.Message, doc *trust.Document) control.Message {
	s.prunePending(doc, s.cfg.Now())
	s.mu.Lock()
	ids := make([]string, 0, len(s.pending))
	for id := range s.pending {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	resp := control.Message{T: control.TypePending, Version: doc.Version, Total: len(ids)}
	if req.Offset > len(ids) {
		s.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	if req.Offset < len(ids) {
		p := s.pending[ids[req.Offset]]
		resp.Data, resp.Sig, resp.InviteSig = p.signed.Payload, p.signed.DeviceSignature, p.signed.InviteSignature
		resp.Offset = req.Offset
	}
	resp.Next = min(req.Offset+1, len(ids))
	s.mu.Unlock()
	return resp
}

// prunePending drops enrollments whose invite is gone, used or expired.
func (s *Server) prunePending(doc *trust.Document, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.pending {
		inv, ok := doc.InviteByID(p.inviteID)
		if !ok || inv.Exhausted() || inv.UsedFor(p.deviceID) || !inv.ActiveAt(now) {
			delete(s.pending, id)
		}
	}
}

func encodeReply(req, resp control.Message) []byte {
	resp.ID = req.ID
	out, err := control.Encode(resp)
	if err != nil {
		return encodeError(req, "response too large")
	}
	return out
}

func (s *Server) hello(_ control.Message, self *trust.Device) control.Message {
	doc, env, digest := s.cfg.Store.Snapshot()
	resp := control.Message{T: control.TypeHello, Version: doc.Version, Digest: hex.EncodeToString(digest[:]), Size: len(env)}
	if st, err := s.wgStatus(false); err == nil {
		if p, ok := st.Peers[self.WireGuardKey]; ok && p.Endpoint.IsValid() {
			resp.Endpoint = p.Endpoint.String()
		}
	}
	return resp
}

func (s *Server) chunk(req control.Message) control.Message {
	doc, env, _ := s.cfg.Store.Snapshot()
	if req.Version != doc.Version {
		return control.Message{T: control.TypeError, Error: "version changed"}
	}
	if req.Offset > len(env) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	end := min(req.Offset+control.ChunkSize, len(env))
	return control.Message{T: control.TypeDoc, Version: doc.Version, Offset: req.Offset, Total: len(env), Data: env[req.Offset:end]}
}

// put receives a newer document in order-sensitive chunks. The document is
// accepted only if it verifies against the pinned root key and is newer.
func (s *Server) put(req control.Message, src netip.Addr) control.Message {
	s.mu.Lock()
	if req.Offset == 0 {
		if req.Total <= 0 || req.Total > trust.MaxEnvelopeSize || len(req.Digest) != sha256.Size*2 {
			s.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "invalid upload"}
		}
		if _, exists := s.uploads[src]; !exists && len(s.uploads) >= maxConcurrentLoads {
			s.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "busy"}
		}
		s.uploads[src] = &upload{total: req.Total, digest: req.Digest, data: make([]byte, 0, req.Total)}
	}
	up, ok := s.uploads[src]
	if !ok || req.Total != up.total || req.Digest != up.digest {
		s.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "no matching upload"}
	}
	switch {
	case req.Offset == len(up.data):
		if len(up.data)+len(req.Data) > up.total {
			delete(s.uploads, src)
			s.mu.Unlock()
			return control.Message{T: control.TypeError, Error: "upload too long"}
		}
		up.data = append(up.data, req.Data...)
	case req.Offset+len(req.Data) == len(up.data):
		// Retransmission of the last chunk after a lost reply.
	default:
		delete(s.uploads, src)
		s.mu.Unlock()
		return control.Message{T: control.TypeError, Error: "out of order"}
	}
	up.updated = s.cfg.Now()
	if len(up.data) < up.total {
		s.mu.Unlock()
		return control.Message{T: control.TypePut, Offset: len(up.data)}
	}
	data := up.data
	delete(s.uploads, src)
	s.mu.Unlock()

	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != req.Digest {
		return control.Message{T: control.TypeError, Error: "digest mismatch"}
	}
	changed, err := s.cfg.Store.Accept(data, s.cfg.Now())
	if err != nil {
		s.logger.Warn("rejected uploaded document", "error", err.Error())
		s.rejected(RejectDocument, src, err) // #187
		return control.Message{T: control.TypeError, Error: "document rejected"}
	}
	if changed {
		s.logger.Info("accepted new network document", "version", s.cfg.Store.Document().Version)
		if err := s.reconcile(); err != nil {
			s.logger.Warn("reconcile peers", "error", err.Error())
		}
	}
	return control.Message{T: control.TypePut, Offset: len(data), Complete: true}
}

func (s *Server) peers(req control.Message, doc *trust.Document, self *trust.Device) control.Message {
	visible := s.visiblePeers(doc, self) // #629
	if req.Offset > len(visible) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	st, err := s.wgStatus(false)
	if err != nil {
		return control.Message{T: control.TypeError, Error: "status unavailable"}
	}
	end := min(req.Offset+control.PeersPerPage, len(visible))
	resp := control.Message{T: control.TypePeers, Version: doc.Version, Total: len(visible)}
	for _, d := range visible[req.Offset:end] {
		pe := control.PeerEndpoint{ID: d.ID}
		if p, ok := st.Peers[d.WireGuardKey]; ok && p.Endpoint.IsValid() {
			pe.Endpoint = p.Endpoint.String()
		}
		resp.Peers = append(resp.Peers, pe)
	}
	resp.Next = end
	return resp
}

func (s *Server) pruneUploads() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.cfg.Now().Add(-uploadIdleTimeout)
	for src, up := range s.uploads {
		if up.updated.Before(cutoff) {
			delete(s.uploads, src)
		}
	}
}

func encodeError(req control.Message, msg string) []byte {
	out, err := control.Encode(control.Message{T: control.TypeError, ID: req.ID, Error: msg})
	if err != nil {
		return nil
	}
	return out
}

// wgLogger routes wireguard-go logs to slog. Verbose logs contain endpoint
// addresses, so they go to debug level only (ADR-0008).
func wgLogger(l *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { l.Warn(fmt.Sprintf(format, args...)) },
	}
}
