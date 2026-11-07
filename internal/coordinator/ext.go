package coordinator

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Control protocol extensions: endpoint candidates and "call me now"
// (ADR-0025), pushed document notices and compressed documents (ADR-0026).
// Everything here lives in memory only and is never logged (ADR-0005,
// ADR-0008).

const (
	// candidateTTL is how long reported candidates are handed out; devices
	// report again well before (every minute and on every change).
	candidateTTL = 5 * time.Minute
	// callInterval rate-limits calls between the same two devices.
	callInterval = 2 * time.Second
	// maxCallsPerSecond bounds the calls one device may make.
	maxCallsPerSecond = 20
)

// coordFeatures is what TypeCaps announces.
var coordFeatures = append([]string{control.FeatureCandidates, control.FeatureCall, control.FeatureNotify, control.FeatureDocGzip, control.FeatureRelease, control.FeatureSealed}, membershipFeatures...)

type candidateEntry struct {
	cands []netip.AddrPort
	at    time.Time
}

type callKey struct{ from, to string }

// extState is guarded by its own mutex: handlers run on WireGuard's receive
// path and must not wait for document reconciliation.
type extState struct {
	mu    sync.Mutex
	subs  map[string]time.Time // device id -> subscription end
	cands map[string]candidateEntry
	calls map[callKey]time.Time
	// callWindow counts the calls of each device in the current second.
	callWindow map[string]int
	callSecond time.Time

	gzMu      sync.Mutex
	gzVersion uint64
	gzDigest  [32]byte
	gzData    []byte

	// seal holds sealed candidates (ADR-0230, sealed.go).
	seal *sealedState
}

func newExtState() *extState {
	return &extState{subs: map[string]time.Time{}, cands: map[string]candidateEntry{}, calls: map[callKey]time.Time{}, callWindow: map[string]int{}, seal: newSealedState()}
}

// caps answers a features request and subscribes the device to pushes.
func (s *Server) caps(req control.Message, self *trust.Device) control.Message {
	now := s.cfg.Now()
	if !now.Before(self.ExpiresAt) {
		return control.Message{T: control.TypeError, Error: "membership expired"}
	}
	s.ext.seal.noteCaps(self.ID, req.Features, now) // ADR-0230
	s.ext.mu.Lock()
	s.ext.subs[self.ID] = now.Add(control.SubscriptionTTL)
	s.ext.mu.Unlock()
	return control.Message{T: control.TypeCaps, Version: s.cfg.Store.Document().Version, Features: coordFeatures}
}

// validCandidate accepts addresses another device could send UDP to.
func validCandidate(doc *trust.Document, ap netip.AddrPort) bool {
	a := ap.Addr()
	if !ap.IsValid() || ap.Port() == 0 || a.Zone() != "" || a.Is4In6() {
		return false
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() && a.As4() == [4]byte{255, 255, 255, 255} {
		return false
	}
	return !doc.IPv4Prefix.Contains(a) && !(doc.IPv6Prefix.IsValid() && doc.IPv6Prefix.Contains(a))
}

// candidates stores the device's reported candidates.
func (s *Server) candidates(req control.Message, doc *trust.Document, self *trust.Device) control.Message {
	now := s.cfg.Now()
	if !now.Before(self.ExpiresAt) {
		return control.Message{T: control.TypeError, Error: "membership expired"}
	}
	seen := map[netip.AddrPort]bool{}
	var list []netip.AddrPort
	for _, c := range req.Cands {
		ap, err := netip.ParseAddrPort(c)
		if err != nil || !validCandidate(doc, ap) {
			return control.Message{T: control.TypeError, Error: "invalid candidate"}
		}
		if !seen[ap] {
			seen[ap] = true
			list = append(list, ap)
		}
	}
	s.ext.mu.Lock()
	s.ext.cands[self.ID] = candidateEntry{cands: list, at: now}
	s.ext.mu.Unlock()
	resp := control.Message{T: control.TypeCandidates, Complete: true}
	if ep := s.observed(self); ep.IsValid() {
		resp.Endpoint = ep.String()
	}
	return resp
}

// observed returns the endpoint WireGuard last saw the device at.
func (s *Server) observed(d *trust.Device) netip.AddrPort {
	st, err := s.wgStatus(false)
	if err != nil {
		return netip.AddrPort{}
	}
	if p, ok := st.Peers[d.WireGuardKey]; ok && p.Endpoint.IsValid() {
		return p.Endpoint
	}
	return netip.AddrPort{}
}

// freshCandidates returns the device's candidates if they are recent.
func (s *Server) freshCandidates(id string, now time.Time) []string {
	s.ext.mu.Lock()
	defer s.ext.mu.Unlock()
	e, ok := s.ext.cands[id]
	if !ok || now.Sub(e.at) > candidateTTL {
		return nil
	}
	out := make([]string, len(e.cands))
	for i, c := range e.cands {
		out[i] = c.String()
	}
	return out
}

// peerCandidates is TypePeers with candidates. A page holds as many peers
// as fit in one datagram (at most PeersPerPage).
func (s *Server) peerCandidates(req control.Message, doc *trust.Document, self *trust.Device) control.Message {
	now := s.cfg.Now()
	// Like TypePeers, an expired device still gets the observed endpoints
	// (it drops expired peers itself); candidates go only between members
	// that are both current.
	selfCurrent := now.Before(self.ExpiresAt)
	visible := s.visiblePeers(doc, self) // #629
	if req.Offset > len(visible) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	st, err := s.wgStatus(false)
	if err != nil {
		return control.Message{T: control.TypeError, Error: "status unavailable"}
	}
	resp := control.Message{T: control.TypePeerCandidates, Version: doc.Version, Total: len(visible), ID: req.ID}
	i := req.Offset
	for ; i < len(visible) && len(resp.PeerCands) < control.PeersPerPage; i++ {
		d := visible[i]
		pc := control.PeerCandidates{ID: d.ID}
		if p, ok := st.Peers[d.WireGuardKey]; ok && p.Endpoint.IsValid() {
			pc.Endpoint = p.Endpoint.String()
		}
		if selfCurrent && now.Before(d.ExpiresAt) {
			pc.Cands = s.freshCandidates(d.ID, now)
		}
		resp.PeerCands = append(resp.PeerCands, pc)
		resp.Next = i + 1
		if control.EncodedSize(resp) > control.MaxDatagram {
			resp.PeerCands = resp.PeerCands[:len(resp.PeerCands)-1]
			resp.Next = i
			break
		}
	}
	if len(resp.PeerCands) == 0 && i < len(visible) {
		return control.Message{T: control.TypeError, Error: "page too large"}
	}
	if resp.Next < req.Offset {
		resp.Next = req.Offset
	}
	return resp
}

// call pushes "probe this device now" to a tunnel peer, so both sides send
// their first packets at about the same time (simultaneous hole punching).
func (s *Server) call(req control.Message, doc *trust.Document, self *trust.Device) control.Message {
	now := s.cfg.Now()
	if !now.Before(self.ExpiresAt) {
		return control.Message{T: control.TypeError, Error: "membership expired"}
	}
	var target *trust.Device
	for _, d := range s.visiblePeers(doc, self) {
		if d.ID == req.Target {
			target = &d
			break
		}
	}
	if target == nil || !now.Before(target.ExpiresAt) {
		return control.Message{T: control.TypeError, Error: "unknown peer"}
	}
	s.ext.mu.Lock()
	if sec := now.Truncate(time.Second); !sec.Equal(s.ext.callSecond) {
		s.ext.callSecond, s.ext.callWindow = sec, map[string]int{}
	}
	key := callKey{self.ID, target.ID}
	limited := now.Sub(s.ext.calls[key]) < callInterval || s.ext.callWindow[self.ID] >= maxCallsPerSecond
	subscribed := now.Before(s.ext.subs[target.ID])
	if !limited {
		s.ext.calls[key] = now
		s.ext.callWindow[self.ID]++
	}
	s.ext.mu.Unlock()
	if limited {
		return control.Message{T: control.TypeError, Error: "rate limited"}
	}
	if !subscribed {
		return control.Message{T: control.TypeError, Error: "peer unavailable"}
	}
	push := control.Message{T: control.TypeCall, Target: self.ID, Cands: s.freshCandidates(self.ID, now)}
	if ep := s.observed(self); ep.IsValid() {
		push.Endpoint = ep.String()
	}
	if !s.push(target.IPv4, push) {
		return control.Message{T: control.TypeError, Error: "peer unavailable"}
	}
	return control.Message{T: control.TypeCall, Complete: true}
}

// push sends an unsolicited message to a device's PushPort.
func (s *Server) push(dst netip.Addr, m control.Message) bool {
	t := s.tun
	if t == nil {
		return false
	}
	payload, err := control.Encode(m)
	if err != nil {
		return false
	}
	pkt, err := packet.BuildUDP4(t.addr, dst, control.Port, control.PushPort, payload)
	if err != nil {
		return false
	}
	select {
	case t.out <- pkt:
		return true
	default:
		return false
	}
}

// notifyAll tells every subscribed, unexpired device that the document
// changed (ADR-0026). Lost notices only delay the device to its next poll.
func (s *Server) notifyAll() int {
	doc, env, digest := s.cfg.Store.Snapshot()
	now := s.cfg.Now()
	s.ext.mu.Lock()
	subs := make(map[string]bool, len(s.ext.subs))
	for id, until := range s.ext.subs {
		if now.Before(until) {
			subs[id] = true
		}
	}
	s.ext.mu.Unlock()
	msg := control.Message{T: control.TypeNotify, Version: doc.Version, Digest: hexDigest(digest), Size: len(env)}
	sent := 0
	for _, d := range doc.Devices {
		if subs[d.ID] && now.Before(d.ExpiresAt) && s.push(d.IPv4, msg) {
			sent++
		}
	}
	return sent
}

// docGzip serves a chunk of the gzip-compressed envelope.
func (s *Server) docGzip(req control.Message) control.Message {
	doc, env, digest := s.cfg.Store.Snapshot()
	if req.Version != doc.Version {
		return control.Message{T: control.TypeError, Error: "version changed"}
	}
	data, err := s.ext.compressed(doc.Version, digest, env)
	if err != nil {
		return control.Message{T: control.TypeError, Error: "compression failed"}
	}
	if req.Offset > len(data) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	end := min(req.Offset+control.ChunkSize, len(data))
	return control.Message{T: control.TypeDocGzip, Version: doc.Version, Offset: req.Offset, Total: len(data), Data: data[req.Offset:end]}
}

// compressed returns the gzip form of env, computed once per version.
func (x *extState) compressed(version uint64, digest [32]byte, env []byte) ([]byte, error) {
	x.gzMu.Lock()
	defer x.gzMu.Unlock()
	if x.gzData != nil && x.gzVersion == version && x.gzDigest == digest {
		return x.gzData, nil
	}
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(env); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	x.gzVersion, x.gzDigest, x.gzData = version, digest, buf.Bytes()
	return x.gzData, nil
}

// prune drops stale extension state and devices no longer in doc.
func (x *extState) prune(doc *trust.Document, now time.Time) {
	members := make(map[string]bool, len(doc.Devices))
	for _, d := range doc.Devices {
		members[d.ID] = true
	}
	x.seal.prune(members, now)
	x.mu.Lock()
	defer x.mu.Unlock()
	for id, until := range x.subs {
		if !members[id] || !now.Before(until) {
			delete(x.subs, id)
		}
	}
	for id, e := range x.cands {
		if !members[id] || now.Sub(e.at) > candidateTTL {
			delete(x.cands, id)
		}
	}
	for k, at := range x.calls {
		if now.Sub(at) >= callInterval {
			delete(x.calls, k)
		}
	}
}

func hexDigest(d [32]byte) string { return hex.EncodeToString(d[:]) }
