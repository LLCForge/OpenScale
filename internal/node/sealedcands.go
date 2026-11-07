package node

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Sealed endpoint candidates (ADR-0230, #38). A device's candidates (LAN
// and IPv6 interface addresses, static and router-mapped endpoints) go to
// each peer end-to-end encrypted through the coordinator, which only stores
// and forwards the opaque blob (coordinator/sealed.go). The plain report
// (TypeCandidates) remains for peers that cannot read sealed blobs, unless
// the owner chose SealedCandidatesOnly.
//
// Key agreement: X25519 between the two devices' existing WireGuard static
// keys (the public halves are in the signed document), then HKDF-SHA256
// with a fixed salt and an info string naming the network, the direction
// (sender and receiver public keys) and both device ids. Each direction has
// its own key.
//
// Blob (big-endian):
//
//	0   magic "OSSC" (4)
//	4   format version 1 (1)
//	5   counter (8): strictly increasing per sender; the receiver accepts
//	    only a counter above the last one it accepted from that sender
//	13  sender clock, unix seconds (8): refused when older than sealMaxAge
//	    or further than sealMaxSkew in the future
//	21  XChaCha20-Poly1305 nonce (24), random
//	45  ciphertext of the payload with the 16-byte tag; the 45 header
//	    bytes are the associated data
//
// Payload: flags (1: bit 0 "my NAT maps ports per destination", bit 1 "I
// take part in birthday scans"), count (1), then count entries of a 16-byte
// address (IPv4 mapped), 2-byte port and 1-byte family (4 or 6).
const (
	sealMagic    = "OSSC"
	sealVersion  = 1
	sealHdrLen   = 4 + 1 + 8 + 8 + chacha20poly1305.NonceSizeX
	sealEntryLen = 19
	sealSalt     = "openscale/sealed-candidates/v1"
	// sealMaxAge and sealMaxSkew bound the sender clock.
	sealMaxAge  = 10 * time.Minute
	sealMaxSkew = 5 * time.Minute
	// sealRefresh re-sends unchanged candidates well within the
	// coordinator's five-minute TTL.
	sealRefresh = time.Minute
	// sealForget drops a peer's sealed candidates not refreshed this long.
	sealForget = 10 * time.Minute
	// maxSealPostsPerSync bounds the blobs posted in one sync round; the
	// rest follow in the next rounds.
	maxSealPostsPerSync = 32
	// sealReplyEvery rate-limits answering a pushed blob with our own.
	sealReplyEvery = 10 * time.Second
	// sealOldStreak: a peer counts as plain-only after this many listings
	// in a row said so (a peer that just came up may be listed as online
	// before its caps request arrived).
	sealOldStreak = 2
	// maxSealPeers bounds the per-peer state.
	maxSealPeers = 4096

	sealFlagHardNAT = 1 << 0
	sealFlagScan    = 1 << 1
)

var (
	errSealFormat = errors.New("sealed candidates: malformed blob")
	errSealOpen   = errors.New("sealed candidates: authentication failed")
	errSealReplay = errors.New("sealed candidates: replayed or reordered blob")
	errSealClock  = errors.New("sealed candidates: sender clock out of range")
)

// SealedCandidatesMode chooses how candidates reach peers (ADR-0230).
type SealedCandidatesMode int

const (
	// SealedCandidatesAuto (default) seals candidates for every peer that
	// can read them and reports them plainly too only while a peer that
	// cannot is online.
	SealedCandidatesAuto SealedCandidatesMode = iota
	// SealedCandidatesOnly never reports candidates plainly: plain-only
	// peers then see the coordinator-observed endpoint and the relay only.
	SealedCandidatesOnly
	// SealedCandidatesOff keeps the old plain report and seals nothing.
	SealedCandidatesOff
)

// ParseSealedCandidatesMode accepts "auto" (or ""), "only" and "off".
func ParseSealedCandidatesMode(s string) (SealedCandidatesMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return SealedCandidatesAuto, nil
	case "only":
		return SealedCandidatesOnly, nil
	case "off":
		return SealedCandidatesOff, nil
	}
	return 0, fmt.Errorf("şifreli aday kipi %q geçersiz; auto, only veya off yazın", s)
}

func (m SealedCandidatesMode) String() string {
	switch m {
	case SealedCandidatesOnly:
		return "only"
	case SealedCandidatesOff:
		return "off"
	}
	return "auto"
}

// sealedPayload is what one blob says.
type sealedPayload struct {
	cands   []netip.AddrPort
	hardNAT bool
	scan    bool
}

func encodeSealedPayload(p sealedPayload) []byte {
	n := min(len(p.cands), control.MaxCandidates)
	b := make([]byte, 2, 2+n*sealEntryLen)
	if p.hardNAT {
		b[0] |= sealFlagHardNAT
	}
	if p.scan {
		b[0] |= sealFlagScan
	}
	b[1] = byte(n)
	for _, ap := range p.cands[:n] {
		raw := ap.Addr().As16()
		b = append(b, raw[:]...)
		b = binary.BigEndian.AppendUint16(b, ap.Port())
		if ap.Addr().Is4() || ap.Addr().Is4In6() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
	}
	return b
}

func decodeSealedPayload(b []byte) (sealedPayload, error) {
	var p sealedPayload
	if len(b) < 2 || b[0]&^(sealFlagHardNAT|sealFlagScan) != 0 || int(b[1]) > control.MaxCandidates || len(b) != 2+int(b[1])*sealEntryLen {
		return p, errSealFormat
	}
	p.hardNAT, p.scan = b[0]&sealFlagHardNAT != 0, b[0]&sealFlagScan != 0
	for i := 0; i < int(b[1]); i++ {
		e := b[2+i*sealEntryLen:]
		a := netip.AddrFrom16([16]byte(e[:16]))
		switch e[18] {
		case 4:
			if !a.Is4In6() {
				return p, errSealFormat
			}
			a = a.Unmap()
		case 6:
			if a.Is4In6() {
				return p, errSealFormat
			}
		default:
			return p, errSealFormat
		}
		ap := netip.AddrPortFrom(a, binary.BigEndian.Uint16(e[16:18]))
		// The peer is trusted only as far as the document trusts it: what
		// it says is probed with signed pings, never used blindly.
		if usableRemote(ap) && !slices.Contains(p.cands, ap) {
			p.cands = append(p.cands, ap)
		}
	}
	return p, nil
}

// sealKey derives the key for blobs from the device with fromPub to the
// device with toPub. shared is X25519 of one side's private and the other
// side's public WireGuard key (the same value on both sides).
func sealKey(shared []byte, network string, fromPub, toPub trust.Key, fromID, toID string) ([]byte, error) {
	info := "openscale sealed candidates v1\x00" + network + "\x00" + hex.EncodeToString(fromPub[:]) + "\x00" + hex.EncodeToString(toPub[:]) +
		"\x00" + fromID + "\x00" + toID
	return hkdf.Key(sha256.New, shared, []byte(sealSalt), info, chacha20poly1305.KeySize)
}

// sealBlob encrypts payload with key.
func sealBlob(key []byte, counter uint64, clock int64, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, sealHdrLen, sealHdrLen+len(payload)+aead.Overhead())
	copy(hdr, sealMagic)
	hdr[4] = sealVersion
	binary.BigEndian.PutUint64(hdr[5:13], counter)
	binary.BigEndian.PutUint64(hdr[13:21], uint64(clock)) //nolint:gosec // two's complement round trip
	if _, err := rand.Read(hdr[21:sealHdrLen]); err != nil {
		return nil, err
	}
	out := aead.Seal(hdr, hdr[21:sealHdrLen], payload, hdr)
	if len(out) > control.MaxSealed {
		return nil, errors.New("sealed candidates: blob too large")
	}
	return out, nil
}

// openBlob checks and decrypts a blob. last is the highest counter already
// accepted from this sender (0 for none); the caller stores the returned
// counter only after it accepted the payload.
func openBlob(key, blob []byte, last uint64, now time.Time) (sealedPayload, uint64, error) {
	if len(blob) < sealHdrLen+chacha20poly1305.Overhead || len(blob) > control.MaxSealed || string(blob[:4]) != sealMagic || blob[4] != sealVersion {
		return sealedPayload{}, 0, errSealFormat
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return sealedPayload{}, 0, err
	}
	hdr := blob[:sealHdrLen]
	plain, err := aead.Open(nil, hdr[21:sealHdrLen], blob[sealHdrLen:], hdr)
	if err != nil {
		return sealedPayload{}, 0, errSealOpen
	}
	counter := binary.BigEndian.Uint64(hdr[5:13])
	if counter <= last {
		return sealedPayload{}, 0, errSealReplay
	}
	age := now.Sub(time.Unix(int64(binary.BigEndian.Uint64(hdr[13:21])), 0)) //nolint:gosec // two's complement round trip
	if age > sealMaxAge || age < -sealMaxSkew {
		return sealedPayload{}, 0, errSealClock
	}
	p, err := decodeSealedPayload(plain)
	return p, counter, err
}

// sealPairKey names the keys of one peer in one network.
type sealPairKey struct {
	network, selfID, peerID string
	peer                    trust.Key
}

// sealPair holds the two directional keys with one peer.
type sealPair struct {
	send, recv []byte
}

type sealGot struct {
	p  sealedPayload
	at time.Time
}

type sealSent struct {
	key string
	at  time.Time
}

// peerSealInfo is what the coordinator's listing says about a peer.
type peerSealInfo struct {
	capable bool
	// oldStreak counts consecutive listings that called the peer old.
	oldStreak int
}

// sealer holds the sealed candidate state of an engine. Its mutex is never
// held while calling the coordinator.
type sealer struct {
	priv    *ecdh.PrivateKey
	selfPub trust.Key

	mu        sync.Mutex
	counter   uint64
	pairs     map[sealPairKey]sealPair
	recvLast  map[string]uint64
	got       map[string]sealGot
	info      map[string]*peerSealInfo
	sent      map[string]sealSent
	lastReply map[string]time.Time
	// listed: a listing completed since start (or since the coordinator
	// changed); before that nobody is known to be old.
	listed bool
	// announced: the coordinator was told we read pushed blobs.
	announced bool
}

func newSealer(private []byte, selfPub trust.Key, now time.Time) (*sealer, error) {
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return &sealer{priv: priv, selfPub: selfPub, counter: uint64(now.UnixNano()), pairs: map[sealPairKey]sealPair{}, recvLast: map[string]uint64{}, //nolint:gosec // positive clock
		got: map[string]sealGot{}, info: map[string]*peerSealInfo{}, sent: map[string]sealSent{}, lastReply: map[string]time.Time{}}, nil
}

// pairFor derives (once) the keys with peer d.
func (s *sealer) pairFor(network, selfID string, d trust.Device) (sealPair, error) {
	k := sealPairKey{network: network, selfID: selfID, peerID: d.ID, peer: d.WireGuardKey}
	s.mu.Lock()
	p, ok := s.pairs[k]
	s.mu.Unlock()
	if ok {
		return p, nil
	}
	pub, err := ecdh.X25519().NewPublicKey(d.WireGuardKey[:])
	if err != nil {
		return sealPair{}, err
	}
	shared, err := s.priv.ECDH(pub) // refuses the all-zero (low order) result
	if err != nil {
		return sealPair{}, err
	}
	if p.send, err = sealKey(shared, network, s.selfPub, d.WireGuardKey, selfID, d.ID); err != nil {
		return sealPair{}, err
	}
	if p.recv, err = sealKey(shared, network, d.WireGuardKey, s.selfPub, d.ID, selfID); err != nil {
		return sealPair{}, err
	}
	s.mu.Lock()
	if len(s.pairs) >= maxSealPeers {
		clear(s.pairs)
	}
	s.pairs[k] = p
	s.mu.Unlock()
	return p, nil
}

// seal builds a blob of p for peer d.
func (s *sealer) seal(network, selfID string, d trust.Device, p sealedPayload, now time.Time) ([]byte, error) {
	pair, err := s.pairFor(network, selfID, d)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.counter = max(s.counter+1, uint64(now.UnixNano())) //nolint:gosec // positive clock
	c := s.counter
	s.mu.Unlock()
	return sealBlob(pair.send, c, now.Unix(), encodeSealedPayload(p))
}

// open checks a blob from peer d and records it; a replay, a forgery and a
// blob for someone else all fail.
func (s *sealer) open(network, selfID string, d trust.Device, blob []byte, now time.Time) (sealedPayload, error) {
	pair, err := s.pairFor(network, selfID, d)
	if err != nil {
		return sealedPayload{}, err
	}
	s.mu.Lock()
	last := s.recvLast[d.ID]
	s.mu.Unlock()
	p, c, err := openBlob(pair.recv, blob, last, now)
	if err != nil {
		return sealedPayload{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c <= s.recvLast[d.ID] { // a concurrent open won
		return sealedPayload{}, errSealReplay
	}
	if len(s.got) >= maxSealPeers {
		clear(s.got)
	}
	s.recvLast[d.ID] = c
	s.got[d.ID] = sealGot{p: p, at: now}
	s.infoLocked(d.ID).capable = true
	return p, nil
}

func (s *sealer) infoLocked(id string) *peerSealInfo {
	pi := s.info[id]
	if pi == nil {
		if len(s.info) >= maxSealPeers {
			clear(s.info)
		}
		pi = &peerSealInfo{}
		s.info[id] = pi
	}
	return pi
}

// noteListing applies one complete listing of the coordinator.
func (s *sealer) noteListing(entries []control.PeerSealed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.ID] = true
		pi := s.infoLocked(e.ID)
		switch {
		case e.Old:
			pi.capable = false
			pi.oldStreak++
		default:
			pi.oldStreak = 0
			if e.Cap {
				pi.capable = true
			}
		}
	}
	for id, pi := range s.info {
		if !seen[id] {
			pi.oldStreak = 0 // offline: neither old nor known to be new
		}
	}
	s.listed = true
}

// legacyOnline reports whether a peer among ids is online and can read
// only plain candidates.
func (s *sealer) legacyOnline(ids []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if pi := s.info[id]; pi != nil && pi.oldStreak >= sealOldStreak {
			return true
		}
	}
	return false
}

// capable reports whether the peer reads sealed blobs (announced in the
// listing or proved by a valid blob).
func (s *sealer) capable(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	pi := s.info[id]
	return pi != nil && pi.capable
}

// due reports whether peer id should get a blob with this payload key.
func (s *sealer) due(id, key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sent[id]
	return !ok || st.key != key || now.Sub(st.at) >= sealRefresh
}

func (s *sealer) markSent(id, key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) >= maxSealPeers {
		clear(s.sent)
	}
	s.sent[id] = sealSent{key: key, at: now}
}

// replyDue rate-limits answering a pushed blob.
func (s *sealer) replyDue(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastReply[id]) < sealReplyEvery || now.Sub(s.sent[id].at) < sealReplyEvery {
		return false
	}
	if len(s.lastReply) >= maxSealPeers {
		clear(s.lastReply)
	}
	s.lastReply[id] = now
	return true
}

// stale returns the peers whose sealed candidates were not refreshed for
// sealForget, and forgets them.
func (s *sealer) stale(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, g := range s.got {
		if now.Sub(g.at) > sealForget {
			delete(s.got, id)
			out = append(out, id)
		}
	}
	return out
}

// plainCandidatesAllowed decides whether candidates are also reported
// plainly (ADR-0230): always when sealing is off; never when the owner
// forces sealed-only; otherwise only when the coordinator cannot forward
// blobs, no listing worked yet, or a plain-only peer is online.
func plainCandidatesAllowed(mode SealedCandidatesMode, coordinatorSeals, listed, legacyOnline bool) bool {
	switch {
	case mode == SealedCandidatesOff:
		return true
	case mode == SealedCandidatesOnly:
		return false
	case !coordinatorSeals || !listed:
		return true
	}
	return legacyOnline
}

// sealingActive reports whether this engine exchanges sealed candidates
// with a coordinator that supports them.
func (e *Engine) sealingActive() bool {
	return e.sealer != nil && !e.cfg.ForceRelay && e.cfg.SealedCandidates != SealedCandidatesOff && e.hasFeature(control.FeatureSealed)
}

// deviceFeatures are announced in caps requests once the coordinator is
// known to understand them (an old coordinator gets no field it might
// refuse).
func (e *Engine) deviceFeatures(coordinator map[string]bool) []string {
	if e.sealer == nil || e.cfg.ForceRelay || e.cfg.SealedCandidates == SealedCandidatesOff || !coordinator[control.FeatureSealed] {
		return nil
	}
	return []string{control.FeatureSealed}
}

// exchangeSealed lists what the coordinator holds for us, applies valid
// blobs and posts ours to every peer that reads them. It returns whether a
// listing completed.
func (e *Engine) exchangeSealed(ctx context.Context, doc *trust.Document, cands []netip.AddrPort, listen uint16) bool {
	self, err := e.selfIn(doc)
	if err != nil {
		return false
	}
	peers := doc.TunnelPeersOf(self.Name)
	byID := make(map[string]trust.Device, len(peers))
	for _, d := range peers {
		byID[d.ID] = d
	}
	ok := e.fetchSealed(ctx, doc, self, byID)
	now := e.cfg.Now()
	for _, id := range e.sealer.stale(now) {
		e.probe.setSealed(id, sealedPayload{})
	}
	payload := e.sealedPayloadFrom(cands, listen)
	key := sealedPayloadKey(payload)
	posted := 0
	for _, d := range peers {
		if posted >= maxSealPostsPerSync || ctx.Err() != nil {
			break
		}
		if !now.Before(d.ExpiresAt) || !e.sealer.capable(d.ID) || !e.sealer.due(d.ID, key, now) {
			continue
		}
		if err := e.postSealed(ctx, doc, self, d, payload, key); err != nil {
			e.logger.Debug("sealed candidates", "error", err.Error())
			continue
		}
		posted++
	}
	return ok
}

// fetchSealed pages through the coordinator's listing for this device.
func (e *Engine) fetchSealed(ctx context.Context, doc *trust.Document, self trust.Device, byID map[string]trust.Device) bool {
	var all []control.PeerSealed
	for offset, pages := 0, 0; pages <= len(doc.Devices); pages++ {
		resp, err := e.client.call(ctx, control.Message{T: control.TypePeerSealed, Offset: offset})
		if err != nil || resp.T != control.TypePeerSealed {
			return false
		}
		all = append(all, resp.PeerSealed...)
		if resp.Next <= offset || resp.Next >= resp.Total {
			break
		}
		offset = resp.Next
	}
	now := e.cfg.Now()
	for _, entry := range all {
		d, ok := byID[entry.ID]
		if !ok || len(entry.Sealed) == 0 {
			continue
		}
		e.applySealed(doc, self, d, entry.Sealed, now)
	}
	e.sealer.noteListing(all)
	return true
}

// applySealed opens a blob from d and hands the candidates to the prober.
func (e *Engine) applySealed(doc *trust.Document, self, d trust.Device, blob []byte, now time.Time) bool {
	p, err := e.sealer.open(doc.NetworkID, self.ID, d, blob, now)
	if err != nil {
		if !errors.Is(err, errSealReplay) { // the same blob is listed again until replaced
			e.logger.Debug("sealed candidates refused", "error", err.Error())
		}
		return false
	}
	e.probe.setSealed(d.ID, p)
	return true
}

// postSealed seals payload for d and hands it to the coordinator.
func (e *Engine) postSealed(ctx context.Context, doc *trust.Document, self, d trust.Device, payload sealedPayload, key string) error {
	now := e.cfg.Now()
	blob, err := e.sealer.seal(doc.NetworkID, self.ID, d, payload, now)
	if err != nil {
		return err
	}
	resp, err := e.client.call(ctx, control.Message{T: control.TypeSealed, Target: d.ID, Sealed: blob})
	if err != nil {
		return err
	}
	if resp.T != control.TypeSealed || !resp.Complete {
		return errors.New("coordinator sent an unexpected reply")
	}
	e.sealer.markSent(d.ID, key, now)
	return nil
}

// onSealedPush handles a blob pushed by the coordinator: it is opened (the
// coordinator cannot forge one) and answered with ours, so a peer that
// starts talking to us learns our candidates within a round trip.
func (e *Engine) onSealedPush(m control.Message) {
	if e.sealer == nil || e.cfg.ForceRelay || e.cfg.SealedCandidates == SealedCandidatesOff {
		return
	}
	doc := e.cfg.Store.Document()
	self, err := e.selfIn(doc)
	if err != nil {
		return
	}
	var peer trust.Device
	found := false
	for _, d := range doc.TunnelPeersOf(self.Name) {
		if d.ID == m.Target {
			peer, found = d, true
			break
		}
	}
	now := e.cfg.Now()
	if !found || !now.Before(peer.ExpiresAt) || !e.applySealed(doc, self, peer, m.Sealed, now) || !e.sealer.replyDue(peer.ID, now) {
		return
	}
	e.mu.Lock()
	cands := slices.Clone(e.localCands)
	listen := e.listenPort
	e.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout*callRetries)
		defer cancel()
		payload := e.sealedPayloadFrom(cands, listen)
		if err := e.postSealed(ctx, doc, self, peer, payload, sealedPayloadKey(payload)); err != nil {
			e.logger.Debug("sealed candidates reply", "error", err.Error())
		}
	}()
}

// sealedPayloadFrom builds our payload: the candidates and the NAT hints
// the birthday scan needs (portpredict.go).
func (e *Engine) sealedPayloadFrom(cands []netip.AddrPort, listen uint16) sealedPayload {
	return sealedPayload{cands: slices.Clone(cands), hardNAT: e.selfNATHard(listen), scan: !e.cfg.DisableBirthdayScan}
}

func sealedPayloadKey(p sealedPayload) string {
	return hex.EncodeToString(encodeSealedPayload(p))
}
