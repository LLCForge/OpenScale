package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Coordinator protocol extensions on the device side (ADR-0025, ADR-0026).
// Every extension is used only after the coordinator listed it in a caps
// reply; an old coordinator answers caps with "unknown message type" and
// the device keeps working exactly as before.

const (
	// capsRefresh renews the caps subscription well within
	// control.SubscriptionTTL.
	capsRefresh = time.Minute
	// oldCoordinatorRecheck: how long an old coordinator is trusted to stay
	// old before caps is asked again (it may have been upgraded).
	oldCoordinatorRecheck = 10 * time.Minute
	// candidateRefresh re-sends unchanged candidates before the
	// coordinator forgets them.
	candidateRefresh = time.Minute
	// notifyMinInterval rate-limits syncs triggered by pushed notices.
	notifyMinInterval = time.Second
)

// errUnknownType is how an old coordinator refuses an extension.
const errUnknownType = "coordinator: unknown message type"

// coordCaps is what the coordinator supports, guarded by Engine.mu.
type coordCaps struct {
	checked  time.Time
	features map[string]bool
	// old: the coordinator refused caps; no extension is used.
	old bool
}

// hasFeature reports whether the coordinator announced f.
func (e *Engine) hasFeature(f string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.caps.features[f]
}

// CoordinatorFeatures returns the extensions the coordinator announced
// (empty for an old coordinator or before the first sync).
func (e *Engine) CoordinatorFeatures() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.caps.features))
	for f := range e.caps.features {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

// refreshCaps asks the coordinator for its features when they are unknown
// or due; the request also renews the push subscription.
func (e *Engine) refreshCaps(ctx context.Context) {
	now := e.cfg.Now()
	e.mu.Lock()
	c := e.caps
	e.mu.Unlock()
	due := c.checked.IsZero() || (c.old && now.Sub(c.checked) >= oldCoordinatorRecheck) || (!c.old && now.Sub(c.checked) >= capsRefresh)
	if !due {
		return
	}
	// Device features go only to a coordinator already known to be new
	// (ADR-0230): an old one might refuse the field.
	resp, err := e.client.call(ctx, control.Message{T: control.TypeCaps, Features: e.deviceFeatures(c.features)})
	switch {
	case err == nil && resp.T == control.TypeCaps:
		features := map[string]bool{}
		for _, f := range resp.Features {
			features[f] = true
		}
		e.mu.Lock()
		e.caps = coordCaps{checked: now, features: features}
		e.mu.Unlock()
		if want := e.deviceFeatures(features); len(want) > 0 && len(e.deviceFeatures(c.features)) == 0 {
			// First contact with a sealing coordinator: announce at once
			// instead of a minute later, so pushes start now.
			if _, err := e.client.call(ctx, control.Message{T: control.TypeCaps, Features: want}); err != nil {
				e.logger.Debug("announce device features", "error", err.Error())
			}
		}
	case err != nil && err.Error() == errUnknownType:
		e.mu.Lock()
		e.caps = coordCaps{checked: now, old: true}
		e.mu.Unlock()
	default:
		// No reply: keep what we knew and ask again next round.
	}
}

// reportCandidates sends this device's candidates when they changed or are
// due (F-001, F-002, F-012). A device whose relaying is forced reveals no
// address (F-022).
func (e *Engine) reportCandidates(ctx context.Context) {
	if e.cfg.ForceRelay || !e.hasFeature(control.FeatureCandidates) {
		return
	}
	st, err := e.wgStatus()
	if err != nil || st.ListenPort <= 0 || st.ListenPort > 65535 {
		return
	}
	listen := uint16(st.ListenPort)
	cands := e.gatherCandidates(listen)
	e.mu.Lock()
	e.localCands, e.listenPort = cands, listen
	e.mu.Unlock()
	// Sealed candidates first (ADR-0230): the listing tells whether a
	// plain-only peer is online.
	sealing, listed, legacy := e.sealingActive(), false, false
	if sealing {
		doc := e.cfg.Store.Document()
		listed = e.exchangeSealed(ctx, doc, cands, listen)
		if self, err := e.selfIn(doc); err == nil {
			var ids []string
			for _, d := range doc.TunnelPeersOf(self.Name) {
				ids = append(ids, d.ID)
			}
			legacy = e.sealer.legacyOnline(ids)
		}
	}
	plain := cands
	key := ""
	if !plainCandidatesAllowed(e.cfg.SealedCandidates, sealing, listed, legacy) {
		// Nothing readable goes to the coordinator; the empty report
		// replaces what an earlier plain report left there.
		plain, key = nil, "sealed-only"
	}
	strs := make([]string, len(plain))
	for i, c := range plain {
		strs[i] = c.String()
	}
	key += strings.Join(strs, ",")
	now := e.cfg.Now()
	e.mu.Lock()
	same := key == e.candKey && now.Sub(e.candSent) < candidateRefresh
	e.mu.Unlock()
	if same {
		return
	}
	resp, err := e.client.call(ctx, control.Message{T: control.TypeCandidates, Cands: strs})
	if err != nil || resp.T != control.TypeCandidates {
		if err != nil {
			e.logger.Debug("report candidates", "error", err.Error())
		}
		return
	}
	e.mu.Lock()
	e.candKey, e.candSent, e.plainCands = key, now, plain
	e.mu.Unlock()
}

// currentListenPort is the WireGuard port the candidates were last
// gathered for (0 before the first report).
func (e *Engine) currentListenPort() uint16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.listenPort
}

// peerInfo is what the coordinator says about one peer.
type peerInfo struct {
	observed netip.AddrPort
	cands    []netip.AddrPort
}

// fetchPeers pages through the peers' endpoints, with candidates when the
// coordinator supports them.
func (e *Engine) fetchPeers(ctx context.Context, doc *trust.Document) (map[trust.Key]peerInfo, error) {
	byID := map[string]trust.Device{}
	for _, d := range doc.Devices {
		byID[d.ID] = d
	}
	out := map[trust.Key]peerInfo{}
	withCands := e.hasFeature(control.FeatureCandidates)
	typ := control.TypePeers
	if withCands {
		typ = control.TypePeerCandidates
	}
	for offset, pages := 0, 0; pages <= len(doc.Devices); pages++ {
		resp, err := e.client.call(ctx, control.Message{T: typ, Offset: offset})
		if err != nil {
			return nil, err
		}
		if resp.T != typ {
			return nil, errors.New("coordinator sent an unexpected reply")
		}
		add := func(id, endpoint string, cands []string) {
			d, ok := byID[id]
			if !ok {
				return
			}
			var pi peerInfo
			if ep, err := netip.ParseAddrPort(endpoint); err == nil {
				pi.observed = ep
			}
			pi.cands = parseCandidates(cands)
			out[d.WireGuardKey] = pi
		}
		for _, pe := range resp.Peers {
			add(pe.ID, pe.Endpoint, nil)
		}
		for _, pc := range resp.PeerCands {
			add(pc.ID, pc.Endpoint, pc.Cands)
		}
		if resp.Next <= offset || resp.Next >= resp.Total {
			break
		}
		offset = resp.Next
	}
	return out, nil
}

// parseCandidates keeps the well-formed, usable candidates (the
// coordinator is untrusted; a bad entry is skipped, not fatal).
func parseCandidates(in []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range in {
		if len(out) >= control.MaxCandidates {
			break
		}
		ap, err := netip.ParseAddrPort(s)
		if err != nil || !usableRemote(ap) || slices.Contains(out, ap) {
			continue
		}
		out = append(out, ap)
	}
	return out
}

// usableRemote reports whether ap may be probed: no loopback, multicast,
// broadcast, unspecified or zoned link-local address.
func usableRemote(ap netip.AddrPort) bool {
	a := ap.Addr()
	if !ap.IsValid() || ap.Port() == 0 || a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	return !(a.IsUnspecified() || a.IsLoopback() && !allowLoopbackProbes || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		(a.Is4() && a.As4() == [4]byte{255, 255, 255, 255}))
}

// allowLoopbackProbes lets tests, which run every device on 127.0.0.1,
// probe loopback endpoints. Never set outside tests.
var allowLoopbackProbes = false

// callPeer asks the coordinator to make the peer probe us now.
func (e *Engine) callPeer(ctx context.Context, peerID string) error {
	if !e.hasFeature(control.FeatureCall) {
		return errors.New("coordinator does not relay calls")
	}
	resp, err := e.client.call(ctx, control.Message{T: control.TypeCall, Target: peerID})
	if err != nil {
		return err
	}
	if resp.T != control.TypeCall || !resp.Complete {
		return errors.New("coordinator sent an unexpected reply")
	}
	return nil
}

// onPush handles a message pushed by the coordinator. The coordinator is
// untrusted: a notice only makes the device sync sooner, and a call only
// makes it send signed probes to a peer the document already pairs it with.
func (e *Engine) onPush(m control.Message) {
	switch m.T {
	case control.TypeNotify:
		e.onPushVersion(m, e.cfg.Store.Document().Version)
	case control.TypeSealed: // ADR-0230: opened here, unreadable to the coordinator
		e.onSealedPush(m)
	case control.TypeCall:
		// A lazy peer that calls us is configured first (F-020).
		e.lazyWake(m.Target)
		if e.probe == nil || e.cfg.ForceRelay {
			return
		}
		var observed netip.AddrPort
		if ap, err := netip.ParseAddrPort(m.Endpoint); err == nil {
			observed = ap
		}
		e.probe.called(m.Target, observed, parseCandidates(m.Cands))
	}
}

// onPushVersion wakes the sync loop for a notice of a version newer than
// current, at most once per notifyMinInterval.
func (e *Engine) onPushVersion(m control.Message, current uint64) {
	if m.Version <= current {
		return
	}
	now := e.cfg.Now()
	e.mu.Lock()
	if now.Sub(e.lastNotify) < notifyMinInterval {
		e.mu.Unlock()
		return
	}
	e.lastNotify = now
	e.mu.Unlock()
	select {
	case e.syncWake <- struct{}{}:
	default:
	}
}

// fetchDocument downloads the document announced in hello and checks its
// size and digest; the caller still verifies the signature. A coordinator
// that supports it sends the gzip form (ADR-0026); any problem with that
// falls back to the plain transfer.
func (e *Engine) fetchDocument(ctx context.Context, hello control.Message) ([]byte, error) {
	if e.hasFeature(control.FeatureDocGzip) {
		buf, err := fetchCompressedDocument(ctx, e.client, hello)
		if err == nil {
			return e.sanitizeDocument(ctx, buf)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		e.logger.Debug("compressed document transfer failed; using the plain one", "error", err.Error())
	}
	buf, err := fetchDocument(ctx, e.client, hello)
	if err != nil {
		return nil, err
	}
	return e.sanitizeDocument(ctx, buf)
}

// sanitizeDocument hands a document received from the network to the
// less privileged parsing helper (ADR-0233) when one is configured. The
// helper's canonical re-encoding is what the store then parses; any helper
// failure rejects the document (fail closed).
func (e *Engine) sanitizeDocument(ctx context.Context, data []byte) ([]byte, error) {
	if e.cfg.DocumentSanitizer == nil {
		return data, nil
	}
	out, err := e.cfg.DocumentSanitizer(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("belge ayrıştırma yardımcısı belgeyi reddetti: %w", err)
	}
	return out, nil
}

// fetchCompressedDocument downloads the gzip form of the announced
// document. The compressed size is bounded like the document itself, and
// decompression stops one byte past the announced size, so a hostile
// coordinator cannot make the device inflate a bomb.
func fetchCompressedDocument(ctx context.Context, c *client, hello control.Message) ([]byte, error) {
	if hello.Size <= 0 || hello.Size > trust.MaxEnvelopeSize {
		return nil, errors.New("coordinator announced an invalid document size")
	}
	var zbuf []byte
	total := -1
	for total < 0 || len(zbuf) < total {
		resp, err := c.call(ctx, control.Message{T: control.TypeDocGzip, Version: hello.Version, Offset: len(zbuf)})
		if err != nil {
			return nil, err
		}
		if total < 0 {
			total = resp.Total
			if total <= 0 || total > trust.MaxEnvelopeSize {
				return nil, errors.New("coordinator announced an invalid compressed size")
			}
		}
		if resp.T != control.TypeDocGzip || resp.Offset != len(zbuf) || resp.Total != total || len(resp.Data) == 0 || len(zbuf)+len(resp.Data) > total {
			return nil, errors.New("coordinator sent an unexpected compressed chunk")
		}
		zbuf = append(zbuf, resp.Data...)
	}
	return inflateDocument(zbuf, hello)
}

// inflateDocument decompresses zbuf and checks it against hello.
func inflateDocument(zbuf []byte, hello control.Message) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(zbuf))
	if err != nil {
		return nil, err
	}
	r.Multistream(false)
	buf, err := io.ReadAll(io.LimitReader(r, int64(hello.Size)+1))
	if err != nil {
		return nil, err
	}
	if len(buf) != hello.Size {
		return nil, errors.New("decompressed document has the wrong size")
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != hello.Digest {
		return nil, errors.New("document digest mismatch")
	}
	return buf, nil
}
