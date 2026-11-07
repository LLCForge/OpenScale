package node

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Coordinator integrity report (#154, ADR-0111). A coordinator cannot forge
// a document, but it can show different devices different (older) signed
// documents: a split view that hides a revocation from some of them. Each
// device remembers which version and digest every coordinator announced,
// tells its peers in the gossip hello (#25), and compares: a coordinator
// that keeps announcing an older version than the device already has, or
// announces the same version with a different digest to another device,
// is reported. Peer reports are claims; only a rejected document proves
// equivocation, and that is marked as verified.

const (
	// integrityFresh: observations older than this are not compared.
	integrityFresh = 10 * time.Minute
	// integrityBehindGrace: a coordinator that keeps answering with an
	// older version than this device's for this long is reported. An
	// honest one catches up within one sync after the device uploads.
	integrityBehindGrace = 3 * time.Minute
	maxVerifiedFindings  = 16
)

type coordObs struct {
	version     uint64
	digest      [32]byte
	at          time.Time
	behindSince time.Time
}

type peerObs struct {
	name    string
	version uint64
	digest  [32]byte
	views   []control.CoordView
	at      time.Time
}

// integrityState is guarded by its own mutex.
type integrityState struct {
	mu       sync.Mutex
	coords   map[trust.Key]*coordObs
	peers    map[string]*peerObs
	verified []IntegrityFinding
	logged   map[string]bool
}

// IntegrityFinding is one suspicious observation.
type IntegrityFinding struct {
	// Severity is "uyari" or "kritik".
	Severity    string `json:"severity"`
	Coordinator string `json:"coordinator,omitempty"`
	Peer        string `json:"peer,omitempty"`
	Text        string `json:"text"`
	// Verified is true when the document itself proved it.
	Verified bool `json:"verified"`
}

// CoordinatorView is what one coordinator last announced to this device.
type CoordinatorView struct {
	Coordinator string    `json:"coordinator"`
	Version     uint64    `json:"version"`
	Digest      string    `json:"digest"`
	At          time.Time `json:"at"`
}

// PeerDocumentView is what one peer said about its document.
type PeerDocumentView struct {
	Peer    string    `json:"peer"`
	Version uint64    `json:"version"`
	Digest  string    `json:"digest"`
	At      time.Time `json:"at"`
}

// IntegrityReport is the coordinator integrity report (#154).
type IntegrityReport struct {
	Version      uint64             `json:"version"`
	Digest       string             `json:"digest"`
	Coordinators []CoordinatorView  `json:"coordinators"`
	Peers        []PeerDocumentView `json:"peers"`
	Findings     []IntegrityFinding `json:"findings"`
}

func hexDigest32(d [32]byte) string { return hex.EncodeToString(d[:]) }

func parseDigest(s string) ([32]byte, bool) {
	var d [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(d) {
		return d, false
	}
	copy(d[:], b)
	return d, true
}

func (s *integrityState) initLocked() {
	if s.coords == nil {
		s.coords = map[trust.Key]*coordObs{}
		s.peers = map[string]*peerObs{}
		s.logged = map[string]bool{}
	}
}

// noteCoordinatorView records a coordinator's hello.
func (e *Engine) noteCoordinatorView(k trust.Key, version uint64, digest string, now time.Time) {
	d, ok := parseDigest(digest)
	if k.IsZero() || !ok || version == 0 {
		return
	}
	own := e.cfg.Store.Document().Version
	s := &e.p15.integ
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	o := s.coords[k]
	if o == nil {
		o = &coordObs{}
		s.coords[k] = o
	}
	o.version, o.digest, o.at = version, d, now
	switch {
	case version >= own:
		o.behindSince = time.Time{}
	case o.behindSince.IsZero():
		o.behindSince = now
	}
}

// notePeerView records a peer's gossip hello (request or reply).
func (e *Engine) notePeerView(p trust.Device, m control.Message) {
	d, ok := parseDigest(m.Digest)
	if !ok || m.Version == 0 {
		return
	}
	views, err := control.ParseCoordViews(m.Data)
	if err != nil {
		views = nil
	}
	s := &e.p15.integ
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	if len(s.peers) >= trust.MaxDevices && s.peers[p.ID] == nil {
		return
	}
	s.peers[p.ID] = &peerObs{name: p.Name, version: m.Version, digest: d, views: views, at: e.cfg.Now()}
}

// noteEquivocation records a peer document that the store rejected as a
// second document with an already seen version: two root-signed documents
// with the same version exist.
func (e *Engine) noteEquivocation(peerID string) {
	s := &e.p15.integ
	s.mu.Lock()
	s.initLocked()
	name := peerID
	if p := s.peers[peerID]; p != nil {
		name = p.name
	}
	f := IntegrityFinding{Severity: "kritik", Peer: name, Verified: true,
		Text: "Aynı sürüm numarasıyla kök anahtarla imzalı iki farklı belge var; kök anahtar başka bir yerde de kullanılıyor olabilir."}
	if len(s.verified) < maxVerifiedFindings {
		s.verified = append(s.verified, f)
	}
	s.mu.Unlock()
	e.logger.Warn("integrity: two signed documents with the same version", "peer", name)
}

// ownCoordViews encodes this device's fresh coordinator views for gossip.
func (e *Engine) ownCoordViews() []byte {
	now := e.cfg.Now()
	s := &e.p15.integ
	s.mu.Lock()
	var views []control.CoordView
	for k, o := range s.coords {
		age := now.Sub(o.at)
		if age > integrityFresh || age < 0 {
			continue
		}
		var v control.CoordView
		copy(v.Key[:], k[:control.CoordKeyPrefixLen])
		v.Version, v.Digest, v.AgeSec = o.version, o.digest, uint32(age/time.Second) //nolint:gosec // bounded by integrityFresh
		views = append(views, v)
	}
	s.mu.Unlock()
	slices.SortFunc(views, func(a, b control.CoordView) int { return slices.Compare(a.Key[:], b.Key[:]) })
	if len(views) > control.MaxCoordViews {
		views = views[:control.MaxCoordViews]
	}
	b, err := control.EncodeCoordViews(views)
	if err != nil || len(views) == 0 {
		return nil
	}
	return b
}

// CoordinatorIntegrity compares what the coordinators announced to this
// device with this device's document and with what peers reported (#154).
func (e *Engine) CoordinatorIntegrity() IntegrityReport {
	now := e.cfg.Now()
	doc, _, digest := e.cfg.Store.Snapshot()
	labels := map[trust.Key]string{}
	byPrefix := map[[control.CoordKeyPrefixLen]byte]trust.Key{}
	for _, c := range doc.AllCoordinators() {
		labels[c.WireGuardKey] = c.CoordinatorLabel()
		var p [control.CoordKeyPrefixLen]byte
		copy(p[:], c.WireGuardKey[:])
		byPrefix[p] = c.WireGuardKey
	}
	label := func(k trust.Key) string {
		if l, ok := labels[k]; ok {
			return l
		}
		return trust.CoordinatorFingerprint(k)
	}
	rep := IntegrityReport{Version: doc.Version, Digest: hexDigest32(digest)}
	s := &e.p15.integ
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	rep.Findings = append(rep.Findings, s.verified...)
	for k, o := range s.coords {
		rep.Coordinators = append(rep.Coordinators, CoordinatorView{Coordinator: label(k), Version: o.version, Digest: hexDigest32(o.digest), At: o.at})
		fresh := now.Sub(o.at) <= integrityFresh
		if !fresh {
			continue
		}
		if o.version == doc.Version && o.digest != digest {
			rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "kritik", Coordinator: label(k),
				Text: fmt.Sprintf("Koordinatör %d sürümü için bu cihazdakinden farklı bir belge özeti bildiriyor.", o.version)})
		}
		if !o.behindSince.IsZero() && o.version < doc.Version && o.at.Sub(o.behindSince) >= integrityBehindGrace {
			rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "uyari", Coordinator: label(k),
				Text: fmt.Sprintf("Koordinatör birkaç dakikadır eski belge sunuyor (%d < %d); yeni belgeyi saklıyor olabilir (bölünmüş görünüm).", o.version, doc.Version)})
		}
	}
	for _, p := range s.peers {
		rep.Peers = append(rep.Peers, PeerDocumentView{Peer: p.name, Version: p.version, Digest: hexDigest32(p.digest), At: p.at})
		if now.Sub(p.at) > integrityFresh {
			continue
		}
		if p.version == doc.Version && p.digest != digest {
			rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "uyari", Peer: p.name,
				Text: fmt.Sprintf("Eş, %d sürümü için farklı bir belge özeti bildiriyor (doğrulanmadı).", p.version)})
		}
		for _, v := range p.views {
			k, ok := byPrefix[v.Key]
			if !ok || v.AgeSec > uint32(integrityFresh/time.Second) {
				continue
			}
			mine := s.coords[k]
			if mine == nil || now.Sub(mine.at) > integrityFresh {
				continue
			}
			seenAt := p.at.Add(-time.Duration(v.AgeSec) * time.Second)
			switch {
			case v.Version == mine.version && v.Digest != mine.digest:
				rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "kritik", Coordinator: label(k), Peer: p.name,
					Text: fmt.Sprintf("Koordinatör aynı sürüm (%d) için bu cihaza ve eşe farklı belge özeti bildirdi.", v.Version)})
			case v.Version > mine.version && mine.at.After(seenAt):
				rep.Findings = append(rep.Findings, IntegrityFinding{Severity: "uyari", Coordinator: label(k), Peer: p.name,
					Text: fmt.Sprintf("Koordinatör eşe %d sürümünü, sonra bu cihaza daha eski %d sürümünü sundu (bölünmüş görünüm).", v.Version, mine.version)})
			}
		}
	}
	slices.SortFunc(rep.Coordinators, func(a, b CoordinatorView) int { return compareStrings(a.Coordinator, b.Coordinator) })
	slices.SortFunc(rep.Peers, func(a, b PeerDocumentView) int { return compareStrings(a.Peer, b.Peer) })
	return rep
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// logIntegrity logs every new finding once.
func (e *Engine) logIntegrity() {
	rep := e.CoordinatorIntegrity()
	s := &e.p15.integ
	for _, f := range rep.Findings {
		key := f.Severity + "|" + f.Coordinator + "|" + f.Peer + "|" + f.Text
		s.mu.Lock()
		seen := s.logged[key]
		if !seen && len(s.logged) < 1024 {
			s.logged[key] = true
		}
		s.mu.Unlock()
		if !seen {
			e.logger.Warn("coordinator integrity", "severity", f.Severity, "coordinator", f.Coordinator, "peer", f.Peer, "finding", f.Text)
		}
	}
}
