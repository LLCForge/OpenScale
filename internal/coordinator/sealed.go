package coordinator

import (
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

// Sealed endpoint candidates (ADR-0230, #38). The coordinator keeps, per
// receiving device, the newest opaque blob each visible peer left for it and
// pushes it on arrival. It never opens a blob: the key exists only on the two
// devices (node/sealedcands.go). Everything lives in memory and is never
// logged.

const (
	// sealedTTL is how long a blob is handed out; devices refresh theirs
	// every minute while their candidates are unchanged.
	sealedTTL = 5 * time.Minute
	// sealedOnline: a peer with a WireGuard handshake this recent counts as
	// online when telling devices which peers are old (plain-only).
	sealedOnline = 3 * time.Minute
	// maxSealedPerTarget and maxSealedTotal bound the mailbox memory.
	maxSealedPerTarget = 256
	maxSealedTotal     = 1 << 16
	// maxSealedPerSecond bounds the blobs one device may post per second.
	maxSealedPerSecond = 40
)

type sealedEntry struct {
	blob []byte
	at   time.Time
}

// sealedState is guarded by its own mutex, like extState.
type sealedState struct {
	mu sync.Mutex
	// caps: device id -> end of the period in which it announced
	// FeatureSealed in a caps request.
	caps map[string]time.Time
	// box: receiver id -> sender id -> newest blob.
	box   map[string]map[string]sealedEntry
	total int
	// window counts the posts of each device in the current second.
	window map[string]int
	second time.Time
}

func newSealedState() *sealedState {
	return &sealedState{caps: map[string]time.Time{}, box: map[string]map[string]sealedEntry{}, window: map[string]int{}}
}

// noteCaps records whether a caps request announced FeatureSealed. A device
// that stops announcing it (downgraded) stops getting pushes at once.
func (x *sealedState) noteCaps(id string, features []string, now time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if slices.Contains(features, control.FeatureSealed) {
		x.caps[id] = now.Add(control.SubscriptionTTL)
	} else {
		delete(x.caps, id)
	}
}

func (x *sealedState) capable(id string, now time.Time) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return now.Before(x.caps[id])
}

// store keeps blob from sender for receiver; false when rate limited.
func (x *sealedState) store(sender, receiver string, blob []byte, now time.Time) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if sec := now.Truncate(time.Second); !sec.Equal(x.second) {
		x.second, x.window = sec, map[string]int{}
	}
	if x.window[sender] >= maxSealedPerSecond {
		return false
	}
	x.window[sender]++
	m := x.box[receiver]
	if m == nil {
		m = map[string]sealedEntry{}
		x.box[receiver] = m
	}
	if _, ok := m[sender]; !ok {
		if len(m) >= maxSealedPerTarget {
			x.evictOldestLocked(m)
		}
		if x.total >= maxSealedTotal {
			x.pruneLocked(now, nil)
			if x.total >= maxSealedTotal {
				return false
			}
		}
		x.total++
	}
	m[sender] = sealedEntry{blob: slices.Clone(blob), at: now}
	return true
}

func (x *sealedState) evictOldestLocked(m map[string]sealedEntry) {
	var oldest string
	var at time.Time
	for id, e := range m {
		if oldest == "" || e.at.Before(at) {
			oldest, at = id, e.at
		}
	}
	if oldest != "" {
		delete(m, oldest)
		x.total--
	}
}

// fresh returns the blob sender left for receiver if it is recent.
func (x *sealedState) fresh(sender, receiver string, now time.Time) []byte {
	x.mu.Lock()
	defer x.mu.Unlock()
	e, ok := x.box[receiver][sender]
	if !ok || now.Sub(e.at) > sealedTTL {
		return nil
	}
	return e.blob
}

// prune drops expired blobs and capability marks; members, when not nil,
// also drops devices that left the document.
func (x *sealedState) prune(members map[string]bool, now time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneLocked(now, members)
}

func (x *sealedState) pruneLocked(now time.Time, members map[string]bool) {
	gone := func(id string) bool { return members != nil && !members[id] }
	for id, until := range x.caps {
		if gone(id) || !now.Before(until) {
			delete(x.caps, id)
		}
	}
	for rcv, m := range x.box {
		for snd, e := range m {
			if gone(rcv) || gone(snd) || now.Sub(e.at) > sealedTTL {
				delete(m, snd)
				x.total--
			}
		}
		if len(m) == 0 {
			delete(x.box, rcv)
		}
	}
}

// sealedPut stores a blob for a visible, current peer and pushes it when
// the peer is subscribed and understands it. The coordinator checks only
// the routing (who may write to whom) and the size, never the content.
func (s *Server) sealedPut(req control.Message, doc *trust.Document, self *trust.Device) control.Message {
	now := s.cfg.Now()
	if !now.Before(self.ExpiresAt) {
		return control.Message{T: control.TypeError, Error: "membership expired"}
	}
	if len(req.Sealed) == 0 || len(req.Sealed) > control.MaxSealed {
		return control.Message{T: control.TypeError, Error: "invalid sealed blob"}
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
	if !s.ext.seal.store(self.ID, target.ID, req.Sealed, now) {
		return control.Message{T: control.TypeError, Error: "rate limited"}
	}
	s.ext.mu.Lock()
	subscribed := now.Before(s.ext.subs[target.ID])
	s.ext.mu.Unlock()
	if subscribed && s.ext.seal.capable(target.ID, now) {
		// Best effort: the peer also finds the blob on its next listing.
		s.push(target.IPv4, control.Message{T: control.TypeSealed, Target: self.ID, Sealed: req.Sealed})
	}
	return control.Message{T: control.TypeSealed, Complete: true}
}

// peerSealed pages through the blobs left for this device and the
// capability of its visible peers.
func (s *Server) peerSealed(req control.Message, doc *trust.Document, self *trust.Device) control.Message {
	now := s.cfg.Now()
	var list []control.PeerSealed
	if now.Before(self.ExpiresAt) {
		st, _ := s.wgStatus(false) // without status nobody counts as old
		s.ext.mu.Lock()
		subs := make(map[string]bool, len(s.ext.subs))
		for id, until := range s.ext.subs {
			subs[id] = now.Before(until)
		}
		s.ext.mu.Unlock()
		for _, d := range s.visiblePeers(doc, self) {
			if !now.Before(d.ExpiresAt) {
				continue
			}
			e := control.PeerSealed{ID: d.ID, Sealed: s.ext.seal.fresh(d.ID, self.ID, now), Cap: s.ext.seal.capable(d.ID, now)}
			if !e.Cap {
				online := subs[d.ID]
				if p, ok := st.Peers[d.WireGuardKey]; ok && p.LastHandshakeUnix > 0 && now.Sub(time.Unix(p.LastHandshakeUnix, 0)) <= sealedOnline {
					online = true
				}
				e.Old = online
			}
			if e.Cap || e.Old || len(e.Sealed) > 0 {
				list = append(list, e)
			}
		}
	}
	if req.Offset > len(list) {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	resp := control.Message{T: control.TypePeerSealed, Version: doc.Version, Total: len(list), ID: req.ID, Next: req.Offset}
	for i := req.Offset; i < len(list) && len(resp.PeerSealed) < control.PeersPerPage; i++ {
		resp.PeerSealed = append(resp.PeerSealed, list[i])
		resp.Next = i + 1
		if control.EncodedSize(resp) > control.MaxDatagram {
			resp.PeerSealed = resp.PeerSealed[:len(resp.PeerSealed)-1]
			resp.Next = i
			break
		}
	}
	if len(resp.PeerSealed) == 0 && req.Offset < len(list) {
		return control.Message{T: control.TypeError, Error: "page too large"}
	}
	return resp
}
