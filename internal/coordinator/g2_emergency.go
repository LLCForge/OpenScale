package coordinator

import (
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
)

// Emergency document priority (#681, ADR-0180). When a document that turns
// the network-wide lock on arrives (the panic button publishes a document
// signed in advance, #682, so the root key is not needed in the crisis),
// the coordinator:
//   - pushes the news to every subscribed device at once and again after
//     2, 5, 15, 30, 60 and 120 seconds, so devices behind lossy links or
//     with a lost push still sync within seconds instead of at their next
//     poll;
//   - compresses the document right away so the first fetch does not wait;
//   - for EmergencyWindow lets the requests a device needs to fetch the
//     document (hello, doc, docz, caps, ver) through even when the control
//     rate limits would drop them, so a flood cannot delay the lock.
// The coordinator decides nothing: the document is root-signed and
// verified by every device; a forged "emergency" cannot pass Store.Accept.

const (
	// EmergencyWindow is how long the priority lasts.
	EmergencyWindow = 15 * time.Minute
)

var emergencyPushes = []time.Duration{0, 2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}

type emergencyState struct {
	mu         sync.Mutex
	started    time.Time
	until      time.Time
	next       int
	lastLocked bool
	version    uint64
}

// emergencyTick runs every second from the run loop.
func (s *Server) emergencyTick() {
	if s.g2 == nil || s.g2.hard.NoEmergencyPriority {
		return
	}
	doc, env, digest := s.cfg.Store.Snapshot()
	if doc == nil {
		return
	}
	now := s.cfg.Now()
	e := &s.g2.emerg
	e.mu.Lock()
	locked := doc.Locked()
	// A new locked version (the lock itself, or a later emergency document
	// such as removing a device while locked) starts the priority again.
	start := locked && (!e.lastLocked || doc.Version != e.version)
	e.lastLocked = locked
	if start {
		e.started, e.until, e.next, e.version = now, now.Add(EmergencyWindow), 0, doc.Version
	}
	if !locked {
		e.until = time.Time{}
	}
	var push bool
	if !e.until.IsZero() && e.next < len(emergencyPushes) && !now.Before(e.started.Add(emergencyPushes[e.next])) {
		push = true
		e.next++
	}
	if !e.until.IsZero() && !now.Before(e.until) {
		e.until = time.Time{}
	}
	e.mu.Unlock()
	if start {
		// Warm the compressed copy for the first fetches (ext.go).
		_, _ = s.ext.compressed(doc.Version, digest, env)
		s.logger.Warn("acil durum belgesi önceliklendirildi: ağ kilitlendi, bütün cihazlara hemen bildiriliyor", "version", doc.Version)
	}
	if push && s.tun != nil {
		s.notifyAll()
	}
}

// EmergencyActive reports whether the emergency priority is on.
func (s *Server) EmergencyActive() bool {
	if s.g2 == nil {
		return false
	}
	e := &s.g2.emerg
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.until.IsZero() && s.cfg.Now().Before(e.until)
}

// emergencyBypass lets the document fetch requests through the control
// limits during the emergency window.
func (s *Server) emergencyBypass(payload []byte) bool {
	if !s.EmergencyActive() {
		return false
	}
	req, err := control.Decode(payload)
	if err != nil {
		return false
	}
	switch req.T {
	case control.TypeHello, control.TypeDoc, control.TypeDocGzip, control.TypeCaps, control.TypeClientVersion:
		return true
	}
	return false
}

// allowControlG2 is the control limit with the emergency exception.
func (s *Server) allowControlG2(src netip.Addr, payload []byte) bool {
	if s.p15.allowControl(src, s.cfg.Now()) {
		return true
	}
	return s.emergencyBypass(payload)
}
