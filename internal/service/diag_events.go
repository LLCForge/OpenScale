package service

import (
	"sync"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
)

// Event list (F-017): peers coming online or going offline, falling back
// to the relay or getting a direct path again, the tunnel, the coordinator
// and captive portals. The list lives in memory only, is bounded, and
// holds device names from the signed document but never addresses.

// MaxEvents bounds the event list.
const MaxEvents = 200

// EventLog is a bounded ring of events, safe for concurrent use.
type EventLog struct {
	mu   sync.Mutex
	buf  []panel.DiagEvent
	next int
	full bool
	// onAdd also receives every event (the event stream, ADR-0105).
	onAdd func(panel.DiagEvent)
}

// SetOnAdd makes fn receive every new event, outside the log's lock.
func (l *EventLog) SetOnAdd(fn func(panel.DiagEvent)) {
	l.mu.Lock()
	l.onAdd = fn
	l.mu.Unlock()
}

// NewEventLog returns a log holding the last n events.
func NewEventLog(n int) *EventLog {
	if n <= 0 {
		n = MaxEvents
	}
	return &EventLog{buf: make([]panel.DiagEvent, n)}
}

// Add appends an event, dropping the oldest when the log is full.
func (l *EventLog) Add(ev panel.DiagEvent) {
	l.mu.Lock()
	l.buf[l.next] = ev
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	fn := l.onAdd
	l.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

// List returns the events, newest first.
func (l *EventLog) List() []panel.DiagEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.next
	if l.full {
		n = len(l.buf)
	}
	out := make([]panel.DiagEvent, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, l.buf[(l.next-i+len(l.buf))%len(l.buf)])
	}
	return out
}

// peerSeen is one peer in an observation.
type peerSeen struct {
	online bool
	path   string
}

// observation is what the watcher compares between two looks.
type observation struct {
	running     bool
	peers       map[string]peerSeen
	captive     bool
	syncFailing bool
}

// EventWatcher turns successive engine observations into events.
type EventWatcher struct {
	Log *EventLog
	Now func() time.Time

	last    observation
	started bool
}

// Observe looks at the engine (nil while the tunnel is down).
func (w *EventWatcher) Observe(e *node.Engine) {
	w.apply(observe(e, w.Now()))
}

func observe(e *node.Engine, now time.Time) observation {
	if e == nil {
		return observation{}
	}
	o := observation{running: true, peers: map[string]peerSeen{}}
	self, err := e.Self()
	if err != nil {
		return o
	}
	doc := e.Document()
	stats, _ := e.PeerStats()
	for _, d := range doc.TunnelPeersOf(self.Name) {
		s, ok := stats[d.WireGuardKey]
		ps := peerSeen{path: pathOf(s, ok)}
		ps.online = ok && s.LastHandshakeUnix > 0 && now.Sub(time.Unix(s.LastHandshakeUnix, 0)) < onlineWindow
		o.peers[d.Name] = ps
	}
	o.captive = e.CaptivePortal().Detected
	o.syncFailing = e.Status().LastSyncError != ""
	return o
}

func (w *EventWatcher) add(kind, peer, msg string) {
	w.Log.Add(panel.DiagEvent{At: w.Now(), Kind: kind, Peer: peer, Message: msg})
}

// apply compares o with the previous observation. The first observation of
// a running tunnel (and of each peer) only sets the baseline.
func (w *EventWatcher) apply(o observation) {
	prev := w.last
	w.last = o
	first := !w.started
	w.started = true
	switch {
	case o.running && !prev.running:
		if !first {
			w.add(panel.EventTunnelUp, "", "Tünel açıldı.")
		}
		return
	case !o.running && prev.running:
		w.add(panel.EventTunnelDown, "", "Tünel kapandı.")
		return
	case !o.running:
		return
	}
	for name, cur := range o.peers {
		old, known := prev.peers[name]
		if !known {
			continue
		}
		switch {
		case cur.online && !old.online:
			w.add(panel.EventPeerOnline, name, name+" çevrimiçi oldu.")
		case !cur.online && old.online:
			w.add(panel.EventPeerOffline, name, name+" çevrimdışı: birkaç dakikadır el sıkışma yok.")
		}
		switch {
		case cur.path == panel.PathRelay && old.path == panel.PathDirect:
			w.add(panel.EventPeerRelayed, name, name+" ile doğrudan yol kesildi; trafik koordinatörün aktarıcısından geçiyor.")
		case cur.path == panel.PathDirect && old.path == panel.PathRelay:
			w.add(panel.EventPeerDirect, name, name+" ile doğrudan yol kuruldu.")
		}
	}
	switch {
	case o.captive && !prev.captive:
		w.add(panel.EventCaptive, "", "Giriş sayfası (captive portal) algılandı; ağın giriş sayfasını açıp oturum açın.")
	case !o.captive && prev.captive:
		w.add(panel.EventCaptiveClear, "", "Giriş sayfası artık engellemiyor.")
	}
	switch {
	case o.syncFailing && !prev.syncFailing:
		w.add(panel.EventSyncLost, "", "Koordinatöre ulaşılamıyor.")
	case !o.syncFailing && prev.syncFailing:
		w.add(panel.EventSyncBack, "", "Koordinatöre yeniden ulaşıldı.")
	}
}
