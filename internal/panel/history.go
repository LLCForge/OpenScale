package panel

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// Connection history (#190): once a minute the panel server notes how this
// computer reaches each peer (direct, relay or no recent handshake) and the
// latest probe round-trip time. Samples stay in memory for 24 hours and
// are lost on restart; they never leave this computer. Path changes come
// from the tunnel's own endpoint history.

const (
	historyInterval = time.Minute
	historySpan     = 24 * time.Hour
	// historyMaxPeers bounds memory: 128 peers x 1440 samples.
	historyMaxPeers = 128
	historyMaxLen   = int(historySpan / historyInterval)
)

type historySample struct {
	At   time.Time `json:"at"`
	Path string    `json:"path"`
	// RTTMS is the latest probe round-trip time in milliseconds, 0 when no
	// new probe finished since the previous sample.
	RTTMS float64 `json:"rttMs,omitempty"`
}

type peerHistory struct {
	samples   []historySample
	lastProbe time.Time
	lastSeen  time.Time
}

// connHistory is safe for concurrent use; the zero value is ready.
type connHistory struct {
	mu    sync.Mutex
	peers map[string]*peerHistory
	// started is when sampling began (the graph's left edge before 24h).
	started time.Time
}

// samplePath classifies one peer like the network map does.
func samplePath(p node.PeerPath, now time.Time) string {
	if p.LastHandshake.IsZero() || now.Sub(p.LastHandshake) >= onlineWindow {
		return pathNone
	}
	if p.Relayed {
		return pathRelay
	}
	if p.Endpoint == "" {
		return pathNone
	}
	return pathDirect
}

// record adds one sample per peer and drops what is older than 24 hours.
func (h *connHistory) record(paths []node.PeerPath, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers == nil {
		h.peers = map[string]*peerHistory{}
	}
	if h.started.IsZero() {
		h.started = now
	}
	for _, p := range paths {
		ph, ok := h.peers[p.Name]
		if !ok {
			if len(h.peers) >= historyMaxPeers {
				continue
			}
			ph = &peerHistory{}
			h.peers[p.Name] = ph
		}
		s := historySample{At: now.UTC(), Path: samplePath(p, now)}
		if p.ProbeRTT > 0 && p.ProbedAt.After(ph.lastProbe) {
			s.RTTMS = float64(p.ProbeRTT.Microseconds()) / 1000
			ph.lastProbe = p.ProbedAt
		}
		ph.samples = append(ph.samples, s)
		if len(ph.samples) > historyMaxLen {
			ph.samples = append([]historySample(nil), ph.samples[len(ph.samples)-historyMaxLen:]...)
		}
		ph.lastSeen = now
	}
	cutoff := now.Add(-historySpan)
	for name, ph := range h.peers {
		if ph.lastSeen.Before(cutoff) {
			delete(h.peers, name)
			continue
		}
		i := sort.Search(len(ph.samples), func(i int) bool { return !ph.samples[i].At.Before(cutoff) })
		if i > 0 {
			ph.samples = append([]historySample(nil), ph.samples[i:]...)
		}
	}
}

// snapshot copies the samples of every peer.
func (h *connHistory) snapshot() (map[string][]historySample, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string][]historySample, len(h.peers))
	for name, ph := range h.peers {
		out[name] = append([]historySample(nil), ph.samples...)
	}
	return out, h.started
}

// diagnostics returns the desktop service's diagnostics, if any.
func (s *Server) diagnostics() (Diagnostics, bool) {
	if s.app == nil {
		return nil, false
	}
	d, ok := s.app.(Diagnostics)
	return d, ok
}

// runHistory samples until ctx ends. Without the desktop service there is
// no tunnel on this computer and it returns at once.
func (s *Server) runHistory(ctx context.Context) {
	d, ok := s.diagnostics()
	if !ok {
		return
	}
	sample := func() {
		paths, err := d.DiagPaths()
		if err != nil {
			return
		}
		s.hist.record(paths, s.now())
	}
	sample()
	t := time.NewTicker(historyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sample()
		}
	}
}

type historyPeer struct {
	Name    string                `json:"name"`
	Samples []historySample       `json:"samples"`
	Changes []node.EndpointChange `json:"changes"`
}

type historyReply struct {
	Schema      int           `json:"schema"`
	IntervalSec int           `json:"intervalSec"`
	Since       time.Time     `json:"since"`
	Now         time.Time     `json:"now"`
	Peers       []historyPeer `json:"peers"`
}

func (s *Server) handleConnHistory(w http.ResponseWriter, _ *http.Request) {
	now := s.now()
	samples, started := s.hist.snapshot()
	since := now.Add(-historySpan)
	if started.After(since) {
		since = started
	}
	if started.IsZero() {
		since = now
	}
	reply := historyReply{Schema: DiagSchema, IntervalSec: int(historyInterval / time.Second), Since: since.UTC(), Now: now.UTC(), Peers: []historyPeer{}}
	changes := map[string][]node.EndpointChange{}
	if d, ok := s.diagnostics(); ok {
		if paths, err := d.DiagPaths(); err == nil {
			for _, p := range paths {
				var recent []node.EndpointChange
				for _, c := range p.History {
					if !c.At.Before(now.Add(-historySpan)) {
						recent = append(recent, c)
					}
				}
				changes[p.Name] = recent
				if _, ok := samples[p.Name]; !ok {
					samples[p.Name] = nil
				}
			}
		}
	}
	for name, list := range samples {
		if list == nil {
			list = []historySample{}
		}
		ch := changes[name]
		if ch == nil {
			ch = []node.EndpointChange{}
		}
		reply.Peers = append(reply.Peers, historyPeer{Name: name, Samples: list, Changes: ch})
	}
	sort.Slice(reply.Peers, func(i, j int) bool { return reply.Peers[i].Name < reply.Peers[j].Name })
	writeJSON(w, http.StatusOK, reply)
}
