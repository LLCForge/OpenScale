package updater

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/handover"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// handoverService is the fake platform's service with the tunnel side of
// a seamless update: the stopping process writes the handover, the starting
// one takes it and has its peers configured at once.
type handoverService struct {
	*fakeService
	t        *testing.T
	state    string
	dir      string
	peers    map[trust.Key]wgconf.PeerStatus
	hintSeen bool
	downAt   time.Time
	upAt     time.Time
	upPeers  int
}

func (s *handoverService) Stop(ctx context.Context) error {
	s.hintSeen = RestartForUpdate(s.state, time.Now())
	now := time.Now()
	if err := handover.Write(s.dir, handover.Capture("net1", "OpenScale", "0.8.0", trust.Key{}, s.peers, now)); err != nil {
		s.t.Error(err)
	}
	err := s.fakeService.Stop(ctx)
	s.downAt = time.Now() // the old tunnel is gone
	return err
}

func (s *handoverService) Start(ctx context.Context) error {
	if err := s.fakeService.Start(ctx); err != nil {
		return err
	}
	if !s.upAt.IsZero() {
		return nil // a rollback start
	}
	st, err := handover.Take(s.dir, "net1", time.Now())
	if err != nil {
		s.t.Errorf("take: %v", err)
		return nil
	}
	cache := filepath.Join(s.dir, handover.EndpointCacheFile)
	if _, err := handover.Seed(cache, st, time.Now()); err != nil {
		s.t.Errorf("seed: %v", err)
	}
	// The engine configures every peer from the cache before it talks to
	// the coordinator; the fake tunnel is up once all peers have one.
	data, err := os.ReadFile(cache)
	if err != nil {
		s.t.Error(err)
		return nil
	}
	var c struct {
		Peers map[string]json.RawMessage `json:"peers"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		s.t.Error(err)
	}
	s.upPeers = len(c.Peers)
	s.upAt = time.Now()
	return nil
}

// TestUpdateOutageWithHandover measures the tunnel outage of an update on
// the fake platform: from the old process's stop to the new process having
// every peer configured. The bound is the issue's target (well below a
// few seconds); the measured value is logged.
func TestUpdateOutageWithHandover(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	peers := map[trust.Key]wgconf.PeerStatus{}
	for i := range 50 {
		var k trust.Key
		k[0], k[1] = byte(i), 1
		peers[k] = wgconf.PeerStatus{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(40000+i)), LastHandshakeUnix: now.Unix()}
	}
	svc := &handoverService{fakeService: f.svc, t: t, state: f.state, dir: t.TempDir(), peers: peers}
	o := f.opts()
	o.Services = []Service{svc}
	res, err := f.apply(o, f.release("0.9.0", program("0.9.0", "ok")))
	if err != nil {
		t.Fatal(err)
	}
	if !svc.hintSeen {
		t.Fatal("the stopping service did not see the restart hint")
	}
	if RestartForUpdate(f.state, time.Now()) {
		t.Fatal("restart hint left behind after the update")
	}
	if svc.upPeers != 50 {
		t.Fatalf("%d peers configured at start, want 50", svc.upPeers)
	}
	gap := svc.upAt.Sub(svc.downAt)
	t.Logf("tunnel outage (stop -> peers configured): %s; update downtime incl. health check %s", gap, res.Downtime)
	if gap <= 0 || gap > 2*time.Second {
		t.Fatalf("outage %s, want under 2s", gap)
	}
}

func TestRestartHintExpires(t *testing.T) {
	dir := t.TempDir()
	done := writeRestartHint(dir, "1.0.1", time.Now())
	if !RestartForUpdate(dir, time.Now()) {
		t.Fatal("fresh hint not seen")
	}
	if RestartForUpdate(dir, time.Now().Add(RestartHintMaxAge+time.Minute)) {
		t.Fatal("old hint still counts")
	}
	done()
	if RestartForUpdate(dir, time.Now()) || RestartForUpdate("", time.Now()) {
		t.Fatal("removed hint still counts")
	}
}
