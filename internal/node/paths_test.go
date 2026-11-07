package node

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// pathRig drives choosePaths for one peer with a fake clock.
type pathRig struct {
	t      *testing.T
	e      *Engine
	now    time.Time
	peer   trust.Device
	cur    wgconf.PeerStatus
	direct map[trust.Key]netip.AddrPort
}

func newPathRig(t *testing.T, force bool) *pathRig {
	r := &pathRig{t: t, now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	var key trust.Key
	key[0] = 7
	r.peer = trust.Device{ID: hex.EncodeToString(make([]byte, 16)), Name: "masaustu", WireGuardKey: key, ExpiresAt: r.now.Add(365 * 24 * time.Hour)}
	r.direct = map[trust.Key]netip.AddrPort{key: netip.MustParseAddrPort("203.0.113.9:41641")}
	r.e = &Engine{cfg: Config{
		Now:         func() time.Time { return r.now },
		RelayAfter:  defaultRelayAfter,
		DirectRetry: defaultDirectRetry,
		ForceRelay:  force,
	}, rand: func() float64 { return 0.5 }}
	return r
}

// step runs choosePaths, then mimics WireGuard applying the UAPI result.
func (r *pathRig) step() string {
	r.t.Helper()
	st := wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{r.peer.WireGuardKey: r.cur}}
	uapi := r.e.choosePaths([]trust.Device{r.peer}, st, r.direct)
	switch {
	case strings.Contains(uapi, "endpoint=relay-"):
		r.cur.Relayed, r.cur.Endpoint = true, netip.AddrPort{}
	case strings.Contains(uapi, "endpoint="):
		r.cur.Relayed, r.cur.Endpoint = false, r.direct[r.peer.WireGuardKey]
	}
	return uapi
}

func (r *pathRig) handshake() { r.cur.LastHandshakeUnix = r.now.Unix() }

func (r *pathRig) advance(d time.Duration) { r.now = r.now.Add(d) }

func (r *pathRig) state() pathState {
	r.e.mu.Lock()
	defer r.e.mu.Unlock()
	return *r.e.paths[r.peer.WireGuardKey]
}

func TestDirectRetryBacksOff(t *testing.T) {
	r := newPathRig(t, false)
	r.step() // learns the direct endpoint
	if r.cur.Relayed || !r.cur.Endpoint.IsValid() {
		t.Fatal("direct endpoint not set")
	}
	r.advance(defaultRelayAfter)
	r.step()
	if !r.cur.Relayed {
		t.Fatal("not relayed without a handshake")
	}
	// Each failed direct try doubles the wait: 5, 10, 20, 40 min.
	for i, wait := range []time.Duration{5, 10, 20, 40} {
		r.advance(wait*time.Minute - time.Second)
		r.step()
		if !r.cur.Relayed {
			t.Fatalf("try %d: direct path tried too early", i)
		}
		r.advance(time.Second)
		r.step()
		if r.cur.Relayed {
			t.Fatalf("try %d: direct path not tried after %s", i, wait*time.Minute)
		}
		r.advance(defaultRelayAfter)
		r.step()
		if !r.cur.Relayed {
			t.Fatalf("try %d: failed direct try did not return to the relay", i)
		}
		if got := r.state().failures; got != i+1 {
			t.Fatalf("try %d: failures %d", i, got)
		}
	}
	// The wait is capped at an hour.
	for i := 0; i < 3; i++ {
		r.advance(time.Hour)
		r.step()
		if r.cur.Relayed {
			t.Fatalf("capped try %d not made", i)
		}
		r.advance(defaultRelayAfter)
		r.step()
	}
	// A direct handshake resets the backoff.
	r.advance(time.Hour)
	r.step()
	r.advance(time.Second)
	r.handshake()
	r.step()
	if r.cur.Relayed || r.state().failures != 0 {
		t.Fatalf("direct handshake did not reset: relayed %v state %+v", r.cur.Relayed, r.state())
	}
}

func TestForceRelayNeverTriesDirect(t *testing.T) {
	r := newPathRig(t, true)
	if uapi := r.step(); !strings.Contains(uapi, "endpoint=relay-") {
		t.Fatalf("not relayed at once: %q", uapi)
	}
	for i := 0; i < 50; i++ {
		r.advance(10 * time.Minute)
		if uapi := r.step(); uapi != "" {
			t.Fatalf("forced relay changed the endpoint: %q", uapi)
		}
	}
	// Roaming to a direct endpoint is undone.
	r.cur.Relayed, r.cur.Endpoint = false, r.direct[r.peer.WireGuardKey]
	r.handshake()
	if uapi := r.step(); !strings.Contains(uapi, "endpoint=relay-") {
		t.Fatalf("roamed direct path kept: %q", uapi)
	}
	r.e.resetPaths(true)
	if uapi := r.step(); uapi != "" {
		t.Fatalf("network change tried a direct path: %q", uapi)
	}
}

func TestResetPathsAfterNetworkChange(t *testing.T) {
	// A relayed peer is tried directly at once when the addresses changed,
	// but not after a mere wake.
	r := newPathRig(t, false)
	r.step()
	r.advance(defaultRelayAfter)
	r.step()
	if !r.cur.Relayed {
		t.Fatal("setup: not relayed")
	}
	r.advance(time.Minute)
	r.e.resetPaths(false)
	if r.step(); !r.cur.Relayed {
		t.Fatal("wake alone left the relay")
	}
	r.e.resetPaths(true)
	if r.step(); r.cur.Relayed {
		t.Fatal("address change did not try the direct path")
	}

	// A direct peer gets RelayAfter to handshake again, instead of waiting
	// for a stale handshake (two minutes) first.
	r = newPathRig(t, false)
	r.step()
	r.handshake()
	r.advance(10 * time.Second)
	r.step()
	r.e.resetPaths(true)
	r.advance(defaultRelayAfter - time.Second)
	if r.step(); r.cur.Relayed {
		t.Fatal("relayed before the window ended")
	}
	r.advance(time.Second)
	if r.step(); !r.cur.Relayed {
		t.Fatal("dead direct path kept after a network change")
	}

	// A handshake within the window keeps the direct path, even in the
	// same second the window started.
	r = newPathRig(t, false)
	r.now = r.now.Add(900 * time.Millisecond)
	r.step()
	r.handshake()
	r.e.resetPaths(true)
	r.handshake()
	r.advance(defaultRelayAfter)
	if r.step(); r.cur.Relayed {
		t.Fatal("working direct path moved to the relay")
	}
}
