package node

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func TestValidateKeepalive(t *testing.T) {
	for _, d := range []time.Duration{MinKeepalive, DefaultKeepalive, MaxKeepalive} {
		if err := ValidateKeepalive(d); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
	for _, d := range []time.Duration{5 * time.Second, 121 * time.Second, 25500 * time.Millisecond} {
		if err := ValidateKeepalive(d); err == nil {
			t.Errorf("%s accepted", d)
		}
	}
}

func TestAdaptiveKeepalive(t *testing.T) {
	clock := &pqClock{t: time.Unix(1_800_000_000, 0)}
	e := &Engine{cfg: Config{AdaptiveKeepalive: true, Keepalive: DefaultKeepalive, Now: clock.now}, logger: testLoggerOrDiscard(t)}
	key := trust.Key{1}
	st := func(handshakeAgo time.Duration) wgconf.Status {
		return wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{key: {LastHandshakeUnix: clock.now().Add(-handshakeAgo).Unix()}}}
	}
	want := func(uapi string, secs int) {
		t.Helper()
		if got := e.keepaliveFor(key); got != secs {
			t.Fatalf("keepalive %d s, want %d s (uapi %q)", got, secs, uapi)
		}
	}
	if u := e.adaptKeepalive(st(10 * time.Second)); u != "" {
		t.Fatalf("healthy peer changed: %q", u)
	}
	want("", 25)
	// The handshake is lost and comes back within minutes: shorter.
	lose := func() string {
		e.adaptKeepalive(st(5 * time.Minute))
		clock.add(time.Minute)
		return e.adaptKeepalive(st(5 * time.Second))
	}
	u := lose()
	if !strings.Contains(u, "persistent_keepalive_interval=16") {
		t.Fatalf("uapi %q", u)
	}
	want(u, 16)
	want(lose(), 10)
	want(lose(), 10) // never below the minimum
	// A peer that was away for long is not a NAT problem.
	e.adaptKeepalive(st(5 * time.Minute))
	clock.add(30 * time.Minute)
	want(e.adaptKeepalive(st(5*time.Second)), 10)
	// An hour without a loss: grows back step by step, up to the setting.
	for _, secs := range []int{15, 20, 25, 25} {
		clock.add(keepaliveGrow)
		want(e.adaptKeepalive(st(5*time.Second)), secs)
	}
	// A network change starts over at the setting.
	lose()
	if u := e.resetKeepalive(); !strings.Contains(u, "persistent_keepalive_interval=25") {
		t.Fatalf("reset uapi %q", u)
	}
	want("", 25)
	// Not adaptive: the setting, always.
	e.cfg.AdaptiveKeepalive = false
	if u := lose(); u != "" {
		t.Fatalf("non-adaptive changed: %q", u)
	}
}

func testLoggerOrDiscard(t *testing.T) *slog.Logger {
	if l := testLogger(t, "test"); l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}
