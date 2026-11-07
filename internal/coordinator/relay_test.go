package coordinator

import (
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

type docStore struct{ doc *trust.Document }

func (s docStore) Document() *trust.Document { return s.doc }

func dev(id byte, name, ip string, roles ...trust.Role) trust.Device {
	raw := make([]byte, 16)
	raw[15] = id
	return trust.Device{ID: hex.EncodeToString(raw), Name: name, IPv4: netip.MustParseAddr(ip), Roles: roles,
		ExpiresAt: time.Now().Add(time.Hour)}
}

func relayPayload(to trust.Device, n int) []byte {
	id, _ := hex.DecodeString(to.ID)
	return append(id, make([]byte, n)...)
}

func TestRelayAuthorization(t *testing.T) {
	a, b, c := dev(1, "a", "100.80.0.2"), dev(2, "b", "100.80.0.3"), dev(3, "c", "100.80.0.4")
	doc := &trust.Document{Version: 1, Devices: []trust.Device{a, b, c},
		Rules: []trust.Rule{{From: []string{"a"}, To: []string{"b"}, Protocol: trust.ProtocolAny}}}
	now := time.Now()
	r := newRelayer(docStore{doc}, func() time.Time { return now }, 0, 0)

	dst, out, ok := r.forward(a.IPv4, relayPayload(b, 100))
	if !ok || dst != b.IPv4 {
		t.Fatal("a -> b refused")
	}
	if got := hex.EncodeToString(out[:control.RelayIDLen]); got != a.ID {
		t.Fatalf("delivered with source %s, want %s", got, a.ID)
	}
	if _, _, ok := r.forward(a.IPv4, relayPayload(c, 100)); ok {
		t.Fatal("a -> c relayed without a rule")
	}
	if _, _, ok := r.forward(netip.MustParseAddr("100.80.0.99"), relayPayload(b, 100)); ok {
		t.Fatal("unknown sender relayed")
	}
	if _, _, ok := r.forward(a.IPv4, []byte{1, 2}); ok {
		t.Fatal("short payload relayed")
	}

	// The token bucket stops a flood; time refills it.
	sent := 0
	for i := 0; i < 10000; i++ {
		if _, _, ok := r.forward(a.IPv4, relayPayload(b, 1400)); ok {
			sent++
		}
	}
	if sent*1416 > DefaultRelayBurst+1416 {
		t.Fatalf("burst not limited: %d packets", sent)
	}
	now = now.Add(time.Second)
	if _, _, ok := r.forward(a.IPv4, relayPayload(b, 1400)); !ok {
		t.Fatal("bucket did not refill")
	}
	if st := r.Stats()[a.ID]; st.Dropped == 0 || st.Packets == 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRelayConfiguredLimits(t *testing.T) {
	a, b := dev(1, "a", "100.80.0.2"), dev(2, "b", "100.80.0.3")
	doc := &trust.Document{Version: 1, Devices: []trust.Device{a, b},
		Rules: []trust.Rule{{From: []string{"a"}, To: []string{"b"}, Protocol: trust.ProtocolAny}}}
	now := time.Now()
	const burst = 64 << 10
	r := newRelayer(docStore{doc}, func() time.Time { return now }, MinRelayRate, burst)
	sent := 0
	for i := 0; i < 1000; i++ {
		if _, _, ok := r.forward(a.IPv4, relayPayload(b, 1000)); ok {
			sent++
		}
	}
	if want := burst / 1016; sent != want {
		t.Fatalf("sent %d packets with a %d byte burst, want %d", sent, burst, want)
	}
	// Half a second refills half the configured rate.
	now = now.Add(500 * time.Millisecond)
	sent = 0
	for i := 0; i < 1000; i++ {
		if _, _, ok := r.forward(a.IPv4, relayPayload(b, 1000)); ok {
			sent++
		}
	}
	if lo, hi := MinRelayRate/2/1016-1, MinRelayRate/2/1016+1; sent < lo || sent > hi {
		t.Fatalf("refill sent %d packets, want about %d", sent, MinRelayRate/2/1016)
	}

	for _, c := range []struct {
		rate, burst int64
		ok          bool
	}{
		{0, 0, true}, {MinRelayRate, control.RelayMaxPayload, true}, {MaxRelayRate, MaxRelayBurst, true},
		{MinRelayRate - 1, 0, false}, {MaxRelayRate + 1, 0, false}, {-1, 0, false},
		{0, control.RelayMaxPayload - 1, false}, {0, MaxRelayBurst + 1, false},
	} {
		if err := validRelayLimits(c.rate, c.burst); (err == nil) != c.ok {
			t.Errorf("validRelayLimits(%d, %d) = %v", c.rate, c.burst, err)
		}
	}
}
