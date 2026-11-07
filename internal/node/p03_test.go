package node

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/osnet"
)

// RFC 6052 section 2.4 examples for 192.0.2.33.
var rfc6052Examples = []struct{ prefix, addr string }{
	{"2001:db8::/32", "2001:db8:c000:221::"},
	{"2001:db8:100::/40", "2001:db8:1c0:2:21::"},
	{"2001:db8:122::/48", "2001:db8:122:c000:2:2100::"},
	{"2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"},
	{"2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"},
	{"2001:db8:122:344::/96", "2001:db8:122:344::c000:221"},
	{"64:ff9b::/96", "64:ff9b::c000:221"},
}

func TestSynthesizeNAT64RFC6052(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.33")
	for _, ex := range rfc6052Examples {
		got, ok := synthesizeNAT64(netip.MustParsePrefix(ex.prefix), v4)
		if !ok || got != netip.MustParseAddr(ex.addr) {
			t.Errorf("%s: %v %v, want %s", ex.prefix, got, ok, ex.addr)
		}
	}
	if _, ok := synthesizeNAT64(netip.MustParsePrefix("2001:db8::/33"), v4); ok {
		t.Error("odd prefix length accepted")
	}
	if _, ok := synthesizeNAT64(netip.MustParsePrefix("fe80::/96"), v4); ok {
		t.Error("link-local prefix accepted")
	}
}

func TestNAT64PrefixFrom(t *testing.T) {
	for _, ex := range rfc6052Examples {
		p := netip.MustParsePrefix(ex.prefix)
		for _, wka := range []string{"192.0.0.170", "192.0.0.171"} {
			a, ok := synthesizeNAT64(p, netip.MustParseAddr(wka))
			if !ok {
				t.Fatal(ex.prefix)
			}
			got, ok := nat64PrefixFrom([]netip.Addr{netip.MustParseAddr("192.0.0.170"), a})
			if !ok || got != p.Masked() {
				t.Errorf("%s via %s: %v %v", ex.prefix, wka, got, ok)
			}
		}
	}
	if _, ok := nat64PrefixFrom([]netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.0.170")}); ok {
		t.Error("prefix found without a well-known address")
	}
	if _, ok := nat64PrefixFrom([]netip.Addr{netip.MustParseAddr("::ffff:192.0.0.170")}); ok {
		t.Error("IPv4-mapped answer accepted")
	}
}

func TestNAT64TranslatableAndIPv6Only(t *testing.T) {
	for s, want := range map[string]bool{"203.0.113.9": true, "198.51.100.1": true, "10.0.0.1": false, "192.168.1.1": false,
		"100.64.1.1": false, "127.0.0.1": false, "2001:db8::1": false, "192.0.0.170": false} {
		if got := nat64Translatable(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
	overlay := []netip.Prefix{netip.MustParsePrefix("100.100.0.0/16")}
	v6only := []interfaceAddr{{"wlan0", netip.MustParseAddr("2a00:1450::5")}, {"wlan0", netip.MustParseAddr("fe80::1")}, {"os0", netip.MustParseAddr("100.100.0.2")}}
	if !ipv6OnlyHost(v6only, "os0", overlay) {
		t.Error("IPv6-only host not recognized")
	}
	dual := append(v6only, interfaceAddr{"wlan0", netip.MustParseAddr("192.168.1.20")})
	if ipv6OnlyHost(dual, "os0", overlay) {
		t.Error("dual-stack host taken for IPv6-only")
	}
	if ipv6OnlyHost([]interfaceAddr{{"wlan0", netip.MustParseAddr("fe80::1")}}, "os0", overlay) {
		t.Error("link-local only taken for IPv6-only")
	}
}

func TestViaNAT64(t *testing.T) {
	orig := listInterfaceAddrs
	t.Cleanup(func() { listInterfaceAddrs = orig })
	listInterfaceAddrs = func() ([]interfaceAddr, error) {
		return []interfaceAddr{{"wlan0", netip.MustParseAddr("2a00:1450::5")}}, nil
	}
	queries := 0
	e := &Engine{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	e.cfg.Now = time.Now
	e.cfg.Resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		queries++
		if host != nat64Name {
			return nil, errors.New("unexpected")
		}
		return []netip.Addr{netip.MustParseAddr("64:ff9b::c000:aa"), netip.MustParseAddr("64:ff9b::c000:ab")}, nil
	}
	ap := netip.MustParseAddrPort("203.0.113.9:51820")
	got := e.viaNAT64(context.Background(), ap)
	if got != netip.MustParseAddrPort("[64:ff9b::cb00:7109]:51820") {
		t.Fatalf("got %v", got)
	}
	_ = e.viaNAT64(context.Background(), ap)
	if queries != 1 {
		t.Fatalf("prefix not cached: %d queries", queries)
	}
	e.p03.nat64.reset()
	_ = e.viaNAT64(context.Background(), ap)
	if queries != 2 {
		t.Fatal("reset did not rediscover")
	}
	if got := e.viaNAT64(context.Background(), netip.MustParseAddrPort("10.0.0.1:1")); got.Addr().Is6() {
		t.Fatal("private address translated")
	}
	e.cfg.DisableNAT64 = true
	if got := e.viaNAT64(context.Background(), ap); got != ap {
		t.Fatal("DisableNAT64 ignored")
	}
	// Dual stack: unchanged, no query.
	e.cfg.DisableNAT64 = false
	listInterfaceAddrs = func() ([]interfaceAddr, error) {
		return []interfaceAddr{{"wlan0", netip.MustParseAddr("192.168.1.2")}, {"wlan0", netip.MustParseAddr("2a00:1450::5")}}, nil
	}
	if got := e.viaNAT64(context.Background(), ap); got != ap {
		t.Fatal("dual-stack address translated")
	}
}

func TestValidStaticEndpointName(t *testing.T) {
	good := []string{"ev.example.net:51820", "EV.Example.NET.:1", "a-1.b2.example:65535"}
	for _, s := range good {
		if _, _, err := ValidStaticEndpointName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{"", "ev.example.net", "ev.example.net:0", "ev.example.net:70000", "ev:1", "localhost:1",
		"x.localhost:1", "1.2.3.4:1", "[2001:db8::1]:1", "-a.example:1", "a..example:1", "a_b.example:1",
		"123.456:1", strings.Repeat("a", 64) + ".example:1"}
	for _, s := range bad {
		if _, _, err := ValidStaticEndpointName(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if err := checkStaticNames([]string{"ev.example.net:1"}, 8); err == nil {
		t.Error("over the candidate limit accepted")
	}
}

func TestStaticNamesResolve(t *testing.T) {
	var mu sync.Mutex
	answer := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("198.51.100.1")}
	var fail bool
	now := time.Unix(1_700_000_000, 0)
	s := newStaticNames([]string{"ev.example.net:51820"}, func(context.Context, string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, errors.New("no answer")
		}
		return answer, nil
	}, func() time.Time { mu.Lock(); defer mu.Unlock(); return now }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := s.current(); len(got) != 0 {
		t.Fatalf("first call blocks or returns %v", got)
	}
	p03WaitFor(t, func() bool { return len(s.current()) == 2 })
	got := s.current()
	if got[0] != netip.MustParseAddrPort("203.0.113.7:51820") || got[1] != netip.MustParseAddrPort("[2001:db8::7]:51820") {
		t.Fatalf("got %v", got)
	}
	// A failure keeps the previous addresses.
	mu.Lock()
	fail = true
	mu.Unlock()
	s.invalidate()
	_ = s.current()
	p03WaitFor(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return !s.resolving })
	if len(s.current()) != 2 {
		t.Fatal("addresses lost on a failed lookup")
	}
}

func p03WaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUDPMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, udpMemoryFile)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	nets := []osnet.CurrentNetwork{{Kind: osnet.NetworkWiFi, Name: "Otel"}}
	ident := func() ([]osnet.CurrentNetwork, error) { return nets, nil }
	m := newUDPMemory(path, clock, ident)
	fp := m.fingerprint()
	if fp == "" || m.blocked(fp) {
		t.Fatalf("fresh memory: %q %v", fp, m.blocked(fp))
	}
	if err := m.note(fp, true); err != nil {
		t.Fatal(err)
	}
	// A new instance (restart) recalls it with the same salt.
	m2 := newUDPMemory(path, clock, ident)
	if fp2 := m2.fingerprint(); fp2 != fp || !m2.blocked(fp2) {
		t.Fatalf("not recalled after restart: %q", fp2)
	}
	// Another network is not blocked.
	nets = []osnet.CurrentNetwork{{Kind: osnet.NetworkWiFi, Name: "Ev"}}
	if m2.blocked(m2.fingerprint()) {
		t.Fatal("other network blocked")
	}
	// Expiry.
	now = now.Add(udpMemoryMaxAge + time.Hour)
	if m2.blocked(fp) {
		t.Fatal("expired entry still blocked")
	}
	now = now.Add(-udpMemoryMaxAge - time.Hour)
	// Forget.
	if err := m2.note(fp, false); err != nil {
		t.Fatal(err)
	}
	if newUDPMemory(path, clock, ident).blocked(fp) {
		t.Fatal("forgotten entry recalled")
	}
	// Bounded.
	for i := range udpMemoryMaxEntries + 10 {
		now = now.Add(time.Second)
		nets = []osnet.CurrentNetwork{{Kind: osnet.NetworkWiFi, Name: "n" + string(rune('A'+i%26)) + string(rune('a'+i/26))}}
		if err := m2.note(m2.fingerprint(), true); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(m2.data.Blocked); n != udpMemoryMaxEntries {
		t.Fatalf("%d entries", n)
	}
	// Wired networks are never remembered.
	nets = []osnet.CurrentNetwork{{Kind: osnet.NetworkWired, Name: "Ethernet"}}
	if m2.fingerprint() != "" {
		t.Fatal("wired network fingerprinted")
	}
}

func TestParseUDPMemoryRejects(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, raw := range []string{"", "{", `{"version":2,"salt":"00112233445566778899aabbccddeeff"}`, `{"version":1,"salt":"zz"}`} {
		if d := parseUDPMemory([]byte(raw), now); d.Salt != "" || len(d.Blocked) != 0 {
			t.Errorf("%q: %+v", raw, d)
		}
	}
	raw := `{"version":1,"salt":"00112233445566778899aabbccddeeff","blocked":{"ABCDEF":"2023-11-14T22:13:20Z","0123456789abcdef0123456789abcdef":"2099-01-01T00:00:00Z","fedcba9876543210fedcba9876543210":"2023-11-14T22:00:00Z"}}`
	d := parseUDPMemory([]byte(raw), now)
	if len(d.Blocked) != 1 {
		t.Fatalf("%+v", d.Blocked)
	}
}

func TestRelayReason(t *testing.T) {
	cases := []struct {
		in   relayReasonInput
		want string
	}{
		{relayReasonInput{forced: true, coordOverTCP: true}, RelayReasonForced},
		{relayReasonInput{coordOverTCP: true}, RelayReasonUDPBlocked},
		{relayReasonInput{}, RelayReasonNoCandidates},
		{relayReasonInput{haveCandidate: true, failures: 3}, RelayReasonDirectTimeout},
	}
	for _, c := range cases {
		code, hint := relayReason(c.in)
		if code != c.want || hint == "" {
			t.Errorf("%+v: %q %q", c.in, code, hint)
		}
	}
	if _, hint := relayReason(relayReasonInput{haveCandidate: true, failures: 3}); !strings.Contains(hint, "3 kez") {
		t.Errorf("failure count missing: %q", hint)
	}
}

func FuzzNAT64PrefixFrom(f *testing.F) {
	f.Add(netip.MustParseAddr("64:ff9b::c000:aa").AsSlice())
	f.Add(netip.MustParseAddr("2001:db8:c000:aa::").AsSlice())
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) != 16 {
			return
		}
		a := netip.AddrFrom16([16]byte(b))
		p, ok := nat64PrefixFrom([]netip.Addr{a})
		if !ok {
			return
		}
		if !usableNAT64Prefix(p) {
			t.Fatalf("unusable prefix %v", p)
		}
		syn, ok := synthesizeNAT64(p, netip.MustParseAddr("192.0.0.170"))
		if !ok {
			t.Fatalf("cannot synthesize with %v", p)
		}
		// The synthesized address must yield a usable prefix again.
		if got, ok := nat64PrefixFrom([]netip.Addr{syn}); !ok || !usableNAT64Prefix(got) {
			t.Fatalf("round trip lost prefix %v (%v)", p, syn)
		}
	})
}

func FuzzParseUDPMemory(f *testing.F) {
	f.Add([]byte(`{"version":1,"salt":"00112233445566778899aabbccddeeff","blocked":{"0123456789abcdef0123456789abcdef":"2023-11-14T22:13:20Z"}}`))
	f.Add([]byte("{}"))
	now := time.Unix(1_700_000_000, 0)
	f.Fuzz(func(t *testing.T, raw []byte) {
		d := parseUDPMemory(raw, now)
		if len(d.Blocked) > udpMemoryMaxEntries {
			t.Fatal("unbounded")
		}
		if d.Salt == "" && len(d.Blocked) != 0 {
			t.Fatal("entries without salt")
		}
		for fp := range d.Blocked {
			if len(fp) != osnet.NetworkFingerprintLen || !isLowerHex(fp) {
				t.Fatalf("bad key %q", fp)
			}
		}
	})
}

func FuzzValidStaticEndpointName(f *testing.F) {
	f.Add("ev.example.net:51820")
	f.Add("1.2.3.4:1")
	f.Add("[::1]:1")
	f.Fuzz(func(t *testing.T, s string) {
		h, p, err := ValidStaticEndpointName(s)
		if err != nil {
			return
		}
		if p == 0 || !validDNSName(h) {
			t.Fatalf("%q accepted as %q %d", s, h, p)
		}
		if _, err := netip.ParseAddr(h); err == nil {
			t.Fatalf("IP accepted: %q", s)
		}
	})
}
