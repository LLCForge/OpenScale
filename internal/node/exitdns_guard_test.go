package node

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/dnsblock"
	"github.com/openscale/openscale/internal/filter"
)

// setGuard installs c for one test and restores the defaults afterwards.
func setGuard(t *testing.T, c ExitDNSGuardConfig, onEvent func(filter.ThreatEvent)) {
	t.Helper()
	if err := ApplyExitDNSGuard(c, onEvent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		exitGuard.Store(nil)
		exitDNSRT.hook.Store(nil)
	})
}

// answerAddr answers an A or AAAA query with addr.
func answerAddr(query []byte, addr netip.Addr, ttl uint32) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil || len(m.Questions) != 1 {
		return nil
	}
	q := m.Questions[0]
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q},
	}
	h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
	switch {
	case q.Type == dnsmessage.TypeA && addr.Is4():
		h.Type = dnsmessage.TypeA
		resp.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: addr.As4()}}}
	case q.Type == dnsmessage.TypeAAAA && addr.Is6():
		h.Type = dnsmessage.TypeAAAA
		resp.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}}}
	}
	return mustPack(resp)
}

func TestExitDNSRebindProtection(t *testing.T) {
	setGuard(t, ExitDNSGuardConfig{RebindAllow: []string{"izinli.example"}}, nil)
	addrs := map[string]netip.Addr{
		"kotu.example.":       netip.MustParseAddr("192.168.1.5"),
		"cgnat.example.":      netip.MustParseAddr("100.70.0.1"),
		"ula.example.":        netip.MustParseAddr("fd00::1"),
		"loop.example.":       netip.MustParseAddr("127.0.0.1"),
		"nat64.example.":      netip.MustParseAddr("64:ff9b::a00:1"),
		"genel.example.":      netip.MustParseAddr("192.0.2.10"),
		"nas.izinli.example.": netip.MustParseAddr("10.0.0.2"),
		"nas.lan.":            netip.MustParseAddr("10.0.0.3"),
	}
	up := newUDPUpstream(t, func(q []byte) []byte {
		var m dnsmessage.Message
		if m.Unpack(q) != nil {
			return nil
		}
		return answerAddr(q, addrs[strings.ToLower(m.Questions[0].Name.String())], 60)
	})
	f := testForwarder(t, up.addr())
	before := ExitDNSStats().Rebind
	cases := []struct {
		name    string
		typ     dnsmessage.Type
		blocked bool
	}{
		{"kotu.example.", dnsmessage.TypeA, true},
		{"cgnat.example.", dnsmessage.TypeA, true},
		{"ula.example.", dnsmessage.TypeAAAA, true},
		{"loop.example.", dnsmessage.TypeA, true},
		{"nat64.example.", dnsmessage.TypeAAAA, true},
		{"genel.example.", dnsmessage.TypeA, false},
		{"nas.izinli.example.", dnsmessage.TypeA, false},
		{"nas.lan.", dnsmessage.TypeA, false},
	}
	for _, c := range cases {
		out, err := f.forward(context.Background(), dnsQuery(t, 5, c.name, c.typ, 1232))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		m := unpack(t, out)
		got := m.RCode == dnsmessage.RCodeNameError && len(m.Answers) == 0
		if got != c.blocked {
			t.Fatalf("%s: blocked %v, want %v (%+v)", c.name, got, c.blocked, m.Header)
		}
	}
	if ExitDNSStats().Rebind-before != 5 {
		t.Fatalf("rebind count %d", ExitDNSStats().Rebind-before)
	}
	// Turned off: the private answer passes.
	setGuard(t, ExitDNSGuardConfig{RebindOff: true}, nil)
	out, err := f.forward(context.Background(), dnsQuery(t, 6, "kotu.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpack(t, out); len(m.Answers) != 1 {
		t.Fatal("rebind_off must pass private answers")
	}
}

// ecsQuery is a query with an EDNS Client Subnet option.
func ecsQuery(t *testing.T) []byte {
	t.Helper()
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 9, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{
			{Code: optionECS, Data: []byte{0, 1, 24, 0, 198, 51, 100}},
			{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, // cookie: kept
		}}}},
	}
	return mustPack(m)
}

func optOptions(t *testing.T, msg []byte) []dnsmessage.Option {
	t.Helper()
	m := unpack(t, msg)
	for _, rr := range m.Additionals {
		if o, ok := rr.Body.(*dnsmessage.OPTResource); ok {
			return o.Options
		}
	}
	return nil
}

func TestPrepareUpstreamECSAndPadding(t *testing.T) {
	q := ecsQuery(t)
	plain := prepareUpstream(q, upstreamUDP)
	opts := optOptions(t, plain)
	if len(opts) != 1 || opts[0].Code != 10 {
		t.Fatalf("UDP: ECS must go and nothing be padded: %+v", opts)
	}
	for _, kind := range []upstreamKind{upstreamDoT, upstreamDoH} {
		padded := prepareUpstream(q, kind)
		if len(padded)%paddingBlock != 0 {
			t.Fatalf("kind %d: length %d is not a multiple of %d", kind, len(padded), paddingBlock)
		}
		opts := optOptions(t, padded)
		var codes []uint16
		for _, o := range opts {
			codes = append(codes, o.Code)
		}
		if len(opts) != 2 || opts[0].Code != 10 || opts[1].Code != optionPadding {
			t.Fatalf("kind %d: options %v", kind, codes)
		}
		if m := unpack(t, padded); m.Questions[0].Name.String() != "a.example." || m.ID != 9 {
			t.Fatal("question or ID changed")
		}
	}
	noEDNS := dnsQuery(t, 3, "b.example.", dnsmessage.TypeA, 0)
	if string(prepareUpstream(noEDNS, upstreamDoT)) != string(noEDNS) {
		t.Fatal("a query without EDNS must be sent unchanged")
	}
	// The forwarder sends the stripped query.
	var seen atomic.Bool
	up := newUDPUpstream(t, func(q []byte) []byte {
		for _, o := range optOptions(t, q) {
			if o.Code == optionECS {
				seen.Store(true)
			}
		}
		return answerFor(q, 1, 30)
	})
	f := testForwarder(t, up.addr())
	if _, err := f.forward(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if seen.Load() {
		t.Fatal("ECS reached the upstream resolver")
	}
}

func TestExitDNSServeStaleAndPrefetch(t *testing.T) {
	var fail atomic.Bool
	up := newUDPUpstream(t, func(q []byte) []byte {
		if fail.Load() {
			return failureAnswer(q)
		}
		return answerFor(q, 1, 100)
	})
	f := testForwarder(t, up.addr())
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	ctx := context.Background()
	ask := func() dnsmessage.Message {
		t.Helper()
		out, err := f.forward(ctx, dnsQuery(t, 1, "bayat.example.", dnsmessage.TypeA, 0))
		if err != nil {
			t.Fatal(err)
		}
		return unpack(t, out)
	}

	// Off: an upstream failure is passed on.
	setGuard(t, ExitDNSGuardConfig{}, nil)
	ask()
	advance(150 * time.Second)
	fail.Store(true)
	if m := ask(); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("serve-stale off: rcode %v", m.RCode)
	}

	// On: the expired entry is served with a 30 s TTL.
	setGuard(t, ExitDNSGuardConfig{ServeStale: true}, nil)
	fail.Store(false)
	advance(200 * time.Second)
	ask() // fresh entry
	advance(150 * time.Second)
	fail.Store(true)
	m := ask()
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 || m.Answers[0].Header.TTL != staleAnswerTTL {
		t.Fatalf("stale answer %+v", m)
	}
	advance(staleWindow)
	if m := ask(); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("an entry older than the stale window must not be served")
	}

	// Prefetch: a busy entry close to expiry is refreshed in the background.
	fail.Store(false)
	advance(time.Second)
	ask() // fresh, TTL 100
	ask() // hit 1
	advance(95 * time.Second)
	before := up.queries.Load()
	ask() // hit 2, 5 s left: refresh
	deadline := time.Now().Add(3 * time.Second)
	for up.queries.Load() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if up.queries.Load() == before {
		t.Fatal("busy entry was not prefetched")
	}
}

func TestExitDNSRateLimit(t *testing.T) {
	var events []filter.ThreatEvent
	var mu sync.Mutex
	setGuard(t, ExitDNSGuardConfig{RateLimit: 1}, func(ev filter.ThreatEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	f := testForwarder(t, "127.0.0.1:9")
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { return now }
	client := exitClient{name: "hizli-telefon"}
	q := dnsQuery(t, 1, dohCanary, dnsmessage.TypeA, 0)
	for i := 0; i < exitDNSBurstFactor; i++ {
		if _, err := f.forwardFrom(context.Background(), client, q, false); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := f.forwardFrom(context.Background(), client, q, false); !errors.Is(err, errExitDNSRateLimited) {
			t.Fatalf("over the limit: %v", err)
		}
	}
	// Another device has its own bucket.
	if _, err := f.forwardFrom(context.Background(), exitClient{name: "baska"}, q, false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := f.forwardFrom(context.Background(), client, q, false); err != nil {
		t.Fatal("tokens must refill")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || events[0].Kind != ThreatDNSRateLimit || events[0].Peer != "hizli-telefon" {
		t.Fatalf("events %+v", events)
	}
}

func TestSuspiciousName(t *testing.T) {
	cases := map[string]bool{
		"www.example.com.": false,
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.tunnel.example.":      true,
		"mzxw6ytboi4dsnzrgiztkmbvgyztkmrqgm2dgnbr.t.example.co.uk.": true,
		"this-is-a-long-but-readable-hostname-here.example.com.":    false,
		"cdn.example.":                          false,
		"kxq9z2vj7wplm3ntr8ycbf6dh4sa1b2c.t.e.": true,
	}
	for name, want := range cases {
		if _, got := suspiciousName(name); got != want {
			t.Fatalf("%s: %v (entropy %.2f)", name, got, shannon(strings.ReplaceAll(name, ".", "")))
		}
	}
	if base, _ := suspiciousName("mzxw6ytboi4dsnzrgiztkmbvgyztkmrqgm2dgnbr.t.example.co.uk."); base != "example.co.uk." {
		t.Fatalf("base %q", base)
	}
}

func TestExitDNSTunnelDetection(t *testing.T) {
	var events atomic.Int32
	setGuard(t, ExitDNSGuardConfig{RateLimit: -1, TunnelBlock: true}, func(ev filter.ThreatEvent) {
		if ev.Kind == ThreatDNSTunnel && !ev.BlockedUntil.IsZero() {
			events.Add(1)
		}
	})
	up := newUDPUpstream(t, func(q []byte) []byte { return answerFor(q, 1, 30) })
	f := testForwarder(t, up.addr())
	client := exitClient{name: "sizdiran"}
	name := func(i int) string {
		const b32 = "abcdefghijklmnopqrstuvwxyz234567"
		r := rand.New(rand.NewPCG(uint64(i), 99))
		var sb strings.Builder
		for range 40 {
			sb.WriteByte(b32[r.IntN(len(b32))])
		}
		return sb.String() + ".veri.example."
	}
	refused := 0
	for i := 0; i < tunnelThreshold+5; i++ {
		out, err := f.forwardFrom(context.Background(), client, dnsQuery(t, 1, name(i), dnsmessage.TypeTXT, 0), false)
		if err != nil {
			t.Fatal(err)
		}
		if unpack(t, out).RCode == dnsmessage.RCodeRefused {
			refused++
		}
	}
	if events.Load() != 1 || refused == 0 {
		t.Fatalf("events %d refused %d", events.Load(), refused)
	}
	// Normal names of the same device still resolve.
	out, err := f.forwardFrom(context.Background(), client, dnsQuery(t, 1, "www.veri.example.", dnsmessage.TypeA, 0), false)
	if err != nil || unpack(t, out).RCode != dnsmessage.RCodeSuccess {
		t.Fatal("ordinary names must not be refused")
	}
}

func TestExitDNSAAAAFilter(t *testing.T) {
	old := exitGlobalIPv6
	exitGlobalIPv6 = func() bool { return false }
	t.Cleanup(func() {
		exitGlobalIPv6 = old
		exitDNSRT.mu.Lock()
		exitDNSRT.v6At = time.Time{}
		exitDNSRT.mu.Unlock()
	})
	exitDNSRT.mu.Lock()
	exitDNSRT.v6At = time.Time{}
	exitDNSRT.mu.Unlock()
	up := newUDPUpstream(t, func(q []byte) []byte { return answerAddr(q, netip.MustParseAddr("2001:db8::1"), 60) })
	f := testForwarder(t, up.addr())
	client := exitClient{name: "v6siz"}
	ask := func() dnsmessage.Message {
		out, err := f.forwardFrom(context.Background(), client, dnsQuery(t, 1, "alti.example.", dnsmessage.TypeAAAA, 1232), false)
		if err != nil {
			t.Fatal(err)
		}
		return unpack(t, out)
	}
	setGuard(t, ExitDNSGuardConfig{}, nil)
	if m := ask(); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 || up.queries.Load() != 0 {
		t.Fatalf("auto without IPv6 must answer NODATA locally: %+v, %d queries", m.Header, up.queries.Load())
	}
	setGuard(t, ExitDNSGuardConfig{AAAA: "keep"}, nil)
	if m := ask(); len(m.Answers) != 1 {
		t.Fatal("keep must pass AAAA records")
	}
	exitGlobalIPv6 = func() bool { return true }
	exitDNSRT.mu.Lock()
	exitDNSRT.v6At = time.Time{}
	exitDNSRT.mu.Unlock()
	setGuard(t, ExitDNSGuardConfig{AAAA: "filter"}, nil)
	if m := ask(); len(m.Answers) != 0 {
		t.Fatal("filter must drop AAAA records")
	}
}

func TestExitDNSProfilesAndExceptions(t *testing.T) {
	dir := t.TempDir()
	cocuk := filepath.Join(dir, "cocuk.txt")
	if err := os.WriteFile(cocuk, []byte("oyun.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	global, err := dnsblock.Parse(strings.NewReader("reklam.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	SetExitDNSBlocklist(global)
	t.Cleanup(func() { SetExitDNSBlocklist(nil) })
	setGuard(t, ExitDNSGuardConfig{ProfileLists: map[string]string{"cocuk": cocuk}, RateLimit: -1}, nil)
	up := newUDPUpstream(t, func(q []byte) []byte { return answerFor(q, 1, 30) })
	f := testForwarder(t, up.addr())
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { return now }
	blocked := func(c exitClient, name string) bool {
		t.Helper()
		out, err := f.forwardFrom(context.Background(), c, dnsQuery(t, 1, name, dnsmessage.TypeA, 0), false)
		if err != nil {
			t.Fatal(err)
		}
		return unpack(t, out).RCode == dnsmessage.RCodeNameError
	}
	child := exitClient{name: "tablet", profile: "cocuk"}
	server := exitClient{name: "sunucu", noBlocklist: true}
	plain := exitClient{name: "laptop"}
	unknown := exitClient{name: "x", profile: "listesiz"}
	if !blocked(child, "oyun.example.") || blocked(child, "reklam.example.") {
		t.Fatal("profile list must replace the default list")
	}
	if blocked(server, "reklam.example.") || !blocked(plain, "reklam.example.") || !blocked(unknown, "reklam.example.") {
		t.Fatal("no_blocklist, default and unmapped profiles")
	}
	if _, err := ExitDNSAllowFor("reklam.example", 15*time.Minute, now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ExitDNSRevokeException("reklam.example") })
	if blocked(plain, "x.reklam.example.") {
		t.Fatal("timed exception must open the name and its subdomains")
	}
	if l := ExitDNSExceptions(now); len(l) != 1 || l[0].Name != "reklam.example." {
		t.Fatalf("exceptions %+v", l)
	}
	now = now.Add(16 * time.Minute)
	if !blocked(plain, "reklam.example.") || len(ExitDNSExceptions(now)) != 0 {
		t.Fatal("exception must close by itself")
	}
	for _, d := range []time.Duration{time.Second, 25 * time.Hour} {
		if _, err := ExitDNSAllowFor("reklam.example", d, now); err == nil {
			t.Fatalf("duration %v must be refused", d)
		}
	}
	if _, err := ExitDNSAllowFor("com", time.Hour, now); err == nil {
		t.Fatal("a top-level domain must be refused")
	}
}

func TestExitDNSQueryLog(t *testing.T) {
	setGuard(t, ExitDNSGuardConfig{RateLimit: -1}, nil)
	f := testForwarder(t, "127.0.0.1:9")
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { return now }
	q := dnsQuery(t, 1, dohCanary, dnsmessage.TypeA, 0)
	if _, err := f.forwardFrom(context.Background(), exitClient{name: "a"}, q, false); err != nil {
		t.Fatal(err)
	}
	if l, until := ExitDNSQueryLog(now); len(l) != 0 || !until.IsZero() {
		t.Fatal("the log is off by default")
	}
	if _, err := SetExitDNSQueryLog(2*time.Hour, now); err == nil {
		t.Fatal("more than an hour must be refused")
	}
	if _, err := SetExitDNSQueryLog(30*time.Minute, now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = SetExitDNSQueryLog(0, now) })
	if _, err := f.forwardFrom(context.Background(), exitClient{name: "telefon"}, q, false); err != nil {
		t.Fatal(err)
	}
	l, until := ExitDNSQueryLog(now)
	if len(l) != 1 || l[0].Device != "telefon" || l[0].Name != dohCanary || l[0].Decision != DecisionCanary || l[0].Type != "A" || !until.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("log %+v until %v", l, until)
	}
	// Expiry deletes the entries.
	now = now.Add(31 * time.Minute)
	if l, until := ExitDNSQueryLog(now); len(l) != 0 || !until.IsZero() {
		t.Fatal("an expired log must be deleted")
	}
	if _, err := SetExitDNSQueryLog(time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.forwardFrom(context.Background(), exitClient{name: "telefon"}, q, false); err != nil {
		t.Fatal(err)
	}
	if _, err := SetExitDNSQueryLog(0, now); err != nil {
		t.Fatal(err)
	}
	if l, _ := ExitDNSQueryLog(now); len(l) != 0 {
		t.Fatal("turning the log off must delete it")
	}
}

func TestExitDNSSafeSearch(t *testing.T) {
	mapFile := filepath.Join(t.TempDir(), "guvenli.txt")
	if err := os.WriteFile(mapFile, []byte("www.google.com.tr forcesafesearch.google.com\nwww.bing.com strict.bing.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setGuard(t, ExitDNSGuardConfig{RateLimit: -1, SafeSearchMap: mapFile}, nil)
	var asked sync.Map
	up := newUDPUpstream(t, func(q []byte) []byte {
		var m dnsmessage.Message
		if m.Unpack(q) == nil {
			asked.Store(strings.ToLower(m.Questions[0].Name.String()), true)
		}
		return answerAddr(q, netip.MustParseAddr("216.239.38.120"), 300)
	})
	f := testForwarder(t, up.addr())
	child := exitClient{name: "cocuk-tablet", safeSearch: true}
	out, err := f.forwardFrom(context.Background(), child, dnsQuery(t, 44, "www.google.com.tr.", dnsmessage.TypeA, 1232), false)
	if err != nil {
		t.Fatal(err)
	}
	m := unpack(t, out)
	if m.ID != 44 || len(m.Answers) != 2 || m.Answers[0].Header.Type != dnsmessage.TypeCNAME || m.Questions[0].Name.String() != "www.google.com.tr." {
		t.Fatalf("safe search answer %+v", m)
	}
	if cn := m.Answers[0].Body.(*dnsmessage.CNAMEResource).CNAME.String(); cn != "forcesafesearch.google.com." {
		t.Fatalf("CNAME %s", cn)
	}
	if _, ok := asked.Load("www.google.com.tr."); ok {
		t.Fatal("the original name must not be asked")
	}
	if _, ok := asked.Load("forcesafesearch.google.com."); !ok {
		t.Fatal("the safe search name must be resolved")
	}
	out, err = f.forwardFrom(context.Background(), child, dnsQuery(t, 45, "www.bing.com.", dnsmessage.Type(65), 0), false)
	if err != nil {
		t.Fatal(err)
	}
	if m := unpack(t, out); len(m.Answers) != 0 || m.RCode != dnsmessage.RCodeSuccess {
		t.Fatal("other types of a search engine name get NODATA")
	}
	if _, ok := g0safe(t)["mail.google.com."]; ok {
		t.Fatal("only listed names are mapped")
	}
}

// g0safe is the safe search map of the installed guard.
func g0safe(t *testing.T) map[string]string {
	t.Helper()
	return currentExitGuard().safeSearch
}

func TestParseSafeSearchMap(t *testing.T) {
	in := "\xef\xbb\xbf# yorum\nWWW.Google.com  forcesafesearch.google.com.\n\nbing.com strict.bing.com # satir sonu\n"
	m, err := ParseSafeSearchMap(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["www.google.com."] != "forcesafesearch.google.com." || m["bing.com."] != "strict.bing.com." {
		t.Fatalf("%v", m)
	}
	bad := []string{
		"tek\n", "a.example b.example c.example\n", "com hedef.example\n",
		"*.a.example b.example\n", "a.example a.example\n", "a.example 10.0.0.1\n",
	}
	for _, b := range bad {
		if _, err := ParseSafeSearchMap(strings.NewReader(b)); err == nil {
			t.Fatalf("%q must be refused", b)
		}
	}
}

func TestExitDNSGuardValidate(t *testing.T) {
	bad := []ExitDNSGuardConfig{
		{RateLimit: -2},
		{RateLimit: MaxExitDNSRate + 1},
		{AAAA: "belki"},
		{RebindAllow: []string{"com"}},
		{RebindAllow: []string{"10.0.0.1"}},
		{ProfileLists: map[string]string{"Cocuk": "/x"}},
		{ProfileLists: map[string]string{"cocuk": "goreli/yol"}},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("%+v must be refused", c)
		}
	}
	if err := (ExitDNSGuardConfig{}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func FuzzExitDNSGuardParsers(f *testing.F) {
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "a.example.")
	f.Add(answerAddr(dnsQueryRaw("a.example."), netip.MustParseAddr("10.0.0.1"), 30), "x.y.z.")
	f.Fuzz(func(t *testing.T, msg []byte, name string) {
		for _, k := range []upstreamKind{upstreamUDP, upstreamDoT} {
			out := prepareUpstream(msg, k)
			if string(out) != string(msg) {
				var m dnsmessage.Message
				if err := m.Unpack(out); err != nil {
					t.Fatalf("rewritten query does not parse: %v", err)
				}
			}
		}
		_ = privateAnswer(msg)
		_, _ = suspiciousName(name)
		if n, ok := normalizeDomain(name); ok && !strings.HasSuffix(n, ".") {
			t.Fatal("normalized name without the root dot")
		}
		_, _ = ParseSafeSearchMap(strings.NewReader(name))
	})
}
