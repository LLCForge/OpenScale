package adblock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/dnsblock"
)

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

const sampleList = "\xef\xbb\xbf# hosts style\n" +
	"0.0.0.0 ads.example tracker.example # trailing comment\n" +
	"127.0.0.1 localhost\n" +
	"! adblock comment\n" +
	"[Adblock Plus 2.0]\n" +
	"||Metrics.Example.ORG^\n" +
	"||cdn.example.net^$third-party\n" +
	"||example.net/path^\n" +
	"@@||ok.ads.example^\n" +
	"*.wild.example\n" +
	"plain.example\n" +
	"com\n" +
	"192.0.2.1\n" +
	"bad_name..example\n"

func build(t *testing.T, lists map[Category]string, keep string) *Matcher {
	t.Helper()
	b := NewBuilder()
	for c, s := range lists {
		if _, err := b.AddList(c, strings.NewReader(s)); err != nil {
			t.Fatal(err)
		}
	}
	if keep != "" {
		if _, err := b.AddKeep(strings.NewReader(keep)); err != nil {
			t.Fatal(err)
		}
	}
	return b.Build()
}

func TestParseMatchesDnsblock(t *testing.T) {
	ref, err := dnsblock.Parse(strings.NewReader(sampleList))
	if err != nil {
		t.Fatal(err)
	}
	m := build(t, map[Category]string{CategoryAds: sampleList}, "")
	names := []string{"ads.example", "x.ads.example.", "tracker.example", "metrics.example.org.", "a.b.metrics.example.org",
		"wild.example", "z.wild.example", "PLAIN.example.", "ok.ads.example", "deep.ok.ads.example.", "localhost",
		"example", "cdn.example.net", "example.net", "com.", "other.example"}
	for _, n := range names {
		got, _ := m.Match(n)
		if (got != 0) != ref.Blocked(n) {
			t.Errorf("%s: adblock %v, dnsblock %v", n, got != 0, ref.Blocked(n))
		}
	}
}

func FuzzParseList(f *testing.F) {
	f.Add(sampleList, "a.ads.example")
	f.Add("||x.example^\n@@||y.x.example^\n", "y.x.example")
	f.Add("0.0.0.0 a.example b.example\n", "b.example")
	f.Fuzz(func(t *testing.T, list, q string) {
		if len(list) > 1<<16 {
			return
		}
		ref, rerr := dnsblock.Parse(strings.NewReader(list))
		b := NewBuilder()
		_, err := b.AddList(CategoryTrackers, strings.NewReader(list))
		if (rerr == nil) != (err == nil) {
			t.Fatalf("error mismatch: %v vs %v", rerr, err)
		}
		if err != nil {
			return
		}
		m := b.Build()
		got, _ := m.Match(q)
		if (got != 0) != ref.Blocked(q) {
			t.Fatalf("%q: adblock %v, dnsblock %v", q, got != 0, ref.Blocked(q))
		}
		if got != 0 && got != CategorySet(CategoryTrackers) {
			t.Fatalf("wrong category %v", got)
		}
	})
}

func TestCategoriesMergeAndKeep(t *testing.T) {
	m := build(t, map[Category]string{
		CategoryAds:         "ads.example\nshared.example\n",
		CategoryTrackers:    "||track.example^\nshared.example\n@@||ok.track.example^\n",
		CategoryMiners:      "coin.example\n",
		CategoryIoT:         "tv.example\n",
		CategoryOSTelemetry: "os.example\n",
	}, "update.os.example\n")
	cases := map[string]CategorySet{
		"a.ads.example":        SetOf(CategoryAds),
		"shared.example":       SetOf(CategoryAds, CategoryTrackers),
		"x.track.example":      SetOf(CategoryTrackers),
		"ok.track.example":     0,
		"coin.example":         SetOf(CategoryMiners),
		"api.tv.example":       SetOf(CategoryIoT),
		"os.example":           SetOf(CategoryOSTelemetry),
		"dl.update.os.example": 0,
		"other.example":        0,
	}
	for n, want := range cases {
		got, keep := m.Match(n)
		if got != want {
			t.Errorf("%s: %v, want %v", n, got.List(), want.List())
		}
		if keep != strings.HasSuffix(n, "update.os.example") {
			t.Errorf("%s: keep %v", n, keep)
		}
	}
	info := m.Info()
	if info.Names["ads"] != 2 || info.Names["trackers"] != 2 || info.Keep != 1 {
		t.Fatalf("info %+v", info)
	}
}

func TestPolicyResolutionAndExceptions(t *testing.T) {
	m := build(t, map[Category]string{
		CategoryAds:      "ads.example\n",
		CategoryTrackers: "track.example\n",
		CategoryIoT:      "tv.example\n",
	}, "")
	e := NewEngine()
	p := Policy{
		Default:          SetOf(CategoryAds),
		Tags:             map[string]CategorySet{"tag:tv": SetOf(CategoryIoT), "tag:kids": SetOf(CategoryAds, CategoryTrackers)},
		Devices:          map[string]CategorySet{"laptop": 0},
		Exceptions:       []string{"good.ads.example"},
		DeviceExceptions: map[string][]string{"phone": {"track.example"}},
	}
	if err := e.Install(m, p); err != nil {
		t.Fatal(err)
	}
	type c struct {
		dev   string
		tags  []string
		name  string
		block bool
		why   Reason
	}
	for _, tc := range []c{
		{"desk", nil, "x.ads.example", true, ReasonListed},
		{"desk", nil, "track.example", false, ReasonNone},
		{"laptop", []string{"tag:kids"}, "ads.example", false, ReasonNone},
		{"tv1", []string{"tag:tv"}, "tv.example", true, ReasonListed},
		{"tv1", []string{"tag:tv"}, "ads.example", false, ReasonNone},
		{"kid", []string{"tag:kids", "tag:tv"}, "track.example", true, ReasonListed},
		{"kid", []string{"tag:kids"}, "a.good.ads.example", false, ReasonException},
		{"phone", []string{"tag:kids"}, "track.example", false, ReasonException},
	} {
		d := e.Decide(tc.dev, tc.tags, tc.name, testNow)
		if d.Blocked != tc.block || d.Reason != tc.why {
			t.Errorf("%+v: %+v", tc, d)
		}
	}
	s := e.Stats()
	if s.Blocked["ads"] != 1 || s.Blocked["iot"] != 1 || s.Blocked["trackers"] != 1 || s.Excepted != 2 || s.Queries != 8 {
		t.Fatalf("stats %+v", s)
	}
}

func TestOSTelemetryNeedsKeepList(t *testing.T) {
	e := NewEngine()
	m := build(t, map[Category]string{CategoryOSTelemetry: "os.example\n"}, "")
	p := Policy{Tags: map[string]CategorySet{"tag:pc": SetOf(CategoryOSTelemetry)}}
	if err := e.Install(m, p); !errors.Is(err, ErrKeepListRequired) {
		t.Fatalf("err = %v", err)
	}
	m = build(t, map[Category]string{CategoryOSTelemetry: "os.example\n"}, "||update.os.example^\n")
	if err := e.Install(m, p); err != nil {
		t.Fatal(err)
	}
	if d := e.Decide("pc", []string{"tag:pc"}, "update.os.example", testNow); d.Blocked || d.Reason != ReasonKeep {
		t.Fatalf("update name: %+v", d)
	}
	if d := e.Decide("pc", []string{"tag:pc"}, "v10.os.example", testNow); !d.Blocked || d.Category != CategoryOSTelemetry {
		t.Fatalf("telemetry name: %+v", d)
	}
}

func TestAllowOnce(t *testing.T) {
	e := NewEngine()
	if err := e.Install(build(t, map[Category]string{CategoryAds: "ads.example\n"}, ""), Policy{Default: AllSet}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AllowOnceFor("phone", "ads.example", 25*time.Hour, testNow); err == nil {
		t.Fatal("too long accepted")
	}
	if _, err := e.AllowOnceFor("phone", "com", time.Minute, testNow); err == nil {
		t.Fatal("tld accepted")
	}
	a, err := e.AllowOnceFor("phone", "ADS.example.", 10*time.Minute, testNow)
	if err != nil || a.Name != "ads.example." {
		t.Fatal(a, err)
	}
	if d := e.Decide("phone", nil, "x.ads.example", testNow.Add(time.Minute)); d.Blocked || d.Reason != ReasonOnce {
		t.Fatalf("%+v", d)
	}
	if d := e.Decide("desk", nil, "ads.example", testNow.Add(time.Minute)); !d.Blocked {
		t.Fatal("other device allowed")
	}
	if d := e.Decide("phone", nil, "ads.example", testNow.Add(11*time.Minute)); !d.Blocked {
		t.Fatal("expired allow still in force")
	}
	if _, err := e.AllowOnceFor("", "ads.example", 0, testNow); err != nil {
		t.Fatal(err)
	}
	if d := e.Decide("desk", nil, "ads.example", testNow.Add(time.Minute)); d.Blocked {
		t.Fatal("network wide allow ignored")
	}
	if len(e.AllowOnces(testNow)) != 1 || !e.RevokeAllowOnce("", "ads.example") || len(e.AllowOnces(testNow)) != 0 {
		t.Fatal("list or revoke")
	}
	for i := 0; i < MaxAllowOnce; i++ {
		if _, err := e.AllowOnceFor("d", "n"+strconv.Itoa(i)+".example", time.Hour, testNow); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := e.AllowOnceFor("d", "full.example", time.Hour, testNow); err == nil {
		t.Fatal("limit not enforced")
	}
}

func TestTopIsTimedAndBounded(t *testing.T) {
	e := NewEngine()
	if err := e.Install(build(t, map[Category]string{CategoryAds: "ads.example\n"}, ""), Policy{Default: AllSet}); err != nil {
		t.Fatal(err)
	}
	e.Decide("d", nil, "a.ads.example", testNow)
	if top, _ := e.Top(10, testNow); len(top) != 0 {
		t.Fatal("names kept while off")
	}
	if _, err := e.StartTop(2*time.Hour, testNow); err == nil {
		t.Fatal("long window accepted")
	}
	if _, err := e.StartTop(time.Minute, testNow); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e.Decide("d", nil, "b.ads.example", testNow)
	}
	e.Decide("d", nil, "c.ads.example", testNow)
	top, _ := e.Top(1, testNow)
	if len(top) != 1 || top[0].Name != "b.ads.example." || top[0].Count != 3 {
		t.Fatalf("%+v", top)
	}
	if top, _ := e.Top(10, testNow.Add(time.Minute)); top != nil {
		t.Fatal("window did not close")
	}
	e.Decide("d", nil, "b.ads.example", testNow.Add(2*time.Minute))
	if top, _ := e.Top(10, testNow.Add(2*time.Minute)); top != nil {
		t.Fatal("recording after window")
	}
}

func TestPolicyJSON(t *testing.T) {
	in := `{"default":["ads","trackers"],"tags":{"tag:tv":["iot"]},"exceptions":["Good.Example"]}`
	var p Policy
	if err := json.Unmarshal([]byte(in), &p); err != nil {
		t.Fatal(err)
	}
	if p.Default != SetOf(CategoryAds, CategoryTrackers) || p.Tags["tag:tv"] != SetOf(CategoryIoT) || p.Validate() != nil {
		t.Fatalf("%+v", p)
	}
	if err := json.Unmarshal([]byte(`{"default":["ads","nope"]}`), &p); err == nil {
		t.Fatal("unknown category accepted")
	}
	out, _ := json.Marshal(SetOf(CategoryMiners, CategoryAds))
	if string(out) != `["ads","miners"]` {
		t.Fatal(string(out))
	}
	if (Policy{Exceptions: []string{"com"}}).Validate() == nil {
		t.Fatal("tld exception accepted")
	}
}

// testDir is a directory below the package's own folder (no system TEMP).
func testDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(".", ".testout-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestSubscriptionValidate(t *testing.T) {
	good := Subscription{Category: "ads", URL: "https://lists.example/ads.txt", SHA256: digest([]byte("x"))}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subscription{
		{Category: "ads", URL: "http://lists.example/a", SHA256: good.SHA256},
		{Category: "ads", URL: "https://u:p@lists.example/a", SHA256: good.SHA256},
		{Category: "ads", URL: "https://lists.example/a", SHA256: strings.ToUpper(good.SHA256)},
		{Category: "bad", URL: "https://lists.example/a", SHA256: good.SHA256},
		{Category: "ads", URL: "file:///etc/hosts", SHA256: good.SHA256},
	} {
		if s.Validate() == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	if ValidateSubscriptions([]Subscription{good, good}) == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestFetchVerifyAndDistribute(t *testing.T) {
	body := []byte("||ads.example^\n0.0.0.0 pop.example\n")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ads.txt":
			w.Write(body)
		case "/big":
			w.Header().Set("Content-Length", "40000000")
			w.WriteHeader(http.StatusOK)
		case "/plain":
			http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if !strings.HasPrefix(srv.URL, "https://127.0.0.1:") {
		t.Fatalf("server not on loopback: %s", srv.URL)
	}
	sub := Subscription{Category: "ads", URL: srv.URL + "/ads.txt", SHA256: digest(body)}
	ctx := context.Background()

	if _, _, err := (&Fetcher{Client: srv.Client()}).Fetch(ctx, sub); !errors.Is(err, ErrNotExitNode) {
		t.Fatalf("non exit node: %v", err)
	}
	f := &Fetcher{ExitNode: true, Client: srv.Client(), Timeout: 5 * time.Second}
	bad := sub
	bad.SHA256 = digest([]byte("other"))
	if _, _, err := f.Fetch(ctx, bad); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	big := Subscription{Category: "ads", URL: srv.URL + "/big", SHA256: sub.SHA256}
	if _, _, err := f.Fetch(ctx, big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("big: %v", err)
	}
	plain := Subscription{Category: "ads", URL: srv.URL + "/plain", SHA256: sub.SHA256}
	if _, _, err := f.Fetch(ctx, plain); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain redirect: %v", err)
	}
	a, data, err := f.Fetch(ctx, sub)
	if err != nil || a.Names != 2 {
		t.Fatal(a, err)
	}

	dir := testDir(t)
	a, err = WriteArtifact(dir, a, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(dir, []Artifact{a}); err != nil {
		t.Fatal(err)
	}
	m, used, err := LoadDistributed(dir, []Subscription{sub}, strings.NewReader("keep.example\n"))
	if err != nil || len(used) != 1 {
		t.Fatal(used, err)
	}
	if got, _ := m.Match("x.ads.example"); got != SetOf(CategoryAds) {
		t.Fatal("distributed list not applied")
	}
	// A digest the document no longer approves is ignored.
	other := Subscription{Category: "ads", URL: srv.URL + "/new.txt", SHA256: digest([]byte("new"))}
	m, used, err = LoadDistributed(dir, []Subscription{other}, nil)
	if err != nil || len(used) != 0 {
		t.Fatal(used, err)
	}
	if got, _ := m.Match("ads.example"); got != 0 {
		t.Fatal("unapproved list applied")
	}
	// A tampered file is refused.
	if err := os.WriteFile(filepath.Join(dir, a.File), []byte("||evil.example^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDistributed(dir, []Subscription{sub}, nil); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered: %v", err)
	}
}

func BenchmarkMatch(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 100000; i++ {
		sb.WriteString("n")
		sb.WriteString(hex.EncodeToString([]byte{byte(i), byte(i >> 8), byte(i >> 16)}))
		sb.WriteString(".ads.example\n")
	}
	bl := NewBuilder()
	if _, err := bl.AddList(CategoryAds, strings.NewReader(sb.String())); err != nil {
		b.Fatal(err)
	}
	m := bl.Build()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("deep.sub.n0a0b0c.ads.example")
	}
}
