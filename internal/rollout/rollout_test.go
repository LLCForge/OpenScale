package rollout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time             { return c.t }
func (c *clock) add(d time.Duration) *clock { c.t = c.t.Add(d); return c }

const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var members = []Member{{"c1", RingCanary}, {"c2", RingCanary}, {"e1", RingEarly}, {"m1", RingMain}, {"m2", RingMain}}

func ok(v string) *Report { return &Report{V: 1, Run: v, OK: true} }

func TestRingOf(t *testing.T) {
	for _, c := range []struct {
		tags []string
		want string
	}{
		{nil, RingMain}, {[]string{"sunucu"}, RingMain}, {[]string{TagMain}, RingMain},
		{[]string{TagEarly}, RingEarly}, {[]string{TagEarly, TagCanary}, RingCanary},
	} {
		if got := RingOf(c.tags); got != c.want {
			t.Errorf("RingOf(%v) = %s, want %s", c.tags, got, c.want)
		}
	}
}

// TestProgressNeedsTimeAndHealth: a ring opens only after a healthy device
// of the previous ring ran the release for the soak time, measured on the
// coordinator's clock between two reports.
func TestProgressNeedsTimeAndHealth(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)}
	tr := NewTracker(t.TempDir(), c.now)
	a := tr.Observe(digest, "1.0.1", members, "", nil)
	if a.Open != RingCanary || a.Halted {
		t.Fatalf("start: %+v", a)
	}
	tr.Observe(digest, "1.0.1", members, "c1", ok("1.0.1"))
	// One report long after installing is not a soak: the first report
	// starts it.
	c.add(5 * time.Hour)
	if a = tr.Observe(digest, "1.0.1", members, "c1", ok("1.0.1")); a.Open != RingCanary {
		t.Fatalf("5h: %+v", a)
	}
	// Another canary device reports unhealthy: the ring is blocked.
	tr.Observe(digest, "1.0.1", members, "c2", &Report{V: 1, Run: "1.0.1", OK: false})
	c.add(time.Hour)
	if a = tr.Observe(digest, "1.0.1", members, "c1", ok("1.0.1")); a.Open != RingCanary {
		t.Fatalf("6h with an unhealthy canary: %+v", a)
	}
	// Healthy again: its soak starts over, c1's soak already passed.
	tr.Observe(digest, "1.0.1", members, "c2", ok("1.0.1"))
	if a = tr.Observe(digest, "1.0.1", members, "c1", ok("1.0.1")); a.Open != RingEarly || a.EarlyAt.IsZero() {
		t.Fatalf("canary passed: %+v", a)
	}
	// Early needs its own soak (24h).
	tr.Observe(digest, "1.0.1", members, "e1", ok("1.0.1"))
	c.add(23 * time.Hour)
	if a = tr.Observe(digest, "1.0.1", members, "e1", ok("1.0.1")); a.Open != RingEarly {
		t.Fatalf("early 23h: %+v", a)
	}
	c.add(time.Hour)
	a = tr.Observe(digest, "1.0.1", members, "e1", ok("1.0.1"))
	if a.Open != RingMain || a.MainAt.IsZero() {
		t.Fatalf("early passed: %+v", a)
	}
	if r := a.Rings[0]; r.Members != 2 || r.Updated != 2 || r.Healthy != 2 {
		t.Fatalf("canary counts %+v", r)
	}
	// The progress survives a coordinator restart.
	tr2 := NewTracker(tr.dir, c.now)
	if a := tr2.Observe(digest, "1.0.1", members, "", nil); a.Open != RingMain {
		t.Fatalf("after restart: %+v", a)
	}
	// A new publication starts over.
	other := strings.Repeat("b", 64)
	if a := tr2.Observe(other, "1.0.2", members, "", nil); a.Open != RingCanary || !a.EarlyAt.IsZero() {
		t.Fatalf("new release: %+v", a)
	}
}

// TestEmptyRingsAreSkipped: a network without ring tags behaves as before.
func TestEmptyRingsAreSkipped(t *testing.T) {
	c := &clock{t: time.Now()}
	tr := NewTracker("", c.now)
	if a := tr.Observe(digest, "1.0.1", []Member{{"m1", RingMain}}, "", nil); a.Open != RingMain {
		t.Fatalf("no rings: %+v", a)
	}
	// Only early devices: canary is skipped, early gates main.
	tr = NewTracker("", c.now)
	if a := tr.Observe(digest, "1.0.1", []Member{{"e1", RingEarly}, {"m1", RingMain}}, "", nil); a.Open != RingEarly {
		t.Fatalf("early only: %+v", a)
	}
}

// TestRollbackHaltsAndResume: a rollback halts the release for every ring;
// the owner's resume lifts it until a new rollback.
func TestRollbackHaltsAndResume(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	tr := NewTracker(dir, c.now)
	tr.Observe(digest, "1.0.1", members, "c1", ok("1.0.1"))
	a := tr.Observe(digest, "1.0.1", members, "c1", &Report{V: 1, Run: "1.0.0", OK: true, RolledBack: "1.0.1"})
	if !a.Halted || a.HaltRing != RingCanary || a.Rings[0].RolledBack != 1 {
		t.Fatalf("not halted: %+v", a)
	}
	// A rollback of another version does not count.
	tr3 := NewTracker("", c.now)
	if a := tr3.Observe(digest, "1.0.1", members, "c1", &Report{V: 1, Run: "1.0.0", OK: true, RolledBack: "0.9.9"}); a.Halted {
		t.Fatalf("old rollback halted: %+v", a)
	}
	if st, err := ReadState(dir); err != nil || !st.Halted || st.HaltedAt.IsZero() {
		t.Fatalf("saved %+v %v", st, err)
	}
	c.add(time.Minute)
	if err := WriteSettings(dir, Settings{CanarySoak: Duration(DefaultCanarySoak), EarlySoak: Duration(DefaultEarlySoak), ResumeDigest: digest, ResumedAt: c.t}); err != nil {
		t.Fatal(err)
	}
	c.add(2 * time.Minute) // the tracker reads the settings once a minute
	if a := tr.Observe(digest, "1.0.1", members, "", nil); a.Halted {
		t.Fatalf("resume ignored: %+v", a)
	}
	// A new rollback after the resume halts again.
	c.add(time.Minute)
	if a := tr.Observe(digest, "1.0.1", members, "c2", &Report{V: 1, Run: "1.0.0", OK: true, RolledBack: "1.0.1"}); !a.Halted {
		t.Fatalf("new rollback ignored: %+v", a)
	}
}

// TestDevicesOutsideTheDocument: a device not in the document (or one that
// left) moves nothing.
func TestDevicesOutsideTheDocument(t *testing.T) {
	c := &clock{t: time.Now()}
	tr := NewTracker("", c.now)
	tr.Observe(digest, "1.0.1", members, "x9", &Report{V: 1, Run: "1.0.0", RolledBack: "1.0.1"})
	if a := tr.Observe(digest, "1.0.1", members, "", nil); a.Halted {
		t.Fatalf("stranger halted the release: %+v", a)
	}
	tr.Observe(digest, "1.0.1", members, "c1", &Report{V: 1, Run: "1.0.0", RolledBack: "1.0.1"})
	if a := tr.Observe(digest, "1.0.1", members[1:], "", nil); a.Halted {
		t.Fatalf("a removed device still halts: %+v", a)
	}
}

func TestWireFormats(t *testing.T) {
	a := Announcement{Open: RingEarly, Halted: true, HaltRing: RingCanary, CanarySoak: 6 * time.Hour, EarlySoak: 24 * time.Hour,
		Since: time.Unix(1_800_000_000, 0).UTC(), EarlyAt: time.Unix(1_800_021_600, 0).UTC(),
		Rings: []RingCount{{RingCanary, 4000, 4000, 3999, 1}, {RingEarly, 4000, 10, 10, 0}, {RingMain, 4000, 0, 0, 0}}}
	data, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Room in a 1200-byte datagram next to the release fields.
	if len(data) > 200 {
		t.Fatalf("announcement is %d bytes", len(data))
	}
	b, err := DecodeAnnouncement(data)
	if err != nil || b.Open != a.Open || !b.Halted || b.HaltRing != RingCanary || b.EarlySoak != a.EarlySoak || !b.EarlyAt.Equal(a.EarlyAt) || len(b.Rings) != 3 || b.Rings[0].RolledBack != 1 {
		t.Fatalf("round trip %+v %v", b, err)
	}
	for _, bad := range []string{
		``, `{}`, `{"v":1,"o":3,"cs":1,"es":1,"s":1}`, `{"v":1,"o":0,"cs":-1,"es":1,"s":1}`,
		`{"v":1,"o":0,"cs":1,"es":1,"s":1,"x":1}`, `{"v":2,"o":0,"cs":1,"es":1,"s":1}`,
		`{"v":1,"o":0,"cs":1,"es":1,"s":1,"n":[[1,1,1,1],[1,1,1,1],[1,1,1,1],[1,1,1,1]]}`,
		`{"v":1,"o":0,"cs":1,"es":1,"s":1} {}`, strings.Repeat(" ", 500),
	} {
		if _, err := DecodeAnnouncement([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	r, err := Report{Run: "1.0.1", OK: true, RolledBack: "1.0.0"}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeReport(r); err != nil || got.Run != "1.0.1" || got.RolledBack != "1.0.0" || !got.OK {
		t.Fatalf("report %+v %v", got, err)
	}
	for _, bad := range []string{`{"v":1,"run":""}`, `{"v":1,"run":"a b"}`, `{"v":1,"run":"1","zz":1}`, `{"v":0,"run":"1"}`} {
		if _, err := DecodeReport([]byte(bad)); err == nil {
			t.Errorf("accepted report %q", bad)
		}
	}
}

func TestSettingsFile(t *testing.T) {
	dir := t.TempDir()
	if s, err := ReadSettings(dir); err != nil || time.Duration(s.CanarySoak) != DefaultCanarySoak {
		t.Fatalf("defaults %+v %v", s, err)
	}
	if err := WriteSettings(dir, Settings{CanarySoak: Duration(time.Minute), EarlySoak: Duration(time.Hour)}); err == nil {
		t.Fatal("soak below the minimum accepted")
	}
	if err := WriteSettings(dir, Settings{CanarySoak: Duration(2 * time.Hour), EarlySoak: Duration(48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSettings(dir); err != nil || time.Duration(s.EarlySoak) != 48*time.Hour {
		t.Fatalf("read %+v %v", s, err)
	}
	if err := os.WriteFile(filepath.Join(dir, SettingsFile), []byte(`{"schema":1,"canarySoak":"1s","earlySoak":"1h0m0s"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSettings(dir); err == nil || time.Duration(s.CanarySoak) != DefaultCanarySoak {
		t.Fatalf("damaged settings: %+v %v", s, err)
	}
}

// TestDecide: the device's own floor bounds what a coordinator can open.
func TestDecide(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	open := func(ring string) *Announcement {
		return &Announcement{Open: ring, CanarySoak: time.Second, EarlySoak: time.Second}
	}
	cases := []struct {
		name string
		g    Gate
		want string
	}{
		{"canary installs at once", Gate{Ring: RingCanary, Canary: 1, Early: 1, Ann: open(RingCanary), FirstSeen: t0, Now: t0}, WaitNone},
		{"early waits for the coordinator", Gate{Ring: RingEarly, Canary: 1, Ann: open(RingCanary), FirstSeen: t0, Now: t0.Add(48 * time.Hour)}, WaitRing},
		// A coordinator opening every ring at once with tiny soaks: the
		// floor is clamped to MinSoak per earlier ring.
		{"lying coordinator, early", Gate{Ring: RingEarly, Canary: 1, Ann: open(RingMain), FirstSeen: t0, Now: t0.Add(59 * time.Minute)}, WaitFloor},
		{"lying coordinator, main", Gate{Ring: RingMain, Canary: 1, Early: 1, Ann: open(RingMain), FirstSeen: t0, Now: t0.Add(119 * time.Minute)}, WaitFloor},
		{"lying coordinator, main after the floor", Gate{Ring: RingMain, Canary: 1, Early: 1, Ann: open(RingMain), FirstSeen: t0, Now: t0.Add(2 * time.Hour)}, WaitNone},
		{"halt", Gate{Ring: RingCanary, Canary: 1, Ann: &Announcement{Open: RingMain, Halted: true}, FirstSeen: t0, Now: t0}, WaitHalted},
		// An older coordinator: the default soaks since first sight.
		{"old coordinator, main", Gate{Ring: RingMain, Canary: 1, Early: 1, FirstSeen: t0, Now: t0.Add(29 * time.Hour)}, WaitFloor},
		{"old coordinator, main later", Gate{Ring: RingMain, Canary: 1, Early: 1, FirstSeen: t0, Now: t0.Add(30 * time.Hour)}, WaitNone},
		{"no rings in the network", Gate{Ring: RingMain, FirstSeen: t0, Now: t0}, WaitNone},
		{"unknown ring is main", Gate{Ring: "x", Canary: 1, Ann: open(RingEarly), FirstSeen: t0, Now: t0.Add(time.Hour)}, WaitRing},
	}
	for _, c := range cases {
		if got := Decide(c.g); got.Wait != c.want {
			t.Errorf("%s: wait %q, want %q (%+v)", c.name, got.Wait, c.want, got)
		}
	}
}
