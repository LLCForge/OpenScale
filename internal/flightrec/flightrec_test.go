package flightrec

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/bundlecrypt"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestRecorder(c *clock, maxBytes int) *Recorder {
	return New(Config{MaxBytes: maxBytes, Now: c.now, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 16))})
}

func TestMasking(t *testing.T) {
	c := &clock{t: time.Now()}
	r := newTestRecorder(c, 0)
	r.SetNames([]string{"laptop-ayse", "nas", "x"})
	key := "q0VZ0Wlq0nm6bS0LxZ2c1pB4wP9rH0nH5K3sGkQvU2c="
	log := slog.New(r.Handler(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})))
	log.Debug("handshake with laptop-ayse at 203.0.113.9:41641 key "+key,
		"peer", "nas", "endpoint", netip.MustParseAddrPort("198.51.100.4:51820"), "private_key", key, "count", 3)
	got := r.Snapshot()
	if len(got) != 1 {
		t.Fatalf("entries = %d, want 1 (debug must be recorded even when the log level is error)", len(got))
	}
	e := got[0]
	all := e.Msg + " " + e.Attrs
	for _, leak := range []string{"laptop-ayse", "203.0.113.9", "198.51.100.4", key, "peer=nas"} {
		if strings.Contains(all, leak) {
			t.Errorf("leaked %q in %q", leak, all)
		}
	}
	if !strings.Contains(e.Msg, r.MaskName("laptop-ayse")) || !strings.Contains(e.Attrs, "peer="+r.MaskName("nas")) {
		t.Errorf("names not replaced consistently: %q", all)
	}
	if !strings.Contains(all, "203.0.*.*") || !strings.Contains(e.Attrs, "count=3") {
		t.Errorf("masked record lost its useful parts: %q", all)
	}
	if e.Level != "debug" {
		t.Errorf("level = %q", e.Level)
	}
}

func TestGroupsAndBoundAttrs(t *testing.T) {
	c := &clock{t: time.Now()}
	r := newTestRecorder(c, 0)
	log := slog.New(r.Handler(nil)).With("role", "device").WithGroup("wg").With("device_name", "masa")
	log.Info("peer up", "rtt", "12ms")
	e := r.Snapshot()[0]
	if !strings.Contains(e.Attrs, "role=device") || !strings.Contains(e.Attrs, "wg.rtt=12ms") || strings.Contains(e.Attrs, "masa") {
		t.Fatalf("attrs = %q", e.Attrs)
	}
}

func TestBounds(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	r := newTestRecorder(c, MinMaxBytes)
	for range 5000 {
		r.Add(c.t, slog.LevelInfo, strings.Repeat("a", 100), nil)
	}
	st := r.Stats()
	if st.Bytes > MinMaxBytes || st.Dropped == 0 || st.Total != 5000 {
		t.Fatalf("size bound not kept: %+v", st)
	}
	c.t = c.t.Add(DefaultMaxAge + time.Second)
	r.Add(c.t, slog.LevelInfo, "new", nil)
	if got := r.Snapshot(); len(got) != 1 || got[0].Msg != "new" {
		t.Fatalf("age bound not kept: %d entries", len(got))
	}
	long := strings.Repeat("ç", 4000)
	r.Add(c.t, slog.LevelWarn, long, nil)
	if e := r.Snapshot()[1]; len(e.Msg) > maxMsg+8 {
		t.Fatalf("message not cut: %d", len(e.Msg))
	}
}

func TestStoreRoundTrip(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	r := newTestRecorder(c, 0)
	if _, err := r.Freeze(ReasonManual, "1.0.0"); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty freeze: %v", err)
	}
	if _, err := r.Freeze("../x", ""); !errors.Is(err, ErrBadReason) {
		t.Fatalf("bad reason accepted: %v", err)
	}
	r.Add(c.t, slog.LevelInfo, "tunnel down", nil)
	dir := t.TempDir()
	st, err := OpenStore(dir, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := range 3 {
		snap, err := r.Freeze(ReasonTunnelDown, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		info, err := st.Save(snap)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, info.ID)
		if i == 0 {
			c.t = c.t.Add(time.Minute)
		}
	}
	list, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != ids[2] || list[1].ID != ids[1] {
		t.Fatalf("list = %+v (ids %v); the oldest must be pruned", list, ids)
	}
	got, err := st.Open(ids[2])
	if err != nil || got.Reason != ReasonTunnelDown || len(got.Entries) != 1 || got.ID != ids[2] {
		t.Fatalf("open = %+v, %v", got, err)
	}
	if _, err := st.Open(ids[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned snapshot still opens: %v", err)
	}
	for _, bad := range []string{"../flightrec.key", "fr-x", ""} {
		if _, err := st.Open(bad); !errors.Is(err, ErrBadID) {
			t.Fatalf("Open(%q) = %v", bad, err)
		}
	}
	helper, err := bundlecrypt.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := st.Export(ids[2], helper.Private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bundlecrypt.Open(helper, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := DecodeSnapshot(plain); err != nil || s.ID != ids[2] {
		t.Fatalf("exported snapshot: %+v, %v", s, err)
	}
	// The same key is used after reopening.
	st2, err := OpenStore(dir, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Open(ids[2]); err != nil {
		t.Fatalf("reopened store: %v", err)
	}
}

func TestThrottle(t *testing.T) {
	th := Throttle{Every: 10 * time.Minute}
	now := time.Unix(1_800_000_000, 0)
	if !th.Allow(now) || th.Allow(now.Add(time.Minute)) || !th.Allow(now.Add(11*time.Minute)) {
		t.Fatal("throttle")
	}
}
