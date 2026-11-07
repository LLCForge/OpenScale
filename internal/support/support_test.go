package support

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMask(t *testing.T) {
	cases := map[string]string{
		`C:\Users\Ayşe\AppData\Local\app.exe`:  `C:\Users\***\AppData\Local\app.exe`,
		`/home/ali/.config/x`:                  `/home/***/.config/x`,
		`mail ali.veli@example.com failed`:     `mail a***@example.com failed`,
		`from 192.168.1.42 port 22`:            `from 192.168.***.*** port 22`,
		`Account Name:  bob  Logon`:            `Account Name: *** Logon`,
		`sid S-1-5-21-1004336348-1177238915-1`: `sid S-1-5-21-***`,
		`peer fd7a:115c:a1e0::5 up`:            `peer ***:*** up`,
		`at 12:30:45 ok`:                       `at 12:30:45 ok`,
		`mac aa:bb:cc:dd:ee:ff`:                `mac aa:bb:cc:**:**:**`,
		`sudo: user=ali tty`:                   `sudo: user=*** tty`,
	}
	for in, want := range cases {
		if got := clean(in, 512); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("ğ", 400)
	if got := clean(long, 100); len(got) > 100+len("…") || !strings.HasSuffix(got, "…") {
		t.Fatalf("cut: %d bytes", len(got))
	}
	if clean("a\x00b\x1bc\nd", 64) != "abc d" {
		t.Fatal("control characters must go")
	}
}

type fakeCollector struct {
	killed atomic.Int32
	big    bool
}

func (f *fakeCollector) Processes(context.Context) ([]Process, error) {
	n := 3
	if f.big {
		n = MaxProcesses + 50
	}
	out := make([]Process, n)
	for i := range out {
		out[i] = Process{PID: 100 + i, Name: `C:\Users\ali\x.exe`, MemoryKB: uint64(i)}
	}
	return out, nil
}
func (f *fakeCollector) Services(context.Context) ([]Service, error) {
	return []Service{{Name: "b"}, {Name: "a", State: "running"}}, nil
}
func (f *fakeCollector) Events(context.Context) ([]Event, error) {
	return []Event{{Time: time.Unix(1, 0), Level: "error", Source: "x", Message: "login by ali@example.com from 10.1.2.3"}}, nil
}
func (f *fakeCollector) Disks(context.Context) ([]Disk, error) {
	return []Disk{{Mount: "/", TotalBytes: 10, FreeBytes: 5}}, nil
}
func (f *fakeCollector) Startup(context.Context) ([]StartupItem, error) { return nil, nil }
func (f *fakeCollector) Kill(_ context.Context, pid int, name string) error {
	if err := checkKill(pid, name); err != nil {
		return err
	}
	f.killed.Add(1)
	return nil
}

type harness struct {
	srv      *Server
	addr     netip.AddrPort
	client   *Client
	coll     *fakeCollector
	mu       sync.Mutex
	allow    map[Mode]bool
	consent  bool
	asked    []Request
	frames   int
	closed   int
	frameErr error
	now      time.Time
	events   []LogEvent
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{coll: &fakeCollector{}, allow: map[Mode]bool{ModeRead: true}, consent: true, now: time.Now()}
	srv, err := New(Config{
		Authorize: func(remote netip.Addr, mode Mode) Decision {
			h.mu.Lock()
			defer h.mu.Unlock()
			if !remote.IsLoopback() {
				return Decision{Reason: "not a device"}
			}
			return Decision{Allowed: h.allow[mode], Peer: "laptop"}
		},
		Consent: func(_ context.Context, r Request) (bool, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.asked = append(h.asked, r)
			return h.consent, nil
		},
		Indicator: func(SessionInfo) (Indicator, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.frameErr != nil {
				return nil, h.frameErr
			}
			h.frames++
			return closer{h}, nil
		},
		Collector: h.coll,
		OnEvent: func(ev LogEvent) {
			h.mu.Lock()
			h.events = append(h.events, ev)
			h.mu.Unlock()
		},
		Now: func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	h.srv, h.addr, h.client = srv, netip.MustParseAddrPort(ln.Addr().String()), NewClient(nil)
	return h
}

type closer struct{ h *harness }

func (c closer) Close() error {
	c.h.mu.Lock()
	c.h.closed++
	c.h.mu.Unlock()
	return nil
}

func TestServerNeedsAuthorizeConsentIndicator(t *testing.T) {
	ok := func(netip.Addr, Mode) Decision { return Decision{} }
	yes := func(context.Context, Request) (bool, error) { return true, nil }
	ind := func(SessionInfo) (Indicator, error) { return nil, nil }
	for _, cfg := range []Config{{Consent: yes, Indicator: ind}, {Authorize: ok, Indicator: ind}, {Authorize: ok, Consent: yes}} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("config %+v accepted", cfg)
		}
	}
	srv, _ := New(Config{Authorize: ok, Consent: yes, Indicator: ind})
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("a listener on every interface must be refused")
	}
}

func TestSnapshotOverLoopback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	snap, err := h.client.Snapshot(ctx, h.addr, KindProcesses)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) != 3 || snap.Processes[0].Name != `C:\Users\***\x.exe` || snap.Processes[0].MemoryKB != 2 {
		t.Fatalf("processes: %+v", snap.Processes)
	}
	ev, err := h.client.Snapshot(ctx, h.addr, KindEvents)
	if err != nil {
		t.Fatal(err)
	}
	if m := ev.Events[0].Message; strings.Contains(m, "ali@") || strings.Contains(m, "10.1.2.3") {
		t.Fatalf("personal data leaked: %q", m)
	}
	svc, _ := h.client.Snapshot(ctx, h.addr, KindServices)
	if svc.Services[0].Name != "a" {
		t.Fatal("services must be sorted")
	}
	h.mu.Lock()
	asked, frames := len(h.asked), h.frames
	h.mu.Unlock()
	if asked != 1 || frames != 1 {
		t.Fatalf("one consent and one indicator per session, got %d and %d", asked, frames)
	}
	if got := h.srv.Sessions(); len(got) != 1 || got[0].Peer != "laptop" || got[0].Kill {
		t.Fatalf("sessions: %+v", got)
	}
	if _, err := h.client.Snapshot(ctx, h.addr, "secrets"); err == nil {
		t.Fatal("unknown kind")
	}
	if err := h.client.End(ctx, h.addr); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed != 1 || len(h.srv.Sessions()) != 0 {
		t.Fatal("End must close the indicator")
	}
}

func TestBigSnapshotTruncated(t *testing.T) {
	h := newHarness(t)
	h.coll.big = true
	snap, err := h.client.Snapshot(context.Background(), h.addr, KindProcesses)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Truncated || len(snap.Processes) != MaxProcesses {
		t.Fatalf("truncated %v, %d", snap.Truncated, len(snap.Processes))
	}
}

func TestConsentRefusedAndIndicatorRequired(t *testing.T) {
	h := newHarness(t)
	h.consent = false
	var re *RemoteError
	if _, err := h.client.Snapshot(context.Background(), h.addr, KindDisks); !errors.As(err, &re) || re.Status != http.StatusForbidden {
		t.Fatalf("refused consent: %v", err)
	}
	h.mu.Lock()
	h.consent, h.frameErr = true, errors.New("no screen")
	h.mu.Unlock()
	if _, err := h.client.Snapshot(context.Background(), h.addr, KindDisks); !errors.As(err, &re) || re.Status != http.StatusServiceUnavailable {
		t.Fatalf("no indicator, no session: %v", err)
	}
	if len(h.srv.Sessions()) != 0 {
		t.Fatal("a session without indicator must not exist")
	}
}

func TestKillIsSeparatePermission(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.client.Snapshot(ctx, h.addr, KindProcesses); err != nil {
		t.Fatal(err)
	}
	var re *RemoteError
	if err := h.client.Kill(ctx, h.addr, 4321, "notepad.exe"); !errors.As(err, &re) || re.Status != http.StatusForbidden {
		t.Fatalf("kill without support.kill: %v", err)
	}
	h.mu.Lock()
	h.allow[ModeKill] = true
	h.mu.Unlock()
	if err := h.client.Kill(ctx, h.addr, 4321, "notepad.exe"); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	asked := h.asked
	frames := h.frames
	h.mu.Unlock()
	if len(asked) != 2 || !asked[1].Kill || frames != 1 {
		t.Fatalf("kill needs its own consent on the same indicator: %+v, frames %d", asked, frames)
	}
	for _, name := range []string{"lsass.exe", "svchost.exe", "systemd", "openscale.exe"} {
		if err := h.client.Kill(ctx, h.addr, 999, name); !errors.As(err, &re) || re.Status != http.StatusForbidden {
			t.Fatalf("protected %s: %v", name, err)
		}
	}
	if h.coll.killed.Load() != 1 {
		t.Fatal("exactly one kill")
	}
}

func TestReapIdleAndWithdrawn(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.Snapshot(context.Background(), h.addr, KindDisks); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.allow[ModeRead] = false
	h.mu.Unlock()
	h.srv.reap()
	if len(h.srv.Sessions()) != 0 {
		t.Fatal("a withdrawn rule ends the session")
	}
	h.mu.Lock()
	h.allow[ModeRead] = true
	h.mu.Unlock()
	if _, err := h.client.Snapshot(context.Background(), h.addr, KindDisks); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.now = h.now.Add(DefaultIdle + time.Second)
	h.mu.Unlock()
	h.srv.reap()
	if len(h.srv.Sessions()) != 0 {
		t.Fatal("an idle session ends")
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < rateLimit; i++ {
		if !h.srv.allowRate("x") {
			t.Fatal("under the limit")
		}
	}
	if h.srv.allowRate("x") {
		t.Fatal("over the limit")
	}
}

func TestClientDistrustsRemote(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("kind") {
		case KindProcesses:
			w.Write([]byte(`{"kind":"processes","collected_at":"2026-01-01T00:00:00Z","truncated":false,"processes":[{"pid":1,"name":"/home/eve/x","memory_kb":1}],"extra":1}`))
		case KindDisks:
			w.Write([]byte(`{"kind":"disks","collected_at":"2026-01-01T00:00:00Z","truncated":false,"disks":[{"mount":"/home/eve","total_bytes":1,"free_bytes":1}]}`))
		default:
			w.Write([]byte(strings.Repeat("x", MaxResponse+10)))
		}
	}))
	defer ts.Close()
	addr := netip.MustParseAddrPort(strings.TrimPrefix(ts.URL, "http://"))
	c := NewClient(nil)
	if _, err := c.Snapshot(context.Background(), addr, KindProcesses); err == nil {
		t.Fatal("unknown fields must be refused")
	}
	s, err := c.Snapshot(context.Background(), addr, KindDisks)
	if err != nil || s.Disks[0].Mount != "/home/***" {
		t.Fatalf("the client cleans again: %+v %v", s, err)
	}
	if _, err := c.Snapshot(context.Background(), addr, KindEvents); err == nil {
		t.Fatal("oversized answers must be refused")
	}
}

func TestSystemCollectorSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("runs system tools")
	}
	snap, err := Collect(context.Background(), System(), KindProcesses, time.Now())
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) == 0 {
		t.Fatal("no processes")
	}
	if d, err := Collect(context.Background(), System(), KindDisks, time.Now()); err != nil || len(d.Disks) == 0 {
		t.Fatalf("disks: %v %v", d.Disks, err)
	}
}
