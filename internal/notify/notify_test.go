package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testDir returns a folder inside the package (never the system
// temporary directory) and removes it afterwards.
func testDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("testdata", ".tmp", strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Join("testdata", ".tmp"))
		_ = os.Remove("testdata")
	})
	return dir
}

// newLoopbackServer serves h on 127.0.0.1 only.
func newLoopbackServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	_ = s.Listener.Close()
	s.Listener = ln
	s.Start()
	t.Cleanup(s.Close)
	return s
}

type recordChannel struct {
	name string
	mu   sync.Mutex
	got  []Message
	err  error
}

func (r *recordChannel) Name() string { return r.name }
func (r *recordChannel) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, m)
	return r.err
}

func TestDispatcherDedupeAndRepeatCount(t *testing.T) {
	ch := &recordChannel{name: "a"}
	d, err := NewDispatcher([]Route{{Channel: ch}}, DispatcherOptions{DedupeWindow: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	m := Message{Kind: "service_down", Subject: "nas", Title: "NAS düştü", At: t0}
	if r := d.Notify(context.Background(), m); r[0].Outcome != Sent {
		t.Fatalf("first: %+v", r)
	}
	m.At = t0.Add(time.Minute)
	if r := d.Notify(context.Background(), m); r[0].Outcome != Suppressed {
		t.Fatalf("repeat: %+v", r)
	}
	m.At = t0.Add(11 * time.Minute)
	if r := d.Notify(context.Background(), m); r[0].Outcome != Sent {
		t.Fatalf("after window: %+v", r)
	}
	if len(ch.got) != 2 || !strings.Contains(ch.got[1].Body, "1 kez daha") {
		t.Fatalf("repeat count not reported: %+v", ch.got)
	}
}

func TestDispatcherQuietHoursAndFlush(t *testing.T) {
	ch := &recordChannel{name: "a"}
	q := &QuietHours{Start: 23 * 60, End: 7 * 60, Location: time.UTC}
	d, _ := NewDispatcher([]Route{{Channel: ch}}, DispatcherOptions{DedupeWindow: -1, Quiet: q})
	night := time.Date(2026, 10, 30, 2, 0, 0, 0, time.UTC)
	for i, title := range []string{"bir", "iki"} {
		r := d.Notify(context.Background(), Message{Title: title, Priority: PriorityNormal, At: night.Add(time.Duration(i) * time.Minute)})
		if r[0].Outcome != Held {
			t.Fatalf("not held: %+v", r)
		}
	}
	if r := d.Notify(context.Background(), Message{Title: "acil", Priority: PriorityUrgent, At: night}); r[0].Outcome != Sent {
		t.Fatalf("urgent held: %+v", r)
	}
	if r := d.Flush(context.Background(), night.Add(time.Hour)); r != nil {
		t.Fatal("flushed during quiet hours")
	}
	r := d.Flush(context.Background(), night.Add(6*time.Hour))
	if len(r) != 1 || r[0].Outcome != Sent || d.HeldCount() != 0 {
		t.Fatalf("flush: %+v", r)
	}
	last := ch.got[len(ch.got)-1]
	if last.Kind != "quiet_digest" || !strings.Contains(last.Body, "bir") || !strings.Contains(last.Body, "iki") {
		t.Fatalf("digest: %+v", last)
	}
}

func TestQuietHoursSameDay(t *testing.T) {
	q := &QuietHours{Start: 12 * 60, End: 13 * 60, Location: time.UTC}
	if !q.Contains(time.Date(2026, 1, 1, 12, 30, 0, 0, time.UTC)) || q.Contains(time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC)) {
		t.Fatal("same-day window wrong")
	}
	var nilQ *QuietHours
	if nilQ.Contains(time.Now()) {
		t.Fatal("nil quiet hours")
	}
}

func TestDispatcherMinPriorityAndRate(t *testing.T) {
	low := &recordChannel{name: "low"}
	high := &recordChannel{name: "high"}
	d, _ := NewDispatcher([]Route{{Channel: low, MaxPerHour: 2}, {Channel: high, MinPriority: PriorityHigh}}, DispatcherOptions{DedupeWindow: -1})
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var outcomes []Outcome
	for i := range 3 {
		r := d.Notify(context.Background(), Message{Title: "x", At: t0.Add(time.Duration(i) * time.Second)})
		outcomes = append(outcomes, r[0].Outcome)
		if r[1].Outcome != BelowMin {
			t.Fatalf("high route got a normal message: %+v", r)
		}
	}
	if outcomes[0] != Sent || outcomes[1] != Sent || outcomes[2] != RateLimited {
		t.Fatalf("rate: %v", outcomes)
	}
	if r := d.Notify(context.Background(), Message{Title: "x", At: t0.Add(2 * time.Hour)}); r[0].Outcome != Sent {
		t.Fatalf("rate window did not slide: %+v", r)
	}
}

func TestDispatcherReportsFailure(t *testing.T) {
	ch := &recordChannel{name: "a", err: errors.New("boom")}
	d, _ := NewDispatcher([]Route{{Channel: ch}}, DispatcherOptions{})
	r := d.Notify(context.Background(), Message{Title: "x"})
	if r[0].Outcome != Failed || r[0].Err == nil {
		t.Fatalf("%+v", r)
	}
	if _, err := NewDispatcher(nil, DispatcherOptions{}); !errors.Is(err, ErrNoChannels) {
		t.Fatal("empty routes accepted")
	}
}

func TestMessageNormalizedStripsControl(t *testing.T) {
	m := Message{Title: "a\r\nInjected: yes", Body: strings.Repeat("ş", MaxBody)}.normalized()
	if strings.ContainsAny(m.Title, "\r\n") {
		t.Fatalf("title keeps line break: %q", m.Title)
	}
	if len(m.Body) > MaxBody || !strings.HasSuffix(m.Body, "ş") {
		t.Fatal("body cut inside a rune or too long")
	}
}

func TestParseDestination(t *testing.T) {
	good := []string{"https://ntfy.example.test/ev", "http://127.0.0.1:8080/x", "http://192.168.1.5/", "http://100.64.0.9/", "http://localhost:2586/t"}
	for _, s := range good {
		if _, err := ParseDestination(s); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
	bad := []string{"http://ntfy.example.test/x", "ftp://a.example.test/", "https://user:pw@a.example.test/", "https://169.254.169.254/", "https://[ff02::1]/", "http://8.8.8.8/", "https://a.example.test/#f", ""}
	for _, s := range bad {
		if _, err := ParseDestination(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestNtfySend(t *testing.T) {
	var got http.Header
	var body string
	s := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		if r.URL.Path != "/ev" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	n, err := NewNtfy("telefon", s.URL+"/ev", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Send(context.Background(), Message{Kind: "service_down", Title: "Servis düştü", Body: "NAS yanıt vermiyor", Priority: PriorityUrgent}); err != nil {
		t.Fatal(err)
	}
	if got.Get("Priority") != "5" || got.Get("Authorization") != "Bearer tok" || got.Get("Tags") != "service_down" {
		t.Fatalf("headers: %v", got)
	}
	if !strings.HasPrefix(got.Get("Title"), "=?utf-8?") || body != "NAS yanıt vermiyor" {
		t.Fatalf("title %q body %q", got.Get("Title"), body)
	}
	if _, err := NewNtfy("x", s.URL, ""); err == nil {
		t.Fatal("topic-less URL accepted")
	}
}

func TestNtfyNoRedirect(t *testing.T) {
	s := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	n, _ := NewNtfy("t", s.URL+"/ev", "")
	if err := n.Send(context.Background(), Message{Title: "x"}); err == nil {
		t.Fatal("redirect followed or accepted")
	}
}

func TestGotifySend(t *testing.T) {
	var got struct {
		Title    string `json:"title"`
		Message  string `json:"message"`
		Priority int    `json:"priority"`
	}
	var key, path string
	s := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, path = r.Header.Get("X-Gotify-Key"), r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	g, err := NewGotify("gotify", s.URL+"/g/", "apptok")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Send(context.Background(), Message{Title: "T", Body: "B", Priority: PriorityHigh}); err != nil {
		t.Fatal(err)
	}
	if key != "apptok" || path != "/g/message" || got.Title != "T" || got.Message != "B" || got.Priority != 7 {
		t.Fatalf("key %q path %q got %+v", key, path, got)
	}
}

func TestMatrixSend(t *testing.T) {
	var path, auth, method string
	var got struct {
		MsgType string `json:"msgtype"`
		Body    string `json:"body"`
	}
	s := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth, method = r.URL.Path, r.Header.Get("Authorization"), r.Method
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	m, err := NewMatrix("matrix", s.URL, "!oda:example.test", "mtok")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), Message{Title: "Başlık", Body: "Gövde"}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || auth != "Bearer mtok" || !strings.HasPrefix(path, "/_matrix/client/v3/rooms/!oda:example.test/send/m.room.message/os") {
		t.Fatalf("method %s auth %q path %q", method, auth, path)
	}
	if got.MsgType != "m.text" || got.Body != "Başlık\nGövde" {
		t.Fatalf("%+v", got)
	}
	if _, err := NewMatrix("m", s.URL, "oda/../x", "t"); err == nil {
		t.Fatal("bad room accepted")
	}
}

func TestChannelErrorStatus(t *testing.T) {
	s := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	n, _ := NewNtfy("t", s.URL+"/ev", "")
	if err := n.Send(context.Background(), Message{Title: "x"}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err %v", err)
	}
}

// fakeSMTP is a minimal SMTP server on 127.0.0.1 without STARTTLS.
func fakeSMTP(t *testing.T, auth bool) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	data := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
		w("220 test")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				if auth {
					w("250-test")
					w("250 AUTH PLAIN")
				} else {
					w("250 test")
				}
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				w("250 ok")
			case cmd == "DATA":
				w("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				data <- b.String()
				w("250 queued")
			case cmd == "QUIT":
				w("221 bye")
				return
			default:
				w("502 no")
			}
		}
	}()
	return ln.Addr().String(), data
}

func TestSMTPPlainToLoopback(t *testing.T) {
	addr, data := fakeSMTP(t, false)
	s, err := NewSMTP("posta", addr, "OpenScale <ev@example.test>", []string{"sahip@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), Message{Title: "Haftalık rapor", Body: "metin", HTML: "<p>html</p>"}); err != nil {
		t.Fatal(err)
	}
	got := <-data
	if !strings.Contains(got, "multipart/alternative") || !strings.Contains(got, "Subject: =?utf-8?") || !strings.Contains(got, "Auto-Submitted: auto-generated") {
		t.Fatalf("message:\n%s", got)
	}
}

func TestSMTPNoCredentialsWithoutTLS(t *testing.T) {
	addr, _ := fakeSMTP(t, true)
	s, _ := NewSMTP("posta", addr, "ev@example.test", []string{"sahip@example.test"})
	s.Username, s.Password = "u", "p"
	err := s.Send(context.Background(), Message{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("credentials sent without TLS: %v", err)
	}
}

func TestNewSMTPValidation(t *testing.T) {
	if _, err := NewSMTP("p", "mail.example.test", "a@example.test", []string{"b@example.test"}); err == nil {
		t.Fatal("missing port accepted")
	}
	if _, err := NewSMTP("p", "mail.example.test:587", "a@example.test\r\nBcc: x@example.test", []string{"b@example.test"}); err == nil {
		t.Fatal("header injection in from accepted")
	}
	if _, err := NewSMTP("p", "169.254.169.254:25", "a@example.test", []string{"b@example.test"}); err == nil {
		t.Fatal("link-local server accepted")
	}
}

func TestBuildMailPlain(t *testing.T) {
	b, err := BuildMail("a@example.test", []string{"b@example.test"}, "Konu\r\nBcc: x", "gövde", "", time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "\r\nBcc:") || !strings.Contains(s, "text/plain; charset=utf-8") {
		t.Fatalf("mail:\n%s", s)
	}
}

func TestWeeklyReport(t *testing.T) {
	from := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	in := WeeklyInput{
		Network: "Ev",
		From:    from,
		To:      from.Add(7 * 24 * time.Hour),
		Devices: []DeviceWeek{
			{Name: "laptop", BytesIn: 3 << 30, BytesOut: 1 << 20, Online: true, Version: "1.2.0", Latest: "1.3.0"},
			{Name: "<nas>", BytesIn: 1 << 20, Online: false, OfflineFor: 26 * time.Hour, Version: "1.3.0", Latest: "1.3.0"},
		},
		Blocked:         map[string]uint64{"reklam": 120, "izleyici": 80},
		Incidents:       map[string]int{"port_scan": 2, "none": 0},
		ServiceDowntime: map[string]time.Duration{"Home Assistant": 95 * time.Minute},
	}
	w := BuildWeekly(in, in.To)
	if w.BlockedSum != 200 || len(w.Updates) != 1 || w.Updates[0].Name != "laptop" || len(w.Offline) != 1 || len(w.Incidents) != 1 {
		t.Fatalf("%+v", w)
	}
	text := w.Text()
	for _, want := range []string{"laptop", "3.0 GiB", "reklam: 120", "1 gün 2 saat", "1 saat 35 dakika", "1.2.0 -> 1.3.0"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	h, err := w.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, "<nas>") || !strings.Contains(h, "&lt;nas&gt;") {
		t.Fatal("HTML not escaped")
	}
	m, err := w.Message()
	if err != nil || m.Kind != "weekly_report" || m.HTML == "" {
		t.Fatalf("%v %+v", err, m)
	}
}

func TestConfigSaveLoadRedact(t *testing.T) {
	dir := testDir(t)
	c := Config{
		Channels: []ChannelConfig{
			{Kind: KindNtfy, Label: "telefon", URL: "https://ntfy.example.test/ev", Token: "gizli", MinPriority: "high"},
			{Kind: KindSMTP, Label: "posta", SMTPAddr: "mail.example.test:587", From: "a@example.test", To: []string{"b@example.test"}, Password: "pw"},
		},
		QuietStart: "23:00", QuietEnd: "07:00", TimeZone: "UTC",
		WeeklyReport: true, ReportDay: 1, ReportHour: 9,
	}
	path := filepath.Join(dir, ConfigFile)
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Channels[0].Token != "gizli" {
		t.Fatal("token lost")
	}
	r := got.Redacted()
	if r.Channels[0].Token != "***" || r.Channels[1].Password != "***" || got.Channels[0].Token != "gizli" {
		t.Fatal("redaction wrong or aliased")
	}
	d, err := got.Build(nil)
	if err != nil || d == nil {
		t.Fatalf("build: %v", err)
	}
	mon := time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC) // Monday
	if !got.ReportDue(mon, time.Time{}) || got.ReportDue(mon, mon.Add(-time.Hour)) || got.ReportDue(mon.Add(-2*time.Hour), time.Time{}) {
		t.Fatal("ReportDue")
	}
	bad := c
	bad.Channels = append(bad.Channels, ChannelConfig{Kind: KindNtfy, Label: "telefon"})
	if err := bad.Validate(); err == nil {
		t.Fatal("duplicate label accepted")
	}
	desk := Config{Schema: 1, Channels: []ChannelConfig{{Kind: KindDesktop, Label: "masaüstü", Devices: []string{"laptop"}}}}
	if _, err := desk.Build(nil); err == nil {
		t.Fatal("desktop without deliverer accepted")
	}
}

func TestDesktopChannelFallsThrough(t *testing.T) {
	var tried []string
	d := &Desktop{Label: "m", Devices: []string{"a", "b"}, Deliver: func(_ context.Context, dev string, _ Message) error {
		tried = append(tried, dev)
		if dev == "a" {
			return errors.New("kapalı")
		}
		return nil
	}}
	if err := d.Send(context.Background(), Message{Title: "x"}); err != nil || len(tried) != 2 {
		t.Fatalf("%v %v", err, tried)
	}
}

func TestLocalCommandArgs(t *testing.T) {
	if got := appleScriptString(`a"b\c` + "\n"); got != `"a\"b\\c "` {
		t.Fatalf("applescript %q", got)
	}
	args := notifySendArgs(Message{Title: "-x", Body: "b", Priority: PriorityUrgent})
	if args[2] != "--" || args[3] != "-x" || args[1] != "--urgency=critical" {
		t.Fatalf("%v", args)
	}
	if a := osascriptArgs(Message{Title: "t", Body: "b"}); a[0] != "-e" || !strings.Contains(a[1], `with title "t"`) {
		t.Fatalf("%v", a)
	}
}

func TestPriorityParse(t *testing.T) {
	for _, p := range []Priority{PriorityLow, PriorityNormal, PriorityHigh, PriorityUrgent} {
		got, err := ParsePriority(p.String())
		if err != nil || got != p {
			t.Fatalf("%v %v", p, err)
		}
	}
	if _, err := ParsePriority("x"); err == nil {
		t.Fatal("bad priority accepted")
	}
}
