package client

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/webhook"
)

// jsonTags returns the JSON names of a struct's fields.
func jsonTags(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			for k, v := range jsonTags(f.Type) {
				out[k] = v
			}
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

// TestContractMatchesLocalAPI keeps the public types in step with the
// documents the tunnel sends: every field of the client must exist with
// the same JSON name and kind in the internal type.
// Tests never read the real service's token.
func init() { serviceDataDir = func() string { return "" } }

func TestContractMatchesLocalAPI(t *testing.T) {
	pairs := []struct {
		public, internal any
	}{
		{Status{}, panel.DiagStatus{}},
		{Self{}, panel.DiagSelf{}},
		{Peer{}, panel.DiagPeer{}},
		{Health{}, panel.HealthReport{}},
		{Alert{}, panel.HealthAlert{}},
		{Device{}, panel.WhoisDevice{}},
		{WhoIsResult{}, panel.WhoisResult{}},
		{PeerPath{}, node.PeerPath{}},
		{Event{}, panel.DiagEvent{}},
		{StreamEvent{}, panel.StreamEvent{}},
		{EventBatch{}, panel.EventStreamReply{}},
		{DNS{}, panel.DNSStatus{}},
		{SplitDNS{}, panel.SplitDNSInfo{}},
		{Pref{}, panel.Pref{}},
	}
	for _, p := range pairs {
		pub, in := jsonTags(reflect.TypeOf(p.public)), jsonTags(reflect.TypeOf(p.internal))
		for name, typ := range pub {
			it, ok := in[name]
			if !ok {
				t.Errorf("%T.%s does not exist in %T", p.public, name, p.internal)
				continue
			}
			if typ.Kind() != it.Kind() {
				t.Errorf("%T.%s is %s, the tunnel sends %s", p.public, name, typ.Kind(), it.Kind())
			}
		}
	}
	if Schema != panel.DiagSchema || Prefix != panel.LocalAPIPrefix {
		t.Fatal("schema or prefix differs from the tunnel")
	}
}

func TestNewRefusesNonLoopback(t *testing.T) {
	tok := strings.Repeat("t", 40)
	for _, base := range []string{"http://192.0.2.1:47821", "https://127.0.0.1:1", "http://127.0.0.1:0", "http://localhost:47821", "http://127.0.0.1:1/x", "http://u@127.0.0.1:1"} {
		if _, err := New(base, tok); err == nil {
			t.Errorf("%s accepted", base)
		}
	}
	if _, err := New("http://127.0.0.1:1", "short"); err == nil {
		t.Error("short token accepted")
	}
	if _, err := New("http://[::1]:5", tok); err != nil {
		t.Errorf("ipv6 loopback refused: %v", err)
	}
}

// fakeTunnel answers the local API from fixed data.
type fakeTunnel struct{ whoisCalls atomic.Int32 }

func (f *fakeTunnel) DiagStatus() (panel.DiagStatus, error) {
	return panel.DiagStatus{Schema: 1, Mode: "up", Running: true, Connected: true,
		Self:  &panel.DiagSelf{Name: "masaustu", IPv4: "100.80.0.1"},
		Peers: []panel.DiagPeer{{Name: "laptop", IPv4: "127.0.0.1", Online: true, Path: panel.PathDirect}}}, nil
}
func (f *fakeTunnel) DiagNetCheck(context.Context) (node.NetReport, error) {
	return node.NetReport{}, nil
}
func (f *fakeTunnel) DiagPaths() ([]node.PeerPath, error) {
	return []node.PeerPath{{Name: "laptop", Relayed: true}}, nil
}
func (f *fakeTunnel) DiagReconnect() error { return nil }
func (f *fakeTunnel) DiagRelayTest(context.Context, string) (time.Duration, error) {
	return 0, nil
}
func (f *fakeTunnel) DiagPing(context.Context, string) (panel.PingResult, error) {
	return panel.PingResult{}, nil
}
func (f *fakeTunnel) DiagDNS() (panel.DNSStatus, error) { return panel.DNSStatus{Schema: 1}, nil }
func (f *fakeTunnel) DiagDNSQuery(context.Context, string) (panel.DNSQueryResult, error) {
	return panel.DNSQueryResult{}, nil
}
func (f *fakeTunnel) DiagWhois(q string) (panel.WhoisResult, error) {
	f.whoisCalls.Add(1)
	res := panel.WhoisResult{Schema: 1, Query: q}
	if q == "127.0.0.1" || q == "laptop" {
		res.Device = &panel.WhoisDevice{Name: "laptop", FQDN: "laptop.openscale.internal", IPv4: "127.0.0.1", Tags: []string{"is"}, Fingerprint: "abcdef012345"}
	}
	return res, nil
}
func (f *fakeTunnel) DiagEvents() []panel.DiagEvent        { return nil }
func (f *fakeTunnel) DiagWireGuard() (panel.WGShow, error) { return panel.WGShow{}, nil }
func (f *fakeTunnel) DiagPacketTrace(panel.TraceRequest) (panel.TraceResult, error) {
	return panel.TraceResult{}, nil
}
func (f *fakeTunnel) DiagHealth() panel.HealthReport {
	return panel.HealthReport{Schema: 1, Live: true, Ready: true, Reasons: []string{}, Alerts: []panel.HealthAlert{}}
}
func (f *fakeTunnel) DiagLogLevel() string             { return "info" }
func (f *fakeTunnel) DiagSetLogLevel(string) error     { return nil }
func (f *fakeTunnel) DiagPrefs() ([]panel.Pref, error) { return []panel.Pref{}, nil }
func (f *fakeTunnel) DiagSetPrefs(map[string]string) ([]panel.Pref, error) {
	return nil, errors.New("read only")
}

func startTunnel(t *testing.T) (string, *fakeTunnel) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTunnel{}
	token := strings.Repeat("k", 43)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = panel.ServeLocalAPI(ctx, ln, panel.LocalAPIConfig{Diag: f, Token: token})
	}()
	t.Cleanup(func() { cancel(); <-done })
	dir := t.TempDir()
	port := ln.Addr().(*net.TCPAddr).Port
	if err := securefile.Replace(filepath.Join(dir, StateFile), []byte(`{"port":`+itoa(port)+`,"token":"`+token+`"}`)); err != nil {
		t.Fatal(err)
	}
	return dir, f
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestClientAgainstLocalAPI(t *testing.T) {
	dir, _ := startTunnel(t)
	ctx := context.Background()
	c, err := Discover(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Self == nil || st.Self.Name != "masaustu" || len(st.Peers) != 1 {
		t.Fatalf("status = %+v %v", st, err)
	}
	who, err := c.WhoIs(ctx, "127.0.0.1:54321")
	if err != nil || who.Device == nil || who.Device.Name != "laptop" || who.Query != "127.0.0.1" {
		t.Fatalf("whois = %+v %v", who, err)
	}
	if who, err := c.WhoIs(ctx, "192.0.2.9"); err != nil || who.Device != nil {
		t.Fatalf("unknown = %+v %v", who, err)
	}
	p, err := c.Paths(ctx)
	if err != nil || len(p.Peers) != 1 || !p.Peers[0].Relayed {
		t.Fatalf("paths = %+v %v", p, err)
	}
	if a, err := c.TunnelAddr(ctx); err != nil || a.String() != "100.80.0.1" {
		t.Fatalf("tunnel addr = %v %v", a, err)
	}
	// A wrong token is refused by the tunnel.
	bad, _ := New(c.base, strings.Repeat("z", 43))
	var apiErr *Error
	if _, err := bad.Status(ctx); !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("wrong token = %v", err)
	}
	// No tunnel: a clear error.
	empty := t.TempDir()
	if _, err := Discover(ctx, empty); !errors.Is(err, ErrNotRunning) && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no tunnel = %v", err)
	}
}

func TestIdentityHandler(t *testing.T) {
	dir, f := startTunnel(t)
	c, err := FromStateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var seen http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		if d, ok := DeviceFrom(r.Context()); ok {
			_, _ = io.WriteString(w, d.Name)
		}
	})
	h := IdentityHandler(next, c, IdentityOptions{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("OpenScale-Device", "yonetici")
	req.Header.Set("openscale-device-tags", "admin")
	req.Header.Set("X-Forwarded-For", "192.0.2.50")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "laptop" {
		t.Fatalf("identity = %d %q", rec.Code, rec.Body)
	}
	if seen.Get(HeaderDevice) != "laptop" || seen.Get(HeaderTags) != "is" || seen.Get(HeaderFingerprint) != "abcdef012345" {
		t.Fatalf("headers = %v", seen)
	}
	// The second request is served from the cache.
	calls := f.whoisCalls.Load()
	h.ServeHTTP(httptest.NewRecorder(), req)
	if f.whoisCalls.Load() != calls {
		t.Fatal("cache not used")
	}
	// Unknown source: refused, or passed without identity headers.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.0.2.9:1"
	req2.Header.Set("OpenScale-Device", "yonetici")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req2)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown source = %d", rec.Code)
	}
	seen = nil
	IdentityHandler(next, c, IdentityOptions{AllowUnknown: true}).ServeHTTP(httptest.NewRecorder(), req2)
	if seen == nil || seen.Get(HeaderDevice) != "" {
		t.Fatalf("forged header survived: %v", seen)
	}
	// Tunnel unreachable: fail closed.
	down, _ := New("http://127.0.0.1:1", strings.Repeat("k", 43))
	rec = httptest.NewRecorder()
	IdentityHandler(next, down, IdentityOptions{CacheTTL: -1}).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unreachable tunnel = %d", rec.Code)
	}
}

func TestForwardChecksSourceDevice(t *testing.T) {
	dir, _ := startTunnel(t)
	c, err := FromStateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, "merhaba")
			_ = conn.Close()
		}
	}()
	front, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	allowed := atomic.Bool{}
	allowed.Store(true)
	go func() {
		done <- Forward(ctx, front, backend.Addr().String(), c, func(d Device) bool { return allowed.Load() && d.Name == "laptop" })
	}()
	read := func() string {
		conn, err := net.Dial("tcp4", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(conn)
		return string(b)
	}
	if got := read(); got != "merhaba" {
		t.Fatalf("forwarded = %q", got)
	}
	allowed.Store(false)
	if got := read(); got != "" {
		t.Fatalf("refused device got %q", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWebhook(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	raw, _ := hexDecode(secret)
	body := []byte(`{"schema":1}`)
	now := time.Now()
	sig := webhook.Sign(raw, now, body)
	if err := VerifyWebhook(secret, sig, body, now); err != nil {
		t.Fatal(err)
	}
	if VerifyWebhook(secret, sig, []byte(`{"schema":2}`), now) == nil {
		t.Fatal("tampered body accepted")
	}
	if VerifyWebhook("zz", sig, body, now) == nil {
		t.Fatal("bad secret accepted")
	}
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
