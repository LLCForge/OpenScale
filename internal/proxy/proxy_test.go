package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/pki"
	"github.com/openscale/openscale/internal/trust"
)

const testDomain = "openscale.internal"

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

type fixture struct {
	mu   sync.Mutex
	doc  *trust.Document
	from atomic.Value // netip.Addr the 127.0.0.1 connections map to
	cert atomic.Pointer[tls.Certificate]
}

func dev(name, v4 string) trust.Device {
	return trust.Device{Name: name, ID: name + "-id", IPv4: netip.MustParseAddr(v4), ExpiresAt: testNow.Add(24 * time.Hour), Tags: []string{"t-" + name}}
}

func newFixture() *fixture {
	f := &fixture{doc: &trust.Document{
		DNSDomain:  testDomain,
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd12:3456:789a::/48"),
		Devices:    []trust.Device{dev("nas", "100.80.0.1"), dev("laptop", "100.80.0.2"), dev("telefon", "100.80.0.3")},
		Rules: []trust.Rule{
			{From: []string{"laptop", "telefon"}, To: []string{"nas"}, Service: trust.ServiceServe},
			{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"5433"}},
		},
	}}
	f.from.Store(netip.MustParseAddr("100.80.0.2"))
	return f
}

func (f *fixture) env() Env {
	return Env{
		Current: func() (*trust.Document, trust.Device, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.doc, f.doc.Devices[0], true
		},
		MapPeer:     func(netip.Addr) netip.Addr { return f.from.Load().(netip.Addr) },
		Certificate: func() *tls.Certificate { return f.cert.Load() },
		Now:         func() time.Time { return testNow },
	}
}

func (f *fixture) as(name string) {
	for _, d := range f.doc.Devices {
		if d.Name == name {
			f.from.Store(d.IPv4)
		}
	}
}

func serve(t *testing.T, run func(context.Context, net.Listener) error) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = run(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

// get sends a request to addr with the given Host.
func do(t *testing.T, addr, method, host, rawPath string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var b strings.Builder
	b.WriteString(method + " " + rawPath + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n")
	for k, v := range hdr {
		b.WriteString(k + ": " + v + "\r\n")
	}
	if method == http.MethodPost {
		b.WriteString("Content-Length: 0\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func backend(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Device", r.Header.Get("OpenScale-Device"))
		w.Header().Set("X-Seen-Forged", r.Header.Get("OpenScale-Evil"))
		_, _ = io.WriteString(w, r.Method+" "+r.URL.Path)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestHTTPProxyRulesAndIdentity(t *testing.T) {
	f := newFixture()
	be := backend(t)
	cfg := Config{Schema: ConfigSchema, Services: []Service{
		{Name: "web", Type: TypeHTTP, Target: be.URL, Paths: []string{"/api/", "/health"}, ReadOnly: true},
		{Name: "admin", Type: TypeHTTP, Target: be.URL, Allow: []string{"tag:t-telefon"}},
		{Name: "loop", Type: TypeHTTP, Target: "http://100.80.0.9:80"},
	}}
	srv, err := New(cfg, f.env())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := serve(t, srv.ServeShared)
	host := "web.nas." + testDomain

	resp, body := do(t, addr, "GET", host, "/api/x", map[string]string{"OpenScale-Device": "sahte", "OpenScale-Evil": "1"})
	if resp.StatusCode != 200 || body != "GET /api/x" || resp.Header.Get("X-Seen-Device") != "laptop" || resp.Header.Get("X-Seen-Forged") != "" {
		t.Fatalf("proxy: %d %q device=%q forged=%q", resp.StatusCode, body, resp.Header.Get("X-Seen-Device"), resp.Header.Get("X-Seen-Forged"))
	}
	cases := []struct {
		method, host, path string
		want               int
	}{
		{"GET", host, "/health", 200},
		{"GET", host, "/healthz", 403},
		{"GET", host, "/admin", 403},
		{"GET", host, "/api/%2e%2e/admin", 400},
		{"GET", host, "/api/..%2fadmin", 400},
		{"GET", host, "/api//x", 400},
		{"POST", host, "/api/x", 405},
		{"GET", "baska.example.org", "/api/x", 421},
		{"GET", "yok.nas." + testDomain, "/", 404},
		{"GET", "admin.nas." + testDomain, "/", 403},
		{"GET", "loop.nas." + testDomain, "/", 502},
		{"GET", "100.80.0.1", "/", 200},
	}
	for _, c := range cases {
		resp, body := do(t, addr, c.method, c.host, c.path, nil)
		if resp.StatusCode != c.want {
			t.Errorf("%s %s%s: %d, want %d (%s)", c.method, c.host, c.path, resp.StatusCode, c.want, body)
		}
	}
	// The index lists only what the caller may use.
	_, body = do(t, addr, "GET", "nas."+testDomain, "/", nil)
	if !strings.Contains(body, "web.nas") || strings.Contains(body, "admin.nas") {
		t.Fatalf("index: %s", body)
	}
	f.as("telefon")
	if resp, _ := do(t, addr, "GET", "admin.nas."+testDomain, "/", nil); resp.StatusCode != 200 {
		t.Fatalf("allow list: %d", resp.StatusCode)
	}
	// This device itself and addresses that are no device are refused
	// before a byte is read.
	f.as("nas")
	expectClosed(t, addr, host)
	f.from.Store(netip.MustParseAddr("100.80.0.77"))
	expectClosed(t, addr, host)
}

func expectClosed(t *testing.T, addr, host string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
		t.Fatal("refused source got an answer")
	}
}

func TestFilesService(t *testing.T) {
	f := newFixture()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("merhaba"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("sır"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "alt"), 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Schema: ConfigSchema, Services: []Service{{Name: "dosya", Type: TypeFiles, Root: dir}}}, f.env())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := serve(t, srv.ServeShared)
	host := "dosya.nas." + testDomain
	for path, want := range map[string]int{"/a.txt": 200, "/.env": 404, "/": 404, "/alt/": 404, "/../a.txt": 400} {
		resp, body := do(t, addr, "GET", host, path, nil)
		if resp.StatusCode != want {
			t.Errorf("%s: %d want %d (%s)", path, resp.StatusCode, want, body)
		}
	}
	if resp, _ := do(t, addr, "POST", host, "/a.txt", nil); resp.StatusCode != 405 {
		t.Fatalf("post: %d", resp.StatusCode)
	}
}

func TestTCPServiceAndRevalidate(t *testing.T) {
	f := newFixture()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	srv, err := New(Config{Schema: ConfigSchema, Services: []Service{{Name: "db", Type: TypeTCP, Target: echo.Addr().String(), Port: 5433}}}, f.env())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := serve(t, func(ctx context.Context, ln net.Listener) error { return srv.ServeOwn(ctx, ln, "db") })
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	// The rule goes away: the open connection is closed.
	f.mu.Lock()
	f.doc = &trust.Document{DNSDomain: f.doc.DNSDomain, IPv4Prefix: f.doc.IPv4Prefix, IPv6Prefix: f.doc.IPv6Prefix, Devices: f.doc.Devices, Rules: f.doc.Rules[:1]}
	f.mu.Unlock()
	if n := srv.Revalidate(); n != 1 {
		t.Fatalf("revalidate closed %d", n)
	}
	if _, err := io.ReadFull(c, buf); err == nil {
		t.Fatal("connection still open")
	}
	// New connections from a device without the rule are closed at once.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("refused source got data")
	}
}

func issueTestCert(t *testing.T, f *fixture) (*x509.CertPool, *tls.Certificate) {
	t.Helper()
	caKey, _ := pki.GenerateKey(nil)
	caDER, err := pki.NewCA(caKey, "", testDomain, f.doc.IPv4Prefix, f.doc.IPv6Prefix, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := pki.KeyPEM(caKey)
	ca, err := pki.LoadCA(caDER, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := pki.GenerateKey(nil)
	leaf, err := ca.Issue(&leafKey.PublicKey, []string{"nas." + testDomain, "*.nas." + testDomain}, nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	var pk *ecdsa.PrivateKey = leafKey
	return pool, &tls.Certificate{Certificate: [][]byte{leaf, caDER}, PrivateKey: pk}
}

func TestTLSAndRedirect(t *testing.T) {
	f := newFixture()
	be := backend(t)
	srv, err := New(Config{Schema: ConfigSchema, Services: []Service{{Name: "web", Type: TypeHTTP, Target: be.URL, TLS: true}}}, f.env())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := serve(t, srv.ServeShared)
	host := "web.nas." + testDomain
	if resp, _ := do(t, addr, "GET", host, "/x", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no certificate yet: %d", resp.StatusCode)
	}
	pool, cert := issueTestCert(t, f)
	f.cert.Store(cert)
	resp, _ := do(t, addr, "GET", host, "/x?a=1", nil)
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://"+host+"/x?a=1" {
		t.Fatalf("redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}}
	r, err := hc.Get("https://" + host + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || string(body) != "GET /x" {
		t.Fatalf("https: %d %q", r.StatusCode, body)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Service{
		{Name: "Web", Type: TypeHTTP, Target: "http://127.0.0.1:1"},
		{Name: "web", Type: TypeHTTP, Target: "ftp://x"},
		{Name: "web", Type: TypeHTTP, Target: "http://u:p@127.0.0.1"},
		{Name: "web", Type: TypeHTTP, Target: "http://127.0.0.1:1", Port: 4051},
		{Name: "web", Type: TypeHTTP, Target: "http://127.0.0.1:1", Port: 47821},
		{Name: "web", Type: TypeHTTP, Target: "http://127.0.0.1:1", Paths: []string{"api"}},
		{Name: "web", Type: TypeHTTP, Target: "http://127.0.0.1:1", Paths: []string{"/a/../b"}},
		{Name: "db", Type: TypeTCP, Target: "127.0.0.1:5432"},
		{Name: "db", Type: TypeTCP, Target: "127.0.0.1", Port: 5432},
		{Name: "d", Type: TypeFiles},
		{Name: "d", Type: TypeFiles, Root: "/x", ReadOnly: true},
		{Name: "i", Type: TypeOIDC, Clients: []OIDCClient{{ID: "a", RedirectURIs: []string{"javascript:x"}}}},
		{Name: "i", Type: TypeOIDC, Clients: []OIDCClient{{ID: "a", SecretSHA256: "zz", RedirectURIs: []string{"https://a.b/c"}}}},
		{Name: "x", Type: "ftp"},
	}
	for i, s := range bad {
		if err := (Config{Schema: ConfigSchema, Services: []Service{s}}).Validate(); err == nil {
			t.Errorf("%d accepted: %+v", i, s)
		}
	}
	if _, err := ParseConfig([]byte(`{"schema":1,"services":[],"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	dup := Config{Schema: ConfigSchema, Services: []Service{{Name: "a", Type: TypeHTTP, Target: "http://127.0.0.1:1"}, {Name: "a", Type: TypeHTTP, Target: "http://127.0.0.1:2"}}}
	if dup.Validate() == nil {
		t.Fatal("duplicate names accepted")
	}
	good := Config{Schema: ConfigSchema, Services: []Service{
		{Name: "web", Type: TypeHTTP, Target: "http://127.0.0.1:8080", Paths: []string{"/api/"}, TLS: true},
		{Name: "db", Type: TypeTCP, Target: "localhost:5432", Port: 5432},
		{Name: "idp", Type: TypeOIDC, TLS: true, Clients: []OIDCClient{{ID: "grafana", RedirectURIs: []string{"https://grafana.nas.openscale.internal:4051/login"}}}},
	}}
	b, err := good.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseConfig(b)
	if err != nil || len(back.Services) != 3 {
		t.Fatalf("round trip: %v", err)
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(`{"schema":1,"services":[{"name":"web","type":"http","target":"http://127.0.0.1:8080","paths":["/api/"]}]}`))
	f.Add([]byte(`{"schema":1,"services":[{"name":"db","type":"tcp","target":"127.0.0.1:5432","port":5432}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseConfig(b)
		if err != nil {
			return
		}
		if _, err := c.Encode(); err != nil {
			t.Fatalf("valid config does not encode: %v", err)
		}
	})
}

func FuzzCleanRequestPath(f *testing.F) {
	for _, s := range []string{"/", "/api/x", "/api/%2e%2e/x", "/a//b", "/a/./b", "/%00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		req, err := http.NewRequest("GET", "http://h"+raw, nil)
		if err != nil || req.URL.Host != "h" {
			return
		}
		p, ok := cleanRequestPath(req.URL)
		if !ok {
			return
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." || seg == "." {
				t.Fatalf("dot segment passed: %q -> %q", raw, p)
			}
		}
		if strings.Contains(p, "//") || strings.Contains(p, "\\") {
			t.Fatalf("ambiguous path passed: %q -> %q", raw, p)
		}
	})
}
