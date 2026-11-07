package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

const testRemotePassword = "kuzey yildizi uzak erisim 42"

// remoteHarness runs ServeRemote with a loopback listener standing in for
// the tunnel address.
type remoteHarness struct {
	srv    *Server
	devs   map[string]trust.Device
	source atomic.Value // netip.Addr the next connection pretends to come from
	addrs  chan net.Addr
	tunnel string // Host the browser would use: owner's tunnel address
	base   string // where the test really connects
	client *http.Client
	jar    []*http.Cookie
	csrf   string
}

func newRemoteHarness(t *testing.T, rules []trust.Rule) *remoteHarness {
	t.Helper()
	srv := newTestServer(t)
	h := &remoteHarness{srv: srv, addrs: make(chan net.Addr, 4)}
	h.devs = addTestDevices(t, srv, []string{"yonetici", "laptop", "telefon"}, rules)
	h.source.Store(h.devs["laptop"].IPv4)
	h.tunnel = netip.AddrPortFrom(h.devs["yonetici"].IPv4, trust.PanelPort).String()
	h.client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

func (h *remoteHarness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	cfg := RemoteConfig{
		Self: func(doc *trust.Document) (trust.Device, bool) { return doc.DeviceByName("yonetici") },
		Listen: func(ctx context.Context, _ netip.AddrPort) (net.Listener, error) {
			var lc net.ListenConfig
			ln, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
			if err == nil {
				h.addrs <- ln.Addr()
			}
			return ln, err
		},
		MapSource: func(netip.Addr) netip.Addr { return h.source.Load().(netip.Addr) },
		Interval:  20 * time.Millisecond,
	}
	go func() {
		defer close(done)
		_ = h.srv.ServeRemote(ctx, cfg)
	}()
}

func (h *remoteHarness) waitListen(t *testing.T) {
	t.Helper()
	select {
	case a := <-h.addrs:
		h.base = "http://" + a.String()
	case <-time.After(5 * time.Second):
		t.Fatal("remote listener did not start")
	}
}

func (h *remoteHarness) req(t *testing.T, method, path string, body any, extra func(*http.Request)) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, h.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = h.tunnel
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", "http://"+h.tunnel)
		if h.csrf != "" {
			req.Header.Set("X-CSRF-Token", h.csrf)
		}
	}
	for _, c := range h.jar {
		req.AddCookie(c)
	}
	if extra != nil {
		extra(req)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if cs := resp.Cookies(); len(cs) > 0 {
		h.jar = cs
	}
	return resp.StatusCode, data, resp.Header
}

func (h *remoteHarness) enable(t *testing.T) {
	t.Helper()
	pw, err := HashRemotePassword([]byte(testRemotePassword), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveRemoteSettings(h.srv.network().Dir(), RemoteSettings{Enabled: true, Password: pw, ChangedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestRemotePanelOffByDefault(t *testing.T) {
	h := newRemoteHarness(t, []trust.Rule{{From: []string{"laptop"}, To: []string{"yonetici"}, Service: trust.ServicePanel}})
	h.start(t)
	select {
	case <-h.addrs:
		t.Fatal("listener opened although remote access is off")
	case <-time.After(150 * time.Millisecond):
	}
	// A password without the switch is not enough either.
	pw, err := HashRemotePassword([]byte(testRemotePassword), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveRemoteSettings(h.srv.network().Dir(), RemoteSettings{Password: pw}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.addrs:
		t.Fatal("listener opened although the switch is off")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestRemotePanelNeedsRule(t *testing.T) {
	// Only a broad "any" rule: the panel must stay closed.
	h := newRemoteHarness(t, []trust.Rule{{From: []string{"*"}, To: []string{"*"}, Protocol: trust.ProtocolAny}})
	h.enable(t)
	h.start(t)
	select {
	case <-h.addrs:
		t.Fatal("listener opened without a panel rule")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestRemotePanelReadOnlyFlow(t *testing.T) {
	h := newRemoteHarness(t, []trust.Rule{{From: []string{"laptop"}, To: []string{"yonetici"}, Service: trust.ServicePanel}})
	h.enable(t)
	h.start(t)
	h.waitListen(t)

	if code, _, _ := h.req(t, http.MethodGet, "/api/overview", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("overview without session = %d", code)
	}
	// The root key passphrase is not the remote password.
	if code, _, _ := h.req(t, http.MethodPost, "/api/login", loginRequest{Passphrase: testPass}, nil); code != http.StatusUnauthorized {
		t.Fatalf("root passphrase login = %d", code)
	}
	// Wrong Origin.
	if code, _, _ := h.req(t, http.MethodPost, "/api/login", loginRequest{Passphrase: testRemotePassword}, func(r *http.Request) {
		r.Header.Set("Origin", "http://evil.example")
	}); code != http.StatusForbidden {
		t.Fatalf("foreign origin login = %d", code)
	}
	// DNS rebinding: another Host.
	if code, _, _ := h.req(t, http.MethodGet, "/api/session", nil, func(r *http.Request) { r.Host = "evil.example:4049" }); code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host = %d", code)
	}
	code, body, _ := h.req(t, http.MethodPost, "/api/login", loginRequest{Passphrase: testRemotePassword}, nil)
	if code != http.StatusOK {
		t.Fatalf("remote login = %d %s", code, body)
	}
	code, body, _ = h.req(t, http.MethodGet, "/api/session", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("session = %d", code)
	}
	var sess sessionResponse
	if err := json.Unmarshal(body, &sess); err != nil || !sess.ReadOnly || sess.CSRFToken == "" {
		t.Fatalf("session = %s", body)
	}
	h.csrf = sess.CSRFToken
	for _, p := range []string{"/api/overview", "/api/devices", "/api/rules", "/api/v1/devices", "/api/v1/network"} {
		if code, body, _ := h.req(t, http.MethodGet, p, nil, nil); code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", p, code, body)
		}
	}
	// Secrets and this computer's own endpoints stay local.
	for _, p := range []string{"/api/invites", "/api/network", "/api/network/export", "/api/history", "/api/app/status", "/api/local/status"} {
		if code, _, _ := h.req(t, http.MethodGet, p, nil, nil); code != http.StatusForbidden {
			t.Fatalf("GET %s = %d, want 403", p, code)
		}
	}
	// Nothing that needs the root key's signature, even with session+CSRF.
	writes := map[string]any{
		"/api/rules":               map[string]any{"from": []string{"telefon"}, "to": []string{"yonetici"}, "protocol": "any"},
		"/api/devices/revoke":      map[string]string{"name": "telefon", "passphrase": testPass},
		"/api/network/renew":       map[string]string{"passphrase": testPass},
		"/api/security/backup":     map[string]string{"passphrase": testPass},
		"/api/invites":             map[string]string{},
		"/api/devices/inspect":     map[string]string{},
		"/api/security/passphrase": map[string]string{},
	}
	for p, b := range writes {
		if code, _, _ := h.req(t, http.MethodPost, p, b, nil); code != http.StatusForbidden {
			t.Fatalf("POST %s = %d, want 403", p, code)
		}
	}
	if code, _, _ := h.req(t, http.MethodDelete, "/api/v1/devices", nil, nil); code != http.StatusForbidden {
		t.Fatal("DELETE must be refused")
	}

	// Another device without a panel rule gets nothing, not even the page.
	h.source.Store(h.devs["telefon"].IPv4)
	if code, _, _ := h.req(t, http.MethodGet, "/api/overview", nil, nil); code != http.StatusForbidden {
		t.Fatalf("device without rule = %d", code)
	}
	if code, _, _ := h.req(t, http.MethodGet, "/", nil, nil); code != http.StatusForbidden {
		t.Fatalf("page for device without rule = %d", code)
	}
	// An address outside the network.
	h.source.Store(netip.MustParseAddr("192.0.2.7"))
	if code, _, _ := h.req(t, http.MethodGet, "/api/overview", nil, nil); code != http.StatusForbidden {
		t.Fatalf("unknown source = %d", code)
	}
	// The owner itself over its tunnel address is not a remote device.
	h.source.Store(h.devs["yonetici"].IPv4)
	if code, _, _ := h.req(t, http.MethodGet, "/api/overview", nil, nil); code != http.StatusForbidden {
		t.Fatalf("self source = %d", code)
	}
}

func TestRemotePanelLockoutAndKeys(t *testing.T) {
	h := newRemoteHarness(t, []trust.Rule{{From: []string{"laptop"}, To: []string{"yonetici"}, Service: trust.ServicePanel}})
	h.enable(t)
	dir := h.srv.network().Dir()
	localKey, _, err := CreateAPIKey(dir, "yerel", false, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	remoteKey, _, err := CreateAPIKey(dir, "uzak", true, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.start(t)
	h.waitListen(t)

	bearer := func(k string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+k) }
	}
	if code, _, _ := h.req(t, http.MethodGet, "/api/v1/devices", nil, bearer(localKey)); code != http.StatusForbidden {
		t.Fatalf("local-only key over the tunnel = %d", code)
	}
	if code, body, _ := h.req(t, http.MethodGet, "/api/v1/devices", nil, bearer(remoteKey)); code != http.StatusOK {
		t.Fatalf("remote key = %d %s", code, body)
	}
	// Keys open the v1 API only, never the panel's own endpoints.
	if code, _, _ := h.req(t, http.MethodGet, "/api/overview", nil, bearer(remoteKey)); code != http.StatusUnauthorized {
		t.Fatalf("key on a panel endpoint = %d", code)
	}

	for i := 0; i < 5; i++ {
		if code, _, _ := h.req(t, http.MethodPost, "/api/login", loginRequest{Passphrase: "yanlis parola " + strings.Repeat("x", i)}, nil); code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d = %d", i, code)
		}
	}
	if code, _, _ := h.req(t, http.MethodPost, "/api/login", loginRequest{Passphrase: testRemotePassword}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("after five failures = %d", code)
	}
	// The local panel's own counter is separate.
	if h.srv.auth.passphraseLocked() {
		t.Fatal("remote failures locked the local panel")
	}

	// Turning remote access off closes the listener.
	set, err := LoadRemoteSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	set.Enabled = false
	if err := SaveRemoteSettings(dir, set); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(h.base, "http://"), 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("listener still open after remote access was turned off")
}

func TestRemoteSettingsAndKeys(t *testing.T) {
	dir := t.TempDir()
	set, err := LoadRemoteSettings(dir)
	if err != nil || set.Ready() {
		t.Fatalf("missing file = %+v %v", set, err)
	}
	for _, weak := range []string{"kisa", "123456789012", "parolaparola"} {
		if _, err := HashRemotePassword([]byte(weak), rand.Reader); err == nil {
			t.Fatalf("weak password %q accepted", weak)
		}
	}
	pw, err := HashRemotePassword([]byte(testRemotePassword), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !pw.Verify([]byte(testRemotePassword)) || pw.Verify([]byte(testRemotePassword+"x")) {
		t.Fatal("verify")
	}
	tampered := *pw
	tampered.MemoryKiB = 1 << 30
	if tampered.Verify([]byte(testRemotePassword)) {
		t.Fatal("out-of-range parameters must not be used")
	}
	secret, k, err := CreateAPIKey(dir, "izleme", false, rand.Reader, time.Now())
	if err != nil || !strings.HasPrefix(secret, "osk_"+k.ID+"_") {
		t.Fatalf("create = %q %+v %v", secret, k, err)
	}
	if strings.Contains(k.Digest, secret) {
		t.Fatal("secret stored")
	}
	if _, ok := lookupAPIKey(dir, secret); !ok {
		t.Fatal("lookup")
	}
	if _, ok := lookupAPIKey(dir, secret+"x"); ok {
		t.Fatal("tampered key accepted")
	}
	if _, _, err := CreateAPIKey(dir, "izleme", false, rand.Reader, time.Now()); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, _, err := CreateAPIKey(dir, "kötü ad", false, rand.Reader, time.Now()); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := RevokeAPIKey(dir, "izleme"); err != nil {
		t.Fatal(err)
	}
	if _, ok := lookupAPIKey(dir, secret); ok {
		t.Fatal("revoked key accepted")
	}
}
