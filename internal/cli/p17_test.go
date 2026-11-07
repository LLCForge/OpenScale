package cli

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/panel"
)

const p17RemotePassword = "kuzey yildizi uzak erisim 42"

func TestPanelRemoteAndAPIKeyCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	out := h.run(exitOK, "panel-remote", "status", "--dir", h.netDir)
	if !strings.Contains(out, "Uzaktan erişim: kapalı") {
		t.Fatalf("status:\n%s", out)
	}
	out = h.run(exitError, "panel-remote", "on", "--dir", h.netDir)
	if !strings.Contains(out, "parola") {
		t.Fatalf("on without password:\n%s", out)
	}
	// The root key passphrase is refused as the remote password.
	root := "çok gizli parola 42"
	h.env.ReadSecret = func(string) ([]byte, error) { return []byte(root), nil }
	h.run(exitError, "panel-remote", "password", "--dir", h.netDir)
	// Two different entries are refused.
	n := 0
	h.env.ReadSecret = func(string) ([]byte, error) {
		n++
		if n == 1 {
			return []byte(p17RemotePassword), nil
		}
		return []byte(p17RemotePassword + "x"), nil
	}
	h.run(exitError, "panel-remote", "password", "--dir", h.netDir)
	h.env.ReadSecret = func(string) ([]byte, error) { return []byte(p17RemotePassword), nil }
	h.run(exitOK, "panel-remote", "password", "--dir", h.netDir)
	h.run(exitOK, "panel-remote", "on", "--dir", h.netDir)
	set, err := panel.LoadRemoteSettings(h.netDir)
	if err != nil || !set.Ready() || !set.Password.Verify([]byte(p17RemotePassword)) {
		t.Fatalf("settings = %+v %v", set, err)
	}
	out = h.run(exitOK, "panel-remote", "status", "--dir", h.netDir, "--json")
	if !strings.Contains(out, `"enabled": true`) || !strings.Contains(out, `"password": true`) {
		t.Fatalf("status json:\n%s", out)
	}
	h.run(exitOK, "panel-remote", "off", "--dir", h.netDir)
	if set, _ := panel.LoadRemoteSettings(h.netDir); set.Enabled {
		t.Fatal("still enabled")
	}
	h.run(exitUsage, "panel-remote", "nope", "--dir", h.netDir)

	out = h.run(exitOK, "api-key", "create", "izleme", "--dir", h.netDir)
	key := regexp.MustCompile(`osk_[0-9a-f]{8}_[A-Za-z0-9_-]+`).FindString(out)
	if key == "" {
		t.Fatalf("create:\n%s", out)
	}
	out = h.run(exitOK, "api-key", "list", "--dir", h.netDir)
	if !strings.Contains(out, "izleme") || strings.Contains(out, key) {
		t.Fatalf("list shows the secret or misses the key:\n%s", out)
	}
	h.run(exitError, "api-key", "create", "izleme", "--dir", h.netDir)
	h.run(exitOK, "api-key", "revoke", "izleme", "--dir", h.netDir)
	out = h.run(exitOK, "api-key", "list", "--dir", h.netDir)
	if !strings.Contains(out, "API anahtarı yok") {
		t.Fatalf("after revoke:\n%s", out)
	}
}

func TestWebhookCommands(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(t.TempDir(), "webhook.json")
	h.run(exitError, "webhook", "init", "--config", cfg, "--url", "http://203.0.113.4/hook")
	h.run(exitError, "webhook", "init", "--config", cfg, "--url", "http://169.254.169.254/")
	out := h.run(exitOK, "webhook", "init", "--config", cfg, "--url", "http://127.0.0.1:9/hook", "--events", "peer_offline, security")
	secret := regexp.MustCompile(`[0-9a-f]{64}`).FindString(out)
	if secret == "" {
		t.Fatalf("init:\n%s", out)
	}
	out = h.run(exitOK, "webhook", "show", "--config", cfg)
	if strings.Contains(out, secret) || !strings.Contains(out, "peer_offline") {
		t.Fatalf("show:\n%s", out)
	}
	if out = h.run(exitOK, "webhook", "show", "--config", cfg, "--secret"); !strings.Contains(out, secret) {
		t.Fatalf("show --secret:\n%s", out)
	}
	h.run(exitOK, "webhook", "off", "--config", cfg)
	h.run(exitError, "webhook", "show", "--config", cfg)
}

func TestDebugHTTPPage(t *testing.T) {
	h := newHarness(t)
	serveFake(t, h, &fakeDiag{})
	lc, err := openLocalClient(h.env, "")
	if err != nil {
		t.Fatal(err)
	}
	dh := &debugHandler{env: h.env, lc: lc, host: "127.0.0.1:5555", prefix: "/d/" + strings.Repeat("ab", 32) + "/", docDir: t.TempDir()}
	get := func(host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		dh.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("evil.example:5555", dh.prefix); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host = %d", rec.Code)
	}
	if rec := get(dh.host, "/d/wrong/"); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong token = %d", rec.Code)
	}
	rec := get(dh.host, dh.prefix)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "OpenScale hata ayıklama") || !strings.Contains(body, "Durum") {
		t.Fatalf("page = %d\n%s", rec.Code, body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script") {
		t.Fatalf("csp = %q", csp)
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Fatal("page has a script")
	}
	if strings.Contains(body, strings.Repeat("a", 43)) {
		t.Fatal("page shows the API token")
	}
}
