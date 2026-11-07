//go:build windows

package webview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestManualWebView2 creates a real WebView2 environment in a hidden
// window and checks every guard against a loopback server. It needs the
// WebView2 runtime and a desktop session, so it runs only with
// OPENSCALE_WEBVIEW_MANUAL=1 (never in CI). No window is shown and the
// system browser is never started.
func TestManualWebView2(t *testing.T) {
	if os.Getenv("OPENSCALE_WEBVIEW_MANUAL") != "1" {
		t.Skip("OPENSCALE_WEBVIEW_MANUAL=1 değil")
	}
	if _, err := findRuntime(); err != nil {
		t.Skipf("WebView2 yok: %v", err)
	}

	var foreignHits atomic.Int32
	var reports sync.Map // what the page saw, from /report?...
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		t.Logf("izinsiz sunucuya istek: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte("foreign"))
	}))
	defer foreign.Close()

	page := fmt.Sprintf(`<!doctype html><html><head><title>t</title></head><body>
<img src="%[1]s/img.png" onload="fetch('/report?img=load')" onerror="fetch('/report?img=error')">
<iframe src="%[1]s/frame"></iframe>
<script>
fetch(%[2]q).then(function(r){ fetch("/report?fetch=" + r.status); }).catch(function(){ fetch("/report?fetch=rejected"); });
try { window.open("https://example.com/"); } catch (e) {}
try { Notification.requestPermission(); } catch (e) {}
try { navigator.geolocation.getCurrentPosition(function(){}, function(){}); } catch (e) {}
</script></body></html>`, foreign.URL, foreign.URL+"/fetch")
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(page))
		case "/report":
			reports.Store(r.URL.RawQuery, true)
		case "/jsnav":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><script>location.href = "https://example.org/js";</script>`))
		case "/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="x.bin"`)
			_, _ = w.Write([]byte("data"))
		case "/auth":
			w.Header().Set("WWW-Authenticate", `Basic realm="t"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer main.Close()

	var externalCalls atomic.Int32
	prev := openExternal
	openExternal = func(string) error { externalCalls.Add(1); return nil }
	defer func() { openExternal = prev }()

	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(local, "OpenScale", "WebView2-manualtest")
	defer func() {
		// The runtime's processes release the folder a moment after the
		// window closes.
		for range 50 {
			if os.RemoveAll(dataDir) == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = os.Remove(filepath.Dir(dataDir)) // only if empty
	}()

	var mu sync.Mutex
	var events []string
	var nav func(string)
	hooks := &testHooks{
		ready: func(n func(string)) { mu.Lock(); nav = n; mu.Unlock() },
		event: func(kind, uri string) {
			mu.Lock()
			events = append(events, kind+" "+uri)
			mu.Unlock()
		},
	}
	has := func(kind, uriPart string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range events {
			if strings.HasPrefix(e, kind+" ") && strings.Contains(e, uriPart) {
				return true
			}
		}
		return false
	}
	wait := func(kind, uriPart string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if has(kind, uriPart) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("%s %s gelmedi; olaylar:\n%s", kind, uriPart, strings.Join(events, "\n"))
	}

	cfg, err := Options{URL: main.URL + "/", Title: "OpenScale deneme", DataDir: dataDir, IconICO: makeICO(16, 32)}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	cfg.hidden = true
	cfg.hooks = hooks

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- open(ctx, cfg) }()

	select {
	case err := <-result:
		t.Fatalf("pencere erken kapandı: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	wait("nav-completed", main.URL)
	// The page's fetch to the foreign server must fail. The
	// WebResourceRequested event is not raised reliably for every
	// request, so the proxy rule is what is checked here.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, ok := reports.Load("fetch=rejected"); ok {
			break
		}
		if _, ok := reports.Load("fetch=200"); ok {
			t.Fatal("sayfa izinsiz sunucunun yanıtını okudu")
		}
		if time.Now().After(deadline) {
			t.Fatal("fetch sonucu gelmedi")
		}
		time.Sleep(50 * time.Millisecond)
	}
	wait("frame-block", foreign.URL+"/frame")
	wait("newwindow-block", "https://example.com/")
	wait("permission-deny", main.URL)

	mu.Lock()
	n := nav
	mu.Unlock()
	if n == nil {
		t.Fatal("ready çağrılmadı")
	}
	n(foreign.URL + "/nav")
	wait("nav-block", foreign.URL+"/nav")
	// A navigation the page script starts without a click is blocked.
	n(main.URL + "/jsnav")
	wait("nav-block", "https://example.org/js")
	// The host's own Navigate call counts as user initiated in WebView2,
	// so an https address goes to the (replaced) system browser.
	n("https://example.com/host")
	wait("nav-external", "https://example.com/host")
	n("data:text/html,x")
	wait("nav-block", "data:text/html")
	n(main.URL + "/download")
	wait("download-cancel", "")
	n(main.URL + "/auth")
	wait("auth-cancel", main.URL+"/auth")

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Open = %v, context.Canceled bekleniyordu", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("pencere kapanmadı")
	}
	mu.Lock()
	t.Logf("olaylar:\n%s", strings.Join(events, "\n"))
	mu.Unlock()
	if h := foreignHits.Load(); h != 0 {
		t.Fatalf("izinsiz sunucuya %d istek ulaştı", h)
	}
	if c := externalCalls.Load(); c != 1 {
		t.Fatalf("sistem tarayıcısı %d kez çağrıldı; yalnızca ana uygulamanın isteği için 1 bekleniyordu", c)
	}
}
