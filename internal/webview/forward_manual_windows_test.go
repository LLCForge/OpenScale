//go:build windows

package webview

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// anyWindow accepts this test's own window.
func anyWindow(uint32) error { return nil }

// TestManualForwardToOpenWindow opens a real, hidden WebView2 window and
// hands it addresses the way the tray does (single window, W2). Runs
// only with OPENSCALE_WEBVIEW_MANUAL=1.
func TestManualForwardToOpenWindow(t *testing.T) {
	if os.Getenv("OPENSCALE_WEBVIEW_MANUAL") != "1" {
		t.Skip("OPENSCALE_WEBVIEW_MANUAL=1 değil")
	}
	if _, err := findRuntime(); err != nil {
		t.Skipf("WebView2 yok: %v", err)
	}
	if h, _, _ := procFindWindowExW.Call(0, 0, uintptr(unsafe.Pointer(windowClassName)), 0); h != 0 {
		t.Skip("açık bir OpenScale penceresi var; deneme ona mesaj göndermesin")
	}
	if err := ForwardToOpenWindow("http://127.0.0.1:1/auth/ticket?t=x", anyWindow); !errors.Is(err, ErrNoOpenWindow) {
		t.Fatalf("no window: %v", err)
	}
	var hits sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Store(r.URL.Path+"?"+r.URL.RawQuery, true)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>t</title>ok"))
	}))
	defer srv.Close()

	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(local, "OpenScale", "WebView2-forwardtest")
	defer func() {
		for range 50 {
			if os.RemoveAll(dataDir) == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		_ = os.Remove(filepath.Dir(dataDir))
	}()
	var mu sync.Mutex
	var events []string
	hooks := &testHooks{event: func(kind, uri string) { mu.Lock(); events = append(events, kind+" "+uri); mu.Unlock() }}
	wait := func(kind, part string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			for _, e := range events {
				if strings.HasPrefix(e, kind+" ") && strings.Contains(e, part) {
					mu.Unlock()
					return
				}
			}
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("%s %s gelmedi:\n%s", kind, part, strings.Join(events, "\n"))
	}
	cfg, err := Options{URL: srv.URL + "/", DataDir: dataDir, ForwardPath: "/auth/ticket"}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	cfg.hidden, cfg.hooks = true, hooks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- open(ctx, cfg) }()
	wait("nav-completed", srv.URL+"/")

	if err := ForwardToOpenWindow(srv.URL+"/auth/ticket?t=bilet1", anyWindow); err != nil {
		t.Fatalf("forward: %v", err)
	}
	wait("forward-accept", "bilet1")
	wait("nav-completed", "/auth/ticket?t=bilet1")
	if _, ok := hits.Load("/auth/ticket?t=bilet1"); !ok {
		t.Fatal("window did not load the forwarded ticket")
	}
	if err := ForwardToOpenWindow(srv.URL+"/devices/", anyWindow); err == nil {
		t.Fatal("window accepted a path other than the ticket path")
	}
	wait("forward-refuse", "/devices/")
	if err := ForwardToOpenWindow("https://example.com/auth/ticket?t=x", anyWindow); err == nil {
		t.Fatal("window accepted a foreign origin")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(15 * time.Second):
		t.Fatal("pencere kapanmadı")
	}
}
