package panel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// remoteApp is featureApp plus the remote services; it records calls.
type remoteApp struct {
	featureApp
	decided  map[string]bool
	woke     string
	sent     []byte
	deleted  string
	autoOn   map[string]bool
	speedDev string
}

func (a *remoteApp) AppsStatus() AppsStatus { return AppsStatus{SSHFingerprint: "SHA256:abc"} }
func (a *remoteApp) RemoteDevice(name string) (RemoteDeviceView, error) {
	return RemoteDeviceView{Name: name, SSHUsers: []string{"ali"}}, nil
}
func (a *remoteApp) Inbox() InboxView {
	return InboxView{Files: []InboxFile{{Name: "rapor.pdf", Size: 3}}, Pending: []PendingOffer{}, AutoAccept: []string{}}
}
func (a *remoteApp) DecideOffer(id string, accept bool) error {
	if id != "abc" {
		return errors.New("yok")
	}
	if a.decided == nil {
		a.decided = map[string]bool{}
	}
	a.decided[id] = accept
	return nil
}
func (a *remoteApp) SetAutoAccept(device string, on bool) error {
	if a.autoOn == nil {
		a.autoOn = map[string]bool{}
	}
	a.autoOn[device] = on
	return nil
}
func (a *remoteApp) DeleteInboxFile(name string) error { a.deleted = name; return nil }
func (a *remoteApp) OpenInboxFile(name string) (io.ReadSeekCloser, InboxFile, error) {
	if name != "rapor.pdf" {
		return nil, InboxFile{}, errors.New("yok")
	}
	return nopSeekCloser{bytes.NewReader([]byte("pdf"))}, InboxFile{Name: name, Size: 3}, nil
}
func (a *remoteApp) SendFile(device, name string, body io.Reader, size int64) (string, error) {
	b, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	a.sent = b
	return "t1", nil
}
func (a *remoteApp) Transfers() []TransferStatus { return []TransferStatus{} }
func (a *remoteApp) Wake(_ context.Context, device string) (WakeResult, error) {
	a.woke = device
	return WakeResult{Relay: "nas"}, nil
}
func (a *remoteApp) SetWakeMAC(string, string) error { return nil }
func (a *remoteApp) SpeedTest(_ context.Context, device string, _ bool, _ int) (SpeedResult, error) {
	a.speedDev = device
	return SpeedResult{Device: device, Mbps: 100}, nil
}

type nopSeekCloser struct{ *bytes.Reader }

func (nopSeekCloser) Close() error { return nil }

func newRemoteServer(t *testing.T) (*Server, *remoteApp, *atomic.Bool) {
	t.Helper()
	srv := newTestServer(t)
	app := &remoteApp{}
	ro := &atomic.Bool{}
	srv.app, srv.token, srv.readOnly = app, "uygulama-anahtari-123", ro.Load
	return srv, app, ro
}

func TestRemoteEndpoints(t *testing.T) {
	srv, app, _ := newRemoteServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	if rec := do(t, h, http.MethodGet, "/api/app/apps", nil, read); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SHA256:abc") {
		t.Fatalf("apps: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/remote?device=Bad!", nil, read); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad device: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/remote?device=nas", nil, read); rec.Code != http.StatusOK {
		t.Fatalf("remote: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/wake", map[string]string{"device": "masaustu"}, read); rec.Code != http.StatusForbidden {
		t.Fatalf("wake without CSRF: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/wake", map[string]string{"device": "masaustu"}, signed); rec.Code != http.StatusOK || app.woke != "masaustu" {
		t.Fatalf("wake: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/speedtest", map[string]any{"device": "nas", "seconds": 60}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("long speedtest: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/speedtest", map[string]any{"device": "nas", "seconds": 3}, signed); rec.Code != http.StatusOK || app.speedDev != "nas" {
		t.Fatalf("speedtest: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/inbox/decide", map[string]any{"id": "abc", "accept": true}, signed); rec.Code != http.StatusOK || !app.decided["abc"] {
		t.Fatalf("decide: %d", rec.Code)
	}
	// Download is an attachment of opaque bytes.
	rec := do(t, h, http.MethodGet, "/api/app/inbox/file?name=rapor.pdf", nil, read)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") || rec.Body.String() != "pdf" {
		t.Fatalf("download: %d %v", rec.Code, rec.Header())
	}
	// Upload: raw body with CSRF.
	req := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/app/files/send?device=nas&name=a.txt", strings.NewReader("merhaba"))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/octet-stream")
	signed(req)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || string(app.sent) != "merhaba" {
		t.Fatalf("send: %d %s", w.Code, w.Body)
	}
}

func TestRemoteEndpointsReadOnly(t *testing.T) {
	srv, app, ro := newRemoteServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	ro.Store(true)
	for _, path := range []string{
		"/api/app/inbox/decide", "/api/app/inbox/delete", "/api/app/inbox/auto-accept",
		"/api/app/files/send", "/api/app/wake", "/api/app/wake/mac", "/api/app/speedtest",
	} {
		rec := do(t, h, http.MethodPost, path, map[string]any{}, signed)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "salt okunur") {
			t.Errorf("%s in read-only mode: %d %s", path, rec.Code, rec.Body)
		}
	}
	if app.woke != "" || app.decided != nil || app.deleted != "" || app.autoOn != nil {
		t.Fatal("a refused request reached the app")
	}
	if rec := do(t, h, http.MethodGet, "/api/app/inbox", nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusOK {
		t.Fatalf("inbox read in read-only mode: %d", rec.Code)
	}
}

func TestCLIInboxNeedsAppToken(t *testing.T) {
	srv, app, _ := newRemoteServer(t)
	h := srv.Handler()
	if rec := do(t, h, http.MethodGet, "/api/app/cli/inbox", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/cli/inbox/decide", map[string]any{"id": "abc", "accept": false}, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+srv.token)
		withOrigin(r)
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("browser origin with token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/cli/inbox/decide", map[string]any{"id": "abc", "accept": false}, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+srv.token)
	}); rec.Code != http.StatusOK || app.decided["abc"] {
		t.Fatalf("cli decide: %d", rec.Code)
	}
}

func TestRemoteEndpointsNeedRemoteApp(t *testing.T) {
	srv, _, _ := newFeatureServer(t)
	h := srv.Handler()
	cookie, _ := login(t, srv)
	if rec := do(t, h, http.MethodGet, "/api/app/inbox", nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusNotFound {
		t.Fatalf("app without services: %d", rec.Code)
	}
}
