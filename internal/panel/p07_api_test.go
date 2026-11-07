package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// p07App implements the P07 endpoints.
type p07App struct {
	featureApp
	pause   *SyncPauseRequest
	cleared string
	ddns    DDNSConfigRequest
	links   int
	scanned string
}

func (a *p07App) SyncGuardStatus() (SyncGuardStatus, error) {
	return SyncGuardStatus{ProbeHours: 24}, nil
}
func (a *p07App) SetSyncPause(r SyncPauseRequest) (SyncGuardStatus, error) {
	a.pause = &r
	return SyncGuardStatus{Paused: r.Paused}, nil
}
func (a *p07App) SetSyncGuard(SyncGuardRequest) (SyncGuardStatus, error) {
	return SyncGuardStatus{}, nil
}
func (a *p07App) ClearSyncAlarm(id string) (SyncGuardStatus, error) {
	if id == "yok" {
		return SyncGuardStatus{}, errors.New("böyle bir klasör yok")
	}
	a.cleared = id
	return SyncGuardStatus{}, nil
}
func (a *p07App) ProbeBackup(context.Context) (SyncGuardStatus, error) {
	return SyncGuardStatus{Probe: &BackupProbeStatus{OK: true}}, nil
}
func (a *p07App) DDNSStatus() (DDNSStatus, error) { return DDNSStatus{}, nil }
func (a *p07App) SetDDNS(r DDNSConfigRequest) (DDNSStatus, error) {
	a.ddns = r
	return DDNSStatus{Updater: DDNSUpdaterView{Enabled: r.Enabled, KeySet: r.Secret != nil}}, nil
}
func (a *p07App) DDNSCheckNow(context.Context) (DDNSStatus, error) {
	return DDNSStatus{Check: &DDNSCheckView{Status: "stale"}}, nil
}
func (a *p07App) DDNSUpdateNow(context.Context) (DDNSStatus, error) { return DDNSStatus{}, nil }
func (a *p07App) FileLinks() (FileLinksStatus, error)               { return FileLinksStatus{}, nil }
func (a *p07App) CreateFileLink(r FileLinkRequest) (FileLinkCreated, error) {
	a.links++
	return FileLinkCreated{URL: "http://laptop.openscale.internal:4051/l/x", Link: FileLinkView{Device: r.Device}}, nil
}
func (a *p07App) RevokeFileLink(string) (FileLinksStatus, error) { return FileLinksStatus{}, nil }
func (a *p07App) FileScanStatus() (FileScanStatus, error)        { return FileScanStatus{}, nil }
func (a *p07App) SetFileScan(FileScanRequest) (FileScanStatus, error) {
	return FileScanStatus{Enabled: true}, nil
}
func (a *p07App) ScanInboxFile(_ context.Context, name string) (FileScanStatus, error) {
	a.scanned = name
	return FileScanStatus{}, nil
}
func (a *p07App) SubnetInventory() (SubnetInventory, error) { return SubnetInventory{}, nil }
func (a *p07App) ServeSuggestions(context.Context) (ServeSuggestions, error) {
	return ServeSuggestions{}, nil
}

func TestP07Routes(t *testing.T) {
	srv := newTestServer(t)
	app := &p07App{}
	srv.app = app
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	// Reads need a session, writes need the CSRF token too.
	if rec := do(t, h, http.MethodGet, "/api/app/sync/guard", nil, func(*http.Request) {}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/sync/pause", SyncPauseRequest{Paused: true}, read); rec.Code != http.StatusForbidden || app.pause != nil {
		t.Fatalf("no csrf: %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/api/app/sync/guard", nil, read)
	var st SyncGuardStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Schema != P07Schema || st.Pauses == nil || st.Folders == nil {
		t.Fatalf("guard: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/sync/pause", SyncPauseRequest{Paused: true, Hours: 5}, signed); rec.Code != http.StatusOK || app.pause == nil || app.pause.Hours != 5 {
		t.Fatalf("pause: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/sync/pause", SyncPauseRequest{Paused: true, Hours: 10000}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("long pause: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/sync/guard/clear", SyncFolderRequest{ID: "notlar"}, signed); rec.Code != http.StatusOK || app.cleared != "notlar" {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/sync/guard/clear", SyncFolderRequest{ID: "yok"}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("clear unknown: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/sync/backup/probe", nil, signed); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"probe"`) {
		t.Fatalf("probe: %d %s", rec.Code, rec.Body)
	}
	secret := "c2lmcmUtZGVnZXJpLTEyMzQ1Ng=="
	if rec := do(t, h, http.MethodPost, "/api/app/ddns", DDNSConfigRequest{Enabled: true, Server: "192.0.2.53:53", Zone: "ornek.test", Name: "ev.ornek.test", KeyName: "k", Secret: &secret}, signed); rec.Code != http.StatusOK || app.ddns.Name != "ev.ornek.test" {
		t.Fatalf("ddns: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("secret echoed")
	}
	if rec := do(t, h, http.MethodPost, "/api/app/ddns", DDNSConfigRequest{Server: strings.Repeat("1", 100)}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("long server: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/ddns/check", nil, signed); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "stale") {
		t.Fatalf("check: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/files/links", FileLinkRequest{Path: "C:/x/a.pdf", Device: "nas", Hours: 1, Downloads: 1}, signed); rec.Code != http.StatusOK || app.links != 1 {
		t.Fatalf("link: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/files/links", FileLinkRequest{Device: "nas"}, signed); rec.Code != http.StatusBadRequest || app.links != 1 {
		t.Fatalf("empty path: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/files/scan/run", FileNameRequest{Name: "rapor.pdf"}, signed); rec.Code != http.StatusOK || app.scanned != "rapor.pdf" {
		t.Fatalf("scan: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/api/app/ddns", "/api/app/files/links", "/api/app/files/scan", "/api/app/routes/inventory", "/api/app/serve/suggestions"} {
		if rec := do(t, h, http.MethodGet, p, nil, read); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"schema":1`) {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
}

func TestP07RoutesWithoutService(t *testing.T) {
	srv := newTestServer(t)
	srv.app = &featureApp{}
	h := srv.Handler()
	cookie, _ := login(t, srv)
	if rec := do(t, h, http.MethodGet, "/api/app/sync/guard", nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusNotFound {
		t.Fatalf("no service: %d", rec.Code)
	}
}
