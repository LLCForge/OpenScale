package panel

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openscale/openscale/internal/sysinfo"
)

type netPlacesApp struct {
	featureApp
	on  bool
	set int
}

func (a *netPlacesApp) NetPlacesStatus() (NetPlacesStatus, error) {
	return NetPlacesStatus{Supported: true, On: a.on, Admin: true, Ready: true, Shares: 1,
		Devices: []NetPlaceDevice{{Name: "nas", Host: "nas.ev.openscale.internal", Known: true, Shares: []sysinfo.Share{{Name: "Arsiv"}}}}}, nil
}

func (a *netPlacesApp) SetNetPlaces(on bool) (NetPlacesStatus, error) {
	a.on = on
	a.set++
	return a.NetPlacesStatus()
}

func TestNetPlacesRoutes(t *testing.T) {
	srv := newTestServer(t)
	app := &netPlacesApp{on: true}
	srv.app, srv.token = app, "uygulama-anahtari-123"
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.token) }

	// The tray's list needs the app token; a browser never gets it.
	if rec := do(t, h, http.MethodGet, "/api/app/tray/netplaces", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tokenless tray: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/tray/netplaces", nil, func(r *http.Request) { bearer(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("browser with token: %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/api/app/tray/netplaces", nil, bearer)
	var st NetPlacesStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || len(st.Devices) != 1 || st.Devices[0].Shares[0].Name != "Arsiv" {
		t.Fatalf("tray: %d %s", rec.Code, rec.Body)
	}
	// The command line turns it off with the token.
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/netplaces", NetPlacesRequest{On: false}, bearer); rec.Code != http.StatusOK || app.on {
		t.Fatalf("cli off: %d %s", rec.Code, rec.Body)
	}
	// The panel: a session to read, CSRF to write.
	if rec := do(t, h, http.MethodGet, "/api/app/netplaces", nil, func(*http.Request) {}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sessionless: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/netplaces", NetPlacesRequest{On: true}, read); rec.Code != http.StatusForbidden || app.on {
		t.Fatalf("without CSRF: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/netplaces", NetPlacesRequest{On: true}, signed); rec.Code != http.StatusOK || !app.on {
		t.Fatalf("panel on: %d %s", rec.Code, rec.Body)
	}
	srv.app = &featureApp{}
	if rec := do(t, srv.Handler(), http.MethodGet, "/api/app/netplaces", nil, read); rec.Code != http.StatusNotFound {
		t.Fatalf("without control: %d", rec.Code)
	}
}
