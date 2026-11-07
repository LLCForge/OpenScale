package panel

import (
	"encoding/json"
	"net/http"
	"testing"
)

type autoUpdateApp struct {
	featureApp
	on  bool
	set int
}

func (a *autoUpdateApp) AutoUpdateStatus() (AutoUpdateStatus, error) {
	return AutoUpdateStatus{Supported: true, Enabled: a.on, State: "waiting-key", Message: "Sürüm imzalama anahtarı kurulmadığı için otomatik güncelleme bekliyor.", Current: "1.0.0-beta.2"}, nil
}

func (a *autoUpdateApp) SetAutoUpdate(on bool) (AutoUpdateStatus, error) {
	a.on = on
	a.set++
	return a.AutoUpdateStatus()
}

func TestAutoUpdateRoutes(t *testing.T) {
	srv := newTestServer(t)
	app := &autoUpdateApp{on: true}
	srv.app = app
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	if rec := do(t, h, http.MethodGet, "/api/app/auto-update", nil, func(*http.Request) {}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("oturumsuz: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/auto-update", AutoUpdateRequest{On: false}, read); rec.Code != http.StatusForbidden || app.set != 0 {
		t.Fatalf("CSRF'siz: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/app/auto-update", AutoUpdateRequest{On: false}, signed)
	var st AutoUpdateStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Enabled || app.on {
		t.Fatalf("kapatma: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/auto-update", nil, read); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.State != "waiting-key" {
		t.Fatalf("okuma: %d %s", rec.Code, rec.Body)
	}
	srv.app = &featureApp{}
	if rec := do(t, srv.Handler(), http.MethodGet, "/api/app/auto-update", nil, read); rec.Code != http.StatusNotFound {
		t.Fatalf("denetimsiz: %d", rec.Code)
	}
}
