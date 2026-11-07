package panel

import (
	"encoding/json"
	"net/http"
	"testing"
)

type dnsEnforceApp struct {
	featureApp
	on  bool
	set int
}

func (a *dnsEnforceApp) DNSEnforceStatus() (DNSEnforceStatus, error) {
	return DNSEnforceStatus{Supported: true, On: a.on, Reason: "Kapalı."}, nil
}

func (a *dnsEnforceApp) SetDNSEnforce(on bool) (DNSEnforceStatus, error) {
	a.on = on
	a.set++
	return a.DNSEnforceStatus()
}

func TestDNSEnforceRoutes(t *testing.T) {
	srv := newTestServer(t)
	app := &dnsEnforceApp{}
	srv.app = app
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	if rec := do(t, h, http.MethodGet, "/api/app/dns-enforce", nil, func(*http.Request) {}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("oturumsuz: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/dns-enforce", DNSEnforceRequest{On: true}, read); rec.Code != http.StatusForbidden || app.set != 0 {
		t.Fatalf("CSRF'siz: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/app/dns-enforce", DNSEnforceRequest{On: true}, signed)
	var st DNSEnforceStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || !st.On || !app.on {
		t.Fatalf("açma: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/dns-enforce", nil, read); rec.Code != http.StatusOK {
		t.Fatalf("okuma: %d", rec.Code)
	}
	// A service without the control answers 404.
	srv.app = &featureApp{}
	if rec := do(t, srv.Handler(), http.MethodGet, "/api/app/dns-enforce", nil, read); rec.Code != http.StatusNotFound {
		t.Fatalf("denetimsiz: %d", rec.Code)
	}
}
