package panel

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// trafficApp is featureApp plus traffic, rdesk and helper endpoints.
type trafficApp struct {
	featureApp
	settings TrafficSettings
	set      int
	helperOK bool
	asked    string
}

func (a *trafficApp) TrafficStatus() TrafficStatus { return TrafficStatus{Settings: a.settings} }
func (a *trafficApp) SetTraffic(c TrafficChange) error {
	a.set++
	if c.Padding != nil {
		a.settings.Padding = *c.Padding
	}
	if c.CoverTraffic != nil {
		a.settings.CoverTraffic = *c.CoverTraffic
	}
	return nil
}
func (a *trafficApp) RDeskHelperAllowed(token, _, _ string) bool {
	return a.helperOK && token == "yardimci"
}
func (a *trafficApp) RDeskHelperAuthorize(remote netip.Addr, mode string) RDeskHelperDecision {
	a.asked = remote.String() + "/" + mode
	return RDeskHelperDecision{Allowed: true, Peer: "laptop"}
}
func (a *trafficApp) RDeskHelperState() RDeskHelperState { return RDeskHelperState{Generation: 7} }
func (a *trafficApp) RDeskHelperEvent(RDeskHelperEvent)  {}
func (a *trafficApp) RDeskHelperPower(RDeskHelperPower) error {
	return nil
}

func TestTrafficCostMustBeAcknowledged(t *testing.T) {
	srv := newTestServer(t)
	app := &trafficApp{settings: TrafficSettings{Padding: "off"}}
	srv.app = app
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	// Turning padding on without the cost acknowledgement is refused.
	if rec := do(t, h, http.MethodPost, "/api/app/traffic", map[string]any{"padding": "mtu"}, signed); rec.Code != http.StatusPreconditionRequired || app.set != 0 {
		t.Fatalf("no ack: %d %s", rec.Code, rec.Body)
	}
	rec := do(t, h, http.MethodGet, "/api/app/traffic/cost?padding=mtu&cover=1024", nil, read)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ack"`) {
		t.Fatalf("cost: %d %s", rec.Code, rec.Body)
	}
	c, err := ComputeTrafficCost("mtu", 1024, 0)
	if err != nil || c.PaddingPercent <= 0 || c.BytesPerDay <= 0 {
		t.Fatalf("cost values: %+v %v", c, err)
	}
	// An acknowledgement of other values does not count.
	if rec := do(t, h, http.MethodPost, "/api/app/traffic", map[string]any{"padding": "mtu", "coverTraffic": 2048, "costAck": c.Ack}, signed); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("wrong ack: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/traffic", map[string]any{"padding": "mtu", "coverTraffic": 1024, "costAck": c.Ack}, signed); rec.Code != http.StatusOK || app.set != 1 {
		t.Fatalf("with ack: %d %s", rec.Code, rec.Body)
	}
	// Turning them off needs no acknowledgement.
	if rec := do(t, h, http.MethodPost, "/api/app/traffic", map[string]any{"padding": "off", "coverTraffic": 0}, signed); rec.Code != http.StatusOK || app.set != 2 {
		t.Fatalf("off: %d %s", rec.Code, rec.Body)
	}
}

func TestRDeskHelperEndpointsNeedHelperToken(t *testing.T) {
	srv := newTestServer(t)
	app := &trafficApp{}
	srv.app = app
	h := srv.Handler()
	body := map[string]string{"remote": "100.80.0.2", "mode": "view"}
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+tok)
			local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47821}
			*r = *r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/app/rdesk-helper/authorize", body, bearer("yardimci")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("helper not running: %d", rec.Code)
	}
	app.helperOK = true
	if rec := do(t, h, http.MethodPost, "/api/app/rdesk-helper/authorize", body, bearer("baska")); rec.Code != http.StatusUnauthorized || app.asked != "" {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/rdesk-helper/authorize", body, func(r *http.Request) { bearer("yardimci")(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("browser origin must be refused: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/app/rdesk-helper/authorize", body, bearer("yardimci"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allowed":true`) || app.asked != "100.80.0.2/view" {
		t.Fatalf("authorize: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/rdesk-helper/authorize", map[string]string{"remote": "x", "mode": "admin"}, bearer("yardimci")); !strings.Contains(rec.Body.String(), `"allowed":false`) {
		t.Fatalf("bad request must be refused: %s", rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/app/rdesk-helper/state", nil, bearer("yardimci")); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"generation":7`) {
		t.Fatalf("state: %d %s", rec.Code, rec.Body)
	}
}
