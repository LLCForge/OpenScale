package panel

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func TestV1APIWithKeyAndSession(t *testing.T) {
	srv := newTestServer(t)
	names := []string{"d01", "d02", "d03", "d04", "d05"}
	devs := addTestDevices(t, srv, names, []trust.Rule{
		{From: []string{"d01"}, To: []string{"d02"}, Protocol: trust.ProtocolTCP, Ports: []string{"3389"}},
		{From: []string{"d03"}, To: []string{"d02"}, Service: trust.ServicePanel},
	})
	h := srv.Handler()
	key, _, err := CreateAPIKey(srv.network().Dir(), "betik", false, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+key) }

	if rec := do(t, h, http.MethodGet, "/api/v1/devices", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/devices", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer osk_00000000_x") }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/devices", nil, func(r *http.Request) { bearer(r); withOrigin(r) }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("key from a browser = %d", rec.Code)
	}

	// Pagination walks every device exactly once.
	var seen []string
	cursor := ""
	for i := 0; i < 10; i++ {
		target := "/api/v1/devices?limit=2"
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		rec := do(t, h, http.MethodGet, target, nil, func(r *http.Request) { bearer(r); r.Header.Set("X-Request-ID", "is-42") })
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d = %d %s", i, rec.Code, rec.Body)
		}
		if rec.Header().Get("X-Request-ID") != "is-42" {
			t.Fatal("request id not echoed")
		}
		var page APIPage[APIDevice]
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || page.Schema != APISchema || page.Total != len(devs) || len(page.Items) > 2 {
			t.Fatalf("page = %s", rec.Body)
		}
		for _, d := range page.Items {
			seen = append(seen, d.Name)
			if d.FQDN == "" || d.IPv4 == "" || d.Fingerprint == "" || d.Tags == nil {
				t.Fatalf("device = %+v", d)
			}
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	slices.Sort(seen)
	if !slices.Equal(seen, names) {
		t.Fatalf("seen = %v", seen)
	}

	for _, bad := range []string{"?limit=0", "?limit=101", "?cursor=-1", "?cursor=99", "?limit=x"} {
		rec := do(t, h, http.MethodGet, "/api/v1/devices"+bad, nil, bearer)
		var e APIError
		if rec.Code != http.StatusBadRequest || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.RequestID == "" {
			t.Fatalf("%s = %d %s", bad, rec.Code, rec.Body)
		}
	}
	rec := do(t, h, http.MethodGet, "/api/v1/devices", nil, func(r *http.Request) { bearer(r); r.Header.Set("X-Request-ID", "bad id\n") })
	if got := rec.Header().Get("X-Request-ID"); len(got) != 16 {
		t.Fatalf("invalid request id must be replaced, got %q", got)
	}

	rec = do(t, h, http.MethodGet, "/api/v1/rules", nil, bearer)
	var rules APIPage[APIRule]
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rules) != nil || rules.Total != 2 || rules.Items[1].Service != "panel" || rules.Items[0].Index != 1 || rules.Items[0].Action != "allow" {
		t.Fatalf("rules = %d %s", rec.Code, rec.Body)
	}

	rec = do(t, h, http.MethodGet, "/api/v1/whois?ip="+devs["d04"].IPv4.String(), nil, bearer)
	var who APIWhoisReply
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &who) != nil || who.Device.Name != "d04" {
		t.Fatalf("whois = %d %s", rec.Code, rec.Body)
	}
	for _, q := range []string{"192.0.2.1", "x", "fe80::1%eth0"} {
		if rec := do(t, h, http.MethodGet, "/api/v1/whois?ip="+q, nil, bearer); rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Fatalf("whois %s = %d", q, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/devices/d02", nil, bearer); rec.Code != http.StatusOK {
		t.Fatalf("device = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/devices/yok", nil, bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("missing device = %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/network", nil, bearer); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"device_count":5`) {
		t.Fatalf("network = %d %s", rec.Code, rec.Body)
	}
	// Read-only: every other method is refused, even with a session.
	auth := authed(t, srv)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if rec := do(t, h, m, "/api/v1/devices", nil, auth); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d", m, rec.Code)
		}
	}
	// The panel's session works too.
	if rec := do(t, h, http.MethodGet, "/api/v1/devices", nil, auth); rec.Code != http.StatusOK {
		t.Fatalf("session = %d", rec.Code)
	}
	// Without the desktop service there is no inventory.
	if rec := do(t, h, http.MethodGet, "/api/v1/devices/d02/services", nil, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("services without app = %d", rec.Code)
	}
}

func TestListeningServiceHints(t *testing.T) {
	srv := newTestServer(t)
	devs := addTestDevices(t, srv, []string{"masaustu", "laptop", "telefon"}, []trust.Rule{
		{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"5432"}},
	})
	doc, err := srv.network().Document()
	if err != nil {
		t.Fatal(err)
	}
	got := listeningServices(doc, devs["masaustu"], []uint16{3389, 5432, 8443, trust.SSHPort})
	if len(got) != 4 {
		t.Fatalf("services = %+v", got)
	}
	rdp, pg, unknown, own := got[0], got[1], got[2], got[3]
	if !rdp.Risky || len(rdp.ReachableFrom) != 0 || !strings.Contains(rdp.Hint, "hiçbir kural") {
		t.Fatalf("rdp = %+v", rdp)
	}
	if !pg.Risky || !slices.Equal(pg.ReachableFrom, []string{"laptop"}) || !strings.Contains(pg.Hint, "laptop") {
		t.Fatalf("postgres = %+v", pg)
	}
	if unknown.Name != "" || unknown.Risky || unknown.Hint != "" {
		t.Fatalf("unknown = %+v", unknown)
	}
	if !own.OpenScale || own.Hint != "" {
		t.Fatalf("own = %+v", own)
	}
}
