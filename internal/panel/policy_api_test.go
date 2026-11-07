package panel

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// policyServer returns a signed-in panel whose network has the devices
// laptop and masaustu, the laptop's key secrets and a request helper.
func policyServer(t *testing.T) (*Server, *trust.DeviceSecrets, func(method, path string, body any) (int, string)) {
	t.Helper()
	srv := newTestServer(t)
	n := srv.network()
	var laptop *trust.DeviceSecrets
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		for _, name := range []string{"laptop", "masaustu"} {
			s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
			if err != nil {
				return err
			}
			env, _, err := s.NewEnrollmentRequest(name, time.Now())
			if err != nil {
				return err
			}
			req, err := trust.OpenEnrollmentRequest(env, time.Now())
			if err != nil {
				return err
			}
			if _, err := doc.AddDevice(req, name, nil, time.Now(), trust.DefaultDeviceLife); err != nil {
				return err
			}
			if name == "laptop" {
				laptop = s
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set("X-CSRF-Token", csrf); withOrigin(r) }
	call := func(method, path string, body any) (int, string) {
		rec := do(t, h, method, path, body, auth)
		// JSON escapes "<" and ">"; the checks below read the plain text.
		esc := func(hex string) string { return "\\" + "u00" + hex }
		text := strings.NewReplacer(esc("3e"), ">", esc("3c"), "<").Replace(rec.Body.String())
		return rec.Code, text
	}
	return srv, laptop, call
}

func signed(body map[string]any) map[string]any {
	body["passphrase"] = testPass
	return body
}

func TestDeviceEditEndpoints(t *testing.T) {
	srv, _, call := policyServer(t)
	n := srv.network()

	// Dry run shows the change without signing.
	code, body := call(http.MethodPost, "/api/devices/extend", map[string]any{"name": "laptop", "lifetimeDays": 30, "dryRun": true})
	if code != http.StatusOK || !strings.Contains(body, "üyelik bitişi") {
		t.Fatalf("extend dry run: %d %s", code, body)
	}
	doc, _ := n.Document()
	before := doc.Version
	for _, bad := range []map[string]any{
		{"name": "laptop", "lifetimeDays": 0},
		{"name": "laptop", "lifetimeDays": 3651},
		{"name": "Büyük", "lifetimeDays": 30},
	} {
		if code, _ := call(http.MethodPost, "/api/devices/extend", signed(bad)); code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, code)
		}
	}
	if code, body := call(http.MethodPost, "/api/devices/extend", signed(map[string]any{"name": "laptop", "lifetimeDays": 30})); code != http.StatusOK {
		t.Fatalf("extend: %d %s", code, body)
	}
	if code, body := call(http.MethodPost, "/api/devices/expire", signed(map[string]any{"name": "masaustu"})); code != http.StatusOK {
		t.Fatalf("expire: %d %s", code, body)
	}
	if code, body := call(http.MethodPost, "/api/devices/tags", signed(map[string]any{"name": "laptop", "tags": []string{"tag:sunucu", "ev"}})); code != http.StatusOK {
		t.Fatalf("tags: %d %s", code, body)
	}
	if code, _ := call(http.MethodPost, "/api/devices/tags", signed(map[string]any{"name": "laptop", "tags": make([]string, 17)})); code != http.StatusBadRequest {
		t.Fatalf("17 tags: %d", code)
	}
	if code, body := call(http.MethodPost, "/api/devices/rename", signed(map[string]any{"name": "laptop", "newName": "masaustu"})); code != http.StatusBadRequest || !strings.Contains(body, "zaten kullanılıyor") {
		t.Fatalf("taken name: %d %s", code, body)
	}
	if code, body := call(http.MethodPost, "/api/devices/rename", signed(map[string]any{"name": "laptop", "newName": "dizustu"})); code != http.StatusOK {
		t.Fatalf("rename: %d %s", code, body)
	}
	doc, _ = n.Document()
	d, ok := doc.DeviceByName("dizustu")
	if !ok || strings.Join(d.Tags, ",") != "sunucu,ev" || doc.Version != before+4 {
		t.Fatalf("after edits: %+v version %d", d, doc.Version)
	}
	code, body = call(http.MethodGet, "/api/devices/detail?name=dizustu", nil)
	var detail deviceDetail
	if code != http.StatusOK || json.Unmarshal([]byte(body), &detail) != nil || len(detail.Tags) != 2 || !detail.MayUseExitNode {
		t.Fatalf("detail: %d %s", code, body)
	}
}

func TestKeyRotationEndpoints(t *testing.T) {
	srv, laptop, call := policyServer(t)
	doc, _ := srv.network().Document()
	_, signedRot, req, err := laptop.NewKeyRotation(rand.Reader, doc.NetworkID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	line, err := trust.EncodeKeyRotation(signedRot)
	if err != nil {
		t.Fatal(err)
	}
	code, body := call(http.MethodPost, "/api/devices/rotation/inspect", map[string]any{"request": line})
	if code != http.StatusOK || !strings.Contains(body, `"deviceName":"laptop"`) {
		t.Fatalf("inspect: %d %s", code, body)
	}
	// The fingerprint is never handed out by the panel.
	if strings.Contains(body, req.Fingerprint()) {
		t.Fatal("inspect revealed the fingerprint")
	}
	if code, _ := call(http.MethodPost, "/api/devices/rotation", signed(map[string]any{"request": line})); code != http.StatusBadRequest {
		t.Fatalf("missing fingerprint: %d", code)
	}
	code, body = call(http.MethodPost, "/api/devices/rotation", map[string]any{"request": line, "fingerprint": "AAAA-BBBB-CCCC-DDDD", "dryRun": true})
	if code != http.StatusBadRequest || !strings.Contains(body, "Parmak izleri eşleşmiyor") {
		t.Fatalf("wrong fingerprint in dry run: %d %s", code, body)
	}
	code, body = call(http.MethodPost, "/api/devices/rotation", signed(map[string]any{"request": line, "fingerprint": strings.ToLower(req.Fingerprint())}))
	if code != http.StatusOK || !strings.Contains(body, "anahtarlar yenilendi") {
		t.Fatalf("rotation: %d %s", code, body)
	}
	doc, _ = srv.network().Document()
	if d, _ := doc.DeviceByName("laptop"); d.WireGuardKey != req.NewWireGuardKey {
		t.Fatal("new key not signed")
	}
	if code, _ := call(http.MethodPost, "/api/devices/rotation", signed(map[string]any{"request": line, "fingerprint": req.Fingerprint()})); code != http.StatusBadRequest {
		t.Fatalf("replayed rotation: %d", code)
	}
}

func TestRulesGroupsAndExitUsersEndpoints(t *testing.T) {
	srv, _, call := policyServer(t)
	if code, body := call(http.MethodPost, "/api/groups", signed(map[string]any{"name": "ofis", "members": []string{"laptop", "tag:sunucu"}})); code != http.StatusOK {
		t.Fatalf("group: %d %s", code, body)
	}
	if code, _ := call(http.MethodPost, "/api/groups", signed(map[string]any{"name": "Ofis", "members": []string{}})); code != http.StatusBadRequest {
		t.Fatalf("bad group name: %d", code)
	}
	rule := signed(map[string]any{"from": []string{"group:ofis"}, "to": []string{"masaustu"}, "protocol": "47", "ports": []string{}, "description": "GRE", "action": "deny"})
	if code, body := call(http.MethodPost, "/api/rules", rule); code != http.StatusOK || !strings.Contains(body, "reddet: group:ofis -> masaustu 47") {
		t.Fatalf("deny rule: %d %s", code, body)
	}
	for _, bad := range []map[string]any{
		{"from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "6", "ports": []string{}, "description": ""},
		{"from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "any", "ports": []string{}, "description": "", "action": "belki"},
	} {
		if code, _ := call(http.MethodPost, "/api/rules", signed(bad)); code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, code)
		}
	}
	if code, body := call(http.MethodPost, "/api/rules/state", signed(map[string]any{"index": 0, "disabled": true})); code != http.StatusOK || !strings.Contains(body, "(kapalı)") {
		t.Fatalf("disable: %d %s", code, body)
	}
	if code, _ := call(http.MethodPost, "/api/rules/state", signed(map[string]any{"index": 5, "disabled": true})); code != http.StatusBadRequest {
		t.Fatalf("missing rule: %d", code)
	}
	code, body := call(http.MethodGet, "/api/rules", nil)
	var rules rulesResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &rules) != nil {
		t.Fatalf("rules: %d %s", code, body)
	}
	if len(rules.Rules) != 1 || rules.Rules[0].Action != "deny" || !rules.Rules[0].Disabled || rules.Rules[0].Protocol != "47" {
		t.Fatalf("rule view: %+v", rules.Rules)
	}
	if len(rules.Groups) != 1 || rules.Groups[0].UsedBy != 1 || strings.Join(rules.UnusedTags, ",") != "sunucu" {
		t.Fatalf("groups/tags: %+v %v", rules.Groups, rules.UnusedTags)
	}
	// A used group cannot be removed.
	if code, _ := call(http.MethodPost, "/api/groups/remove", signed(map[string]any{"name": "ofis"})); code != http.StatusBadRequest {
		t.Fatalf("remove used group: %d", code)
	}
	// The overview warns about the tag nobody carries.
	if _, body := call(http.MethodGet, "/api/overview", nil); !strings.Contains(body, HealthUnusedTag) {
		t.Fatalf("overview lacks the tag warning: %s", body)
	}

	if code, body := call(http.MethodPost, "/api/network/exit-users", signed(map[string]any{"restricted": true, "users": []string{}})); code != http.StatusOK || !strings.Contains(body, "herkes -> hiçbir cihaz") {
		t.Fatalf("exit users none: %d %s", code, body)
	}
	if code, _ := call(http.MethodPost, "/api/network/exit-users", signed(map[string]any{"restricted": false, "users": []string{"laptop"}})); code != http.StatusBadRequest {
		t.Fatalf("contradictory request: %d", code)
	}
	code, body = call(http.MethodGet, "/api/network", nil)
	if code != http.StatusOK || !strings.Contains(body, `"exitUsers":{"restricted":true,"users":[]}`) {
		t.Fatalf("network exit users: %s", body)
	}
	if code, body := call(http.MethodPost, "/api/network/exit-users", signed(map[string]any{"restricted": false})); code != http.StatusOK {
		t.Fatalf("clear exit users: %d %s", code, body)
	}
	_ = srv
}

func TestDNSAndNameEndpoints(t *testing.T) {
	srv, _, call := policyServer(t)
	doc, _ := srv.network().Document()
	pc, _ := doc.DeviceByName("masaustu")
	body := signed(map[string]any{"nameservers": []string{pc.IPv4.String()}, "split": []map[string]any{{"domain": "Ev.Lan.", "nameservers": []string{pc.IPv6.String()}}}})
	if code, resp := call(http.MethodPost, "/api/network/dns", body); code != http.StatusOK || !strings.Contains(resp, "ev.lan =>") {
		t.Fatalf("dns: %d %s", code, resp)
	}
	code, resp := call(http.MethodGet, "/api/network", nil)
	var net networkResponse
	if code != http.StatusOK || json.Unmarshal([]byte(resp), &net) != nil || net.DNS == nil || len(net.DNS.Split) != 1 || len(net.DNSWarnings) != 1 || len(net.Resolvers) != 2 {
		t.Fatalf("network dns view: %s", resp)
	}
	for _, bad := range []map[string]any{
		{"nameservers": []string{"8.8.8.8"}},
		{"nameservers": []string{"yok"}},
		{"nameservers": []string{}, "split": []map[string]any{}},
		{"split": []map[string]any{{"domain": "lan", "nameservers": []string{}}}},
		{"split": []map[string]any{{"domain": "openscale.internal", "nameservers": []string{pc.IPv4.String()}}}},
	} {
		if code, _ := call(http.MethodPost, "/api/network/dns", signed(bad)); code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, code)
		}
	}
	if code, resp := call(http.MethodPost, "/api/network/dns", signed(map[string]any{"clear": true})); code != http.StatusOK || !strings.Contains(resp, "-> yok") {
		t.Fatalf("clear dns: %d %s", code, resp)
	}

	if code, resp := call(http.MethodPost, "/api/network/name", signed(map[string]any{"displayName": "  Ev ağı "})); code != http.StatusOK || !strings.Contains(resp, "Ağ adı: yok -> Ev ağı") {
		t.Fatalf("name: %d %s", code, resp)
	}
	for _, bad := range []string{"a‮b", strings.Repeat("ş", 65), "a\nb"} {
		if code, _ := call(http.MethodPost, "/api/network/name", signed(map[string]any{"displayName": bad})); code != http.StatusBadRequest {
			t.Fatalf("%q: %d", bad, code)
		}
	}
	if _, resp := call(http.MethodGet, "/api/overview", nil); !strings.Contains(resp, `"displayName":"Ev ağı"`) {
		t.Fatalf("overview name: %s", resp)
	}
}

// settingsApp records the network DNS and advanced settings calls.
type settingsApp struct {
	App
	accept   *bool
	advanced *AdvancedSettings
}

func (a *settingsApp) Status() AppStatus { return AppStatus{Mode: ModeMember, Health: []HealthAlert{}} }

func (a *settingsApp) SetAcceptNetworkDNS(on bool) error { a.accept = &on; return nil }

func (a *settingsApp) SetAdvanced(s AdvancedSettings) error { a.advanced = &s; return nil }

func TestAppSettingsEndpoints(t *testing.T) {
	srv := newTestServer(t)
	app := &settingsApp{}
	ro := &atomic.Bool{}
	srv.app, srv.readOnly = app, ro.Load
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set("X-CSRF-Token", csrf); withOrigin(r) }

	if rec := do(t, h, http.MethodPost, "/api/app/dns", map[string]any{}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing choice: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/dns", map[string]any{"accept": false}, auth); rec.Code != http.StatusOK || app.accept == nil || *app.accept {
		t.Fatalf("dns choice: %d", rec.Code)
	}
	for _, bad := range []map[string]any{{}, {"mtu": -1}, {"mtu": 100000}, {"relayRate": -5}} {
		if rec := do(t, h, http.MethodPost, "/api/app/advanced", bad, auth); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/app/advanced", map[string]any{"forceRelay": true}, auth); rec.Code != http.StatusOK || app.advanced == nil || app.advanced.ForceRelay == nil || app.advanced.MTU != nil {
		t.Fatalf("advanced: %d %+v", rec.Code, app.advanced)
	}

	// Read-only mode refuses every new change endpoint.
	ro.Store(true)
	app.accept, app.advanced = nil, nil
	for _, path := range []string{
		"/api/devices/extend", "/api/devices/expire", "/api/devices/rename", "/api/devices/tags", "/api/devices/rotation",
		"/api/groups", "/api/groups/remove", "/api/rules/state", "/api/network/exit-users", "/api/network/dns", "/api/network/name",
		"/api/app/dns", "/api/app/advanced",
	} {
		rec := do(t, h, http.MethodPost, path, map[string]any{}, auth)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "salt okunur") {
			t.Errorf("%s in read-only mode: %d %s", path, rec.Code, rec.Body)
		}
	}
	if app.accept != nil || app.advanced != nil {
		t.Fatal("a refused request reached the app")
	}
	// Inspecting a rotation request changes nothing and stays available.
	if rec := do(t, h, http.MethodPost, "/api/devices/rotation/inspect", map[string]string{"request": "x"}, auth); rec.Code == http.StatusForbidden {
		t.Fatalf("inspect is not a change: %d", rec.Code)
	}
}

func TestInviteTagsEndpoints(t *testing.T) {
	srv, _, call := policyServer(t)
	// Invites need a coordinator in the document.
	n := srv.network()
	s, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, wg, _ := s.PublicKeys()
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.SetCoordinator("vpn.ornek.com:51820", wg)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(http.MethodPost, "/api/invites", map[string]any{"passphrase": testPass, "tags": make([]string, 17)}); code != http.StatusBadRequest {
		t.Fatalf("17 tags: %d", code)
	}
	if code, body := call(http.MethodPost, "/api/invites", map[string]any{"passphrase": testPass, "tags": []string{"sunucu"}}); code != http.StatusOK {
		t.Fatalf("tagged invite: %d %s", code, body)
	}
	code, body := call(http.MethodGet, "/api/invites", nil)
	if code != http.StatusOK || !strings.Contains(body, `"tags":["sunucu"]`) {
		t.Fatalf("invites: %d %s", code, body)
	}
}
