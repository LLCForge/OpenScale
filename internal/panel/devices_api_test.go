package panel

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func TestDeviceDetailAndExitNode(t *testing.T) {
	srv := newTestServer(t)
	secrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := secrets.NewEnrollmentRequest("laptop", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, err := trust.OpenEnrollmentRequest(env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	n := srv.network()
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		if _, err := doc.AddDevice(req, "laptop", nil, time.Now(), trust.DefaultDeviceLife); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"*"}, To: []string{"laptop"}, Protocol: trust.ProtocolICMP})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, []byte(testPass)); err != nil {
		t.Fatal(err)
	}

	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		withOrigin(r)
	}

	rec := do(t, h, http.MethodGet, "/api/devices/detail?name=laptop", nil, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status %d: %s", rec.Code, rec.Body)
	}
	var d deviceDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Fingerprint != req.Fingerprint() || d.WireGuardKey != req.WireGuardKey.String() || len(d.Incoming) != 1 || len(d.Outgoing) != 0 || d.ExitNode {
		t.Fatalf("unexpected detail %+v", d)
	}
	if rec := do(t, h, http.MethodGet, "/api/devices/detail?name=yok", nil, auth); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown device status %d", rec.Code)
	}

	body := map[string]any{"name": "laptop", "exitNode": true, "passphrase": testPass}
	if rec := do(t, h, http.MethodPost, "/api/devices/exit-node", body, auth); rec.Code != http.StatusOK {
		t.Fatalf("exit node status %d: %s", rec.Code, rec.Body)
	}
	doc, _ := n.Document()
	if dev, _ := doc.DeviceByName("laptop"); !dev.HasRole(trust.RoleExitNode) {
		t.Fatal("exit node role not signed")
	}
	body["exitNode"] = false
	if rec := do(t, h, http.MethodPost, "/api/devices/exit-node", body, auth); rec.Code != http.StatusOK {
		t.Fatalf("exit node off status %d: %s", rec.Code, rec.Body)
	}
	doc, _ = n.Document()
	if dev, _ := doc.DeviceByName("laptop"); dev.HasRole(trust.RoleExitNode) {
		t.Fatal("exit node role not removed")
	}
}
