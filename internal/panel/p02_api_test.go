package panel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/enrollkit"
	"github.com/openscale/openscale/internal/trust"
)

func p02Server(t *testing.T) (*Server, http.Handler, func(*http.Request)) {
	t.Helper()
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	return srv, srv.Handler(), auth
}

func TestP02LikeLostAndCard(t *testing.T) {
	srv, h, auth := p02Server(t)
	addTestDevices(t, srv, []string{"laptop", "masaustu", "yeni"}, []trust.Rule{
		{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"3389"}},
		{From: []string{"masaustu"}, To: []string{"laptop"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}},
	})
	rec := do(t, h, http.MethodGet, "/api/p02/devices/like?source=laptop&target=yeni", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"rules":[{`) {
		t.Fatalf("like suggest: %d %s", rec.Code, rec.Body)
	}
	// A dry run shows the diff, then one signature applies it.
	rec = do(t, h, http.MethodPost, "/api/p02/devices/like", map[string]any{"source": "laptop", "target": "yeni", "rules": []int{0, 1}, "dryRun": true}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dryRun":true`) {
		t.Fatalf("like dry run: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/devices/like", map[string]any{"source": "laptop", "target": "yeni", "rules": []int{7}, "dryRun": true}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("out of range rule: %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/p02/devices/like", map[string]any{"source": "laptop", "target": "yeni", "rules": []int{0}, "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("like sign: %d %s", rec.Code, rec.Body)
	}
	doc, _ := srv.network().Document()
	if !doc.Allows("yeni", "masaustu", trust.ProtocolTCP, 3389) {
		t.Fatal("yeni did not get the rule")
	}
	// Lost device report and card.
	rec = do(t, h, http.MethodGet, "/api/p02/devices/lost?name=laptop", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "checklist") || !strings.Contains(rec.Body.String(), "uzak masaüstü") {
		t.Fatalf("lost report: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/p02/devices/card?name=laptop", nil, auth)
	var card connectionCard
	if err := json.Unmarshal(rec.Body.Bytes(), &card); err != nil || len(card.Services) != 1 || card.Services[0].Command == "" || !strings.HasPrefix(card.QR, "data:image/png;base64,") {
		t.Fatalf("card: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/devices/lost", map[string]any{"name": "laptop", "action": "sil", "passphrase": testPass}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad action: %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/p02/devices/lost", map[string]any{"name": "laptop", "action": "expire", "dropRules": true, "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("lost expire: %d %s", rec.Code, rec.Body)
	}
	doc, _ = srv.network().Document()
	for _, r := range doc.Rules {
		if len(r.From) == 1 && r.From[0] == "laptop" {
			t.Fatal("rule only for the lost device kept")
		}
	}
	rec = do(t, h, http.MethodPost, "/api/p02/devices/lost", map[string]any{"name": "laptop", "action": "revoke", "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("lost revoke: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/p02/devices/card?name=laptop", nil, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("card without session: %d", rec.Code)
	}
}

func setCoordinator(t *testing.T, srv *Server) {
	t.Helper()
	var k trust.Key
	_, _ = rand.Read(k[:])
	n := srv.network()
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.SetCoordinator("vpn.example.org:41820", k)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
}

func TestP02GuestSplitAndLauncher(t *testing.T) {
	srv, h, auth := p02Server(t)
	addTestDevices(t, srv, []string{"nas"}, nil)
	setCoordinator(t, srv)
	before, _ := srv.network().Document()
	guest := map[string]any{"label": "Ayşe", "target": "nas", "protocol": "tcp", "port": "8096", "hours": 48}
	dry := map[string]any{"dryRun": true}
	for k, v := range guest {
		dry[k] = v
	}
	rec := do(t, h, http.MethodPost, "/api/p02/guest", dry, auth)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"code"`) {
		t.Fatalf("guest dry run: %d %s", rec.Code, rec.Body)
	}
	guest["passphrase"] = testPass
	rec = do(t, h, http.MethodPost, "/api/p02/guest", guest, auth)
	var gr guestResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &gr) != nil || !strings.HasPrefix(gr.Code, "osinv1.") {
		t.Fatalf("guest: %d %s", rec.Code, rec.Body)
	}
	after, _ := srv.network().Document()
	if after.Version != before.Version+1 {
		t.Fatalf("guest wizard used %d signatures", after.Version-before.Version)
	}
	rec = do(t, h, http.MethodGet, "/api/p02/guests", nil, auth)
	if !strings.Contains(rec.Body.String(), gr.Tag) || !strings.Contains(rec.Body.String(), `"until"`) {
		t.Fatalf("guests: %s", rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/guest", map[string]any{"target": "nas", "protocol": "tcp", "port": "8096", "hours": 9999, "passphrase": testPass}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("long guest: %d", rec.Code)
	}

	rec = do(t, h, http.MethodPost, "/api/p02/invites/split", map[string]any{"passphrase": testPass}, auth)
	var sp struct{ PartA, PartB string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &sp) != nil {
		t.Fatalf("split: %d %s", rec.Code, rec.Body)
	}
	if _, err := trust.CombineInviteParts(sp.PartA, sp.PartB); err != nil {
		t.Fatalf("split parts: %v", err)
	}

	rec = do(t, h, http.MethodPost, "/api/p02/invites/launcher", map[string]any{"passphrase": testPass, "platform": "linux"}, auth)
	var ln struct{ FileName, Content string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ln) != nil {
		t.Fatalf("launcher: %d %s", rec.Code, rec.Body)
	}
	body, _ := base64.StdEncoding.DecodeString(ln.Content)
	if ln.FileName != "openscale-davet.sh" || !strings.Contains(string(body), "invite-join") {
		t.Fatalf("launcher body: %s", body)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/invites/launcher", map[string]any{"passphrase": testPass, "platform": "linux", "lifetimeHours": 48}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("long launcher invite: %d", rec.Code)
	}
}

func TestP02AccessRequestInbox(t *testing.T) {
	srv, h, auth := p02Server(t)
	n := srv.network()
	secrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, _, _ := secrets.NewEnrollmentRequest("telefon", time.Now())
	req, _ := trust.OpenEnrollmentRequest(env, time.Now())
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		_, err := doc.AddDevice(req, "telefon", nil, time.Now(), trust.DefaultDeviceLife)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	addTestDevices(t, srv, []string{"masaustu"}, nil)
	doc, _ := n.Document()
	line, _, err := secrets.NewAccessRequest(doc, trust.AccessRequestInput{To: "masaustu", Service: trust.ServiceSSH, Users: []string{"ali"}, Hours: 4, Reason: "yedek"}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/access-requests", map[string]any{"request": "osreq1.bozuk"}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad request accepted: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/p02/access-requests", map[string]any{"request": line}, auth)
	var added struct{ ID string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &added) != nil || added.ID == "" {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/p02/access-requests", map[string]any{"request": line}, auth)
	if !strings.Contains(rec.Body.String(), `"duplicate":true`) {
		t.Fatalf("duplicate: %s", rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/p02/access-requests", nil, auth)
	if !strings.Contains(rec.Body.String(), `"status":"pending"`) || !strings.Contains(rec.Body.String(), `"to":"masaustu"`) {
		t.Fatalf("list: %s", rec.Body)
	}
	// Approval cannot lengthen the request; a wrong passphrase leaves it pending.
	if rec := do(t, h, http.MethodPost, "/api/p02/access-requests/approve", map[string]any{"id": added.ID, "hours": 9, "dryRun": true}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("lengthened: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/access-requests/approve", map[string]any{"id": added.ID, "passphrase": "yanlis-parola"}, auth); rec.Code == http.StatusOK {
		t.Fatal("approved with a wrong passphrase")
	}
	rec = do(t, h, http.MethodPost, "/api/p02/access-requests/approve", map[string]any{"id": added.ID, "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	doc, _ = n.Document()
	last := doc.Rules[len(doc.Rules)-1]
	if last.Service != trust.ServiceSSH || last.NotAfter.IsZero() || last.From[0] != "telefon" {
		t.Fatalf("approved rule: %+v", last)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/access-requests/approve", map[string]any{"id": added.ID, "passphrase": testPass}, auth); rec.Code != http.StatusConflict {
		t.Fatalf("second approval: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/p02/access-requests/reject", map[string]any{"id": "yok"}, auth); rec.Code != http.StatusNotFound {
		t.Fatalf("reject unknown: %d", rec.Code)
	}
}

func TestP02NearbyLoopback(t *testing.T) {
	srv, h, auth := p02Server(t)
	// Tests bind to loopback only (no LAN broadcast, no firewall prompt).
	srv.p02().nearbyAddr = "127.0.0.1:0"
	rec := do(t, h, http.MethodPost, "/api/p02/nearby/listen", map[string]any{"on": true}, auth)
	var st struct{ Addr string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil {
		t.Fatalf("listen: %d %s", rec.Code, rec.Body)
	}
	dst, err := net.ResolveUDPAddr("udp4", st.Addr)
	if err != nil {
		t.Fatal(err)
	}
	secrets, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	env, _, _ := secrets.NewEnrollmentRequest("yakindaki", time.Now())
	line, _ := trust.EncodeEnrollment(env)
	pkt, err := enrollkit.NearbyPacket(line)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := enrollkit.Announce(context.Background(), c, dst, pkt, 10*time.Millisecond, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec = do(t, h, http.MethodGet, "/api/p02/nearby", nil, auth)
		if strings.Contains(rec.Body.String(), "yakindaki") || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "yakindaki") || !strings.Contains(body, `"listening":true`) || strings.Contains(body, `"sas"`) {
		t.Fatalf("nearby: %s", body)
	}
	rec = do(t, h, http.MethodPost, "/api/p02/nearby/listen", map[string]any{"on": false}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/p02/nearby", nil, auth)
	if !strings.Contains(rec.Body.String(), `"listening":false`) {
		t.Fatalf("still listening: %s", rec.Body)
	}
}
