package panel

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/trust"
)

func addTestDevices(t *testing.T, srv *Server, names []string, rules []trust.Rule) map[string]trust.Device {
	t.Helper()
	n := srv.network()
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, func(doc *trust.Document) error {
		for _, name := range names {
			secrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
			if err != nil {
				return err
			}
			env, _, err := secrets.NewEnrollmentRequest(name, time.Now())
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
		}
		for _, r := range rules {
			if err := doc.AddRule(r); err != nil {
				return err
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
	doc, _ := n.Document()
	out := map[string]trust.Device{}
	for _, d := range doc.Devices {
		out[d.Name] = d
	}
	return out
}

func authed(t *testing.T, srv *Server) func(*http.Request) {
	t.Helper()
	cookie, csrf := login(t, srv)
	return func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		withOrigin(r)
	}
}

func checkByID(rep scoreReport, id string) scoreCheck {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	return scoreCheck{}
}

func TestComputeScore(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	doc := &trust.Document{ExpiresAt: now.Add(90 * 24 * time.Hour)}

	// A fresh network with a backup and nothing risky scores 100.
	rep := computeScore(scoreInput{Doc: doc, BackupCount: 1, LastBackup: now.Add(-time.Hour), Now: now})
	if rep.Score != 100 || rep.Grade != "excellent" || rep.Local {
		t.Fatalf("clean network: %+v", rep)
	}
	if c := checkByID(rep, scoreKillSwitch); c.Status != checkSkip {
		t.Fatalf("kill switch without the app = %q, want skip", c.Status)
	}

	// No backup and an everyone-to-everyone rule fail.
	wide := &trust.Document{ExpiresAt: now.Add(5 * 24 * time.Hour),
		Rules: []trust.Rule{{From: []string{"*"}, To: []string{"*"}, Protocol: trust.ProtocolAny}}}
	rep = computeScore(scoreInput{Doc: wide, Now: now})
	if checkByID(rep, scoreBackup).Status != checkFail || checkByID(rep, scoreWideRule).Status != checkFail ||
		checkByID(rep, scoreDocumentExpiry).Status != checkWarn || rep.Score >= 50 || rep.Grade != "weak" {
		t.Fatalf("risky network: %+v", rep)
	}
	// A disabled wide rule does not count.
	wide.Rules[0].Disabled = true
	if c := checkByID(computeScore(scoreInput{Doc: wide, Now: now}), scoreWideRule); c.Status != checkPass {
		t.Fatalf("disabled wide rule = %q", c.Status)
	}

	// An old backup is a warning.
	rep = computeScore(scoreInput{Doc: doc, BackupCount: 2, LastBackup: now.Add(-400 * 24 * time.Hour), Now: now})
	if c := checkByID(rep, scoreBackupAge); c.Status != checkWarn || c.Days != 400 {
		t.Fatalf("old backup: %+v", c)
	}

	// This computer: exit node without kill switch, RDP open to the LAN.
	dev := &DeviceStatus{ExitNode: "vps"}
	local := &LocalSecurity{Supported: true, RDP: ServiceAccess{Available: true, Port: 3389},
		SSH: ServiceAccess{Available: true, Port: 22, OverlayOnly: true}, Summary: ExposureSummary{All: 2}}
	rep = computeScore(scoreInput{Doc: doc, BackupCount: 1, LastBackup: now, Now: now, Device: dev, Local: local, Outdated: []string{"b", "a"}})
	if !rep.Local || checkByID(rep, scoreKillSwitch).Status != checkWarn || checkByID(rep, scoreRemoteDesktop).Status != checkFail ||
		checkByID(rep, scoreSSH).Status != checkPass || checkByID(rep, scoreOpenPorts).Count != 2 ||
		checkByID(rep, scorePostQuantum).Status != checkWarn {
		t.Fatalf("local checks: %+v", rep.Checks)
	}
	if c := checkByID(rep, scoreOutdated); c.Status != checkWarn || strings.Join(c.Names, ",") != "a,b" {
		t.Fatalf("outdated: %+v", c)
	}
	dev.KillSwitch, dev.KillSwitchError = true, "filtre kurulamadı"
	if c := checkByID(computeScore(scoreInput{Doc: doc, Now: now, Device: dev}), scoreKillSwitch); c.Status != checkFail {
		t.Fatalf("failing kill switch = %q", c.Status)
	}
}

func TestSecurityScoreEndpoint(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	if rec := do(t, h, http.MethodGet, "/api/security/score", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("score without session = %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/api/security/score", nil, authed(t, srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("score status %d: %s", rec.Code, rec.Body)
	}
	var rep scoreReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if checkByID(rep, scoreBackup).Status != checkFail || rep.Score >= 100 {
		t.Fatalf("new network without backup: %+v", rep)
	}
}

func TestExportAndInspectDocument(t *testing.T) {
	srv := newTestServer(t)
	ro := &atomic.Bool{}
	srv.readOnly = ro.Load
	h := srv.Handler()
	auth := authed(t, srv)

	rec := do(t, h, http.MethodGet, "/api/network/export", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "openscale-belge-v1.json") {
		t.Fatalf("export: %d %v", rec.Code, rec.Header())
	}
	v1 := rec.Body.String()
	if strings.Contains(v1, "private") {
		t.Fatal("export must not contain key material")
	}

	inspect := func(doc string, mutate func(*http.Request)) (int, importResponse) {
		rec := do(t, h, http.MethodPost, "/api/network/import/inspect", map[string]string{"document": doc}, mutate)
		var resp importResponse
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, resp
	}
	if code, resp := inspect(v1, auth); code != http.StatusOK || resp.Relation != relationSame || resp.Version != 1 || len(resp.SHA256) != 64 {
		t.Fatalf("same document: %d %+v", code, resp)
	}
	// Without the CSRF token the check is refused.
	noCSRF := func(r *http.Request) {
		auth(r)
		r.Header.Del("X-CSRF-Token")
	}
	if code, _ := inspect(v1, noCSRF); code != http.StatusForbidden {
		t.Fatalf("inspect without CSRF = %d", code)
	}
	// A changed byte breaks the signature.
	var env trust.Envelope
	if err := json.Unmarshal([]byte(v1), &env); err != nil {
		t.Fatal(err)
	}
	env.Signature[0] ^= 1
	raw, _ := json.Marshal(env)
	tampered := string(raw)
	if code, _ := inspect(tampered, auth); code != http.StatusBadRequest {
		t.Fatalf("tampered document = %d", code)
	}
	if code, _ := inspect("bu bir belge değil", auth); code != http.StatusBadRequest {
		t.Fatalf("garbage = %d", code)
	}

	// After a change the exported copy is an older version with a diff;
	// checking it works in read-only mode and changes nothing.
	addTestDevices(t, srv, []string{"laptop"}, nil)
	ro.Store(true)
	code, resp := inspect(v1, auth)
	if code != http.StatusOK || resp.Relation != relationOlder || resp.CurrentVersion != 2 || len(resp.Changes) == 0 {
		t.Fatalf("older document: %d %+v", code, resp)
	}
	if doc, _ := srv.network().Document(); doc.Version != 2 {
		t.Fatalf("inspect changed the document: v%d", doc.Version)
	}
}

func TestNetworkMap(t *testing.T) {
	srv := newTestServer(t)
	devs := addTestDevices(t, srv, []string{"laptop", "nas", "phone"}, []trust.Rule{
		{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}},
	})
	h := srv.Handler()
	rec := do(t, h, http.MethodGet, "/api/map", nil, authed(t, srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("map status %d: %s", rec.Code, rec.Body)
	}
	var m mapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Nodes) != 3 || m.Live {
		t.Fatalf("nodes: %+v", m)
	}
	if len(m.Edges) != 1 || !m.Edges[0].Rule || m.Edges[0].Path != pathUnknown {
		t.Fatalf("edges: %+v", m.Edges)
	}
	e := m.Edges[0]
	if !(e.From == devs["laptop"].ID && e.To == devs["nas"].ID) && !(e.From == devs["nas"].ID && e.To == devs["laptop"].ID) {
		t.Fatalf("edge between wrong devices: %+v", e)
	}

	// This computer's links carry the live path.
	doc, _ := srv.network().Document()
	now := time.Now()
	l := live{selfName: "laptop", stats: LiveStats{Direct: map[trust.Key]PeerTraffic{
		devs["nas"].WireGuardKey: {Relayed: true, LastHandshake: now.Add(-time.Minute)},
	}}}
	m = buildNetworkMap(doc, l, now)
	if !m.Live || len(m.Edges) != 1 || m.Edges[0].Path != pathRelay {
		t.Fatalf("live map: %+v", m)
	}
}

type historyApp struct {
	diagApp
	paths []node.PeerPath
}

func (a *historyApp) DiagPaths() ([]node.PeerPath, error) { return a.paths, nil }

func TestConnectionHistory(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var h connHistory
	probe := now.Add(-10 * time.Second)
	paths := []node.PeerPath{
		{Name: "nas", Endpoint: "192.0.2.1:41641", LastHandshake: now.Add(-time.Minute), ProbeRTT: 12500 * time.Microsecond, ProbedAt: probe},
		{Name: "phone", Relayed: true, Endpoint: "aktarıcı", LastHandshake: now.Add(-time.Minute)},
		{Name: "old", Endpoint: "192.0.2.2:41641", LastHandshake: now.Add(-time.Hour)},
	}
	h.record(paths, now)
	h.record(paths, now.Add(time.Minute)) // same probe: no new RTT
	got, _ := h.snapshot()
	if s := got["nas"]; len(s) != 2 || s[0].Path != pathDirect || s[0].RTTMS != 12.5 || s[1].RTTMS != 0 {
		t.Fatalf("nas samples: %+v", s)
	}
	if got["phone"][0].Path != pathRelay || got["old"][0].Path != pathNone {
		t.Fatalf("paths: %+v", got)
	}
	// After a day without the peer its history is dropped; old samples
	// fall out of the 24-hour window.
	h.record(paths[:1], now.Add(25*time.Hour))
	got, _ = h.snapshot()
	if _, ok := got["phone"]; ok || len(got["nas"]) != 1 {
		t.Fatalf("after 25h: %+v", got)
	}

	// The endpoint needs the desktop app and a session.
	srv := newTestServer(t)
	hd := srv.Handler()
	auth := authed(t, srv)
	if rec := do(t, hd, http.MethodGet, "/api/app/diag/history", nil, auth); rec.Code != http.StatusNotFound {
		t.Fatalf("history without app = %d", rec.Code)
	}
	app := &historyApp{diagApp: diagApp{level: "info"}, paths: []node.PeerPath{{Name: "nas", History: []node.EndpointChange{{At: time.Now(), Endpoint: "aktarıcı", Relayed: true}}}}}
	srv.app = app
	srv.hist.record(app.paths, time.Now())
	rec := do(t, hd, http.MethodGet, "/api/app/diag/history", nil, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("history status %d: %s", rec.Code, rec.Body)
	}
	var reply historyReply
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Peers) != 1 || len(reply.Peers[0].Samples) != 1 || len(reply.Peers[0].Changes) != 1 || reply.IntervalSec != 60 {
		t.Fatalf("history reply: %+v", reply)
	}
}
