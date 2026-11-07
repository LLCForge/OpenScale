package panel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/flightrec"
	"github.com/openscale/openscale/internal/troubleshoot"
)

type p2App struct {
	featureApp
	frozen   int
	exported string
	sessions int
	ran      int
}

func (a *p2App) FlightRecStatus() FlightRecStatus {
	return FlightRecStatus{Schema: DiagSchema, Enabled: true, Stored: []flightrec.Info{}}
}

func (a *p2App) FlightRecFreeze(reason string) (flightrec.Info, error) {
	a.frozen++
	return flightrec.Info{ID: "fr-20261107-120000-" + reason, Reason: reason}, nil
}

func (a *p2App) FlightRecExport(id string, to *ecdh.PublicKey) ([]byte, error) {
	if id == "fr-20261107-120000-yok" {
		return nil, flightrec.ErrNotFound
	}
	a.exported = id
	return bundlecrypt.Seal(rand.Reader, to, []byte("kayit"))
}

func (a *p2App) Troubleshoot(context.Context) troubleshoot.Report {
	a.ran++
	return troubleshoot.Report{Schema: troubleshoot.Schema, OK: true, FirstFailure: -1, Steps: []troubleshoot.Step{{Layer: "interface", Status: troubleshoot.Pass, Key: "interface.ok"}}}
}

func (a *p2App) PrefMeta() []PrefMeta {
	return []PrefMeta{{Key: "mtu", RestartsConnection: true}}
}

func (a *p2App) RDeskStatus() RDeskStatus {
	return RDeskStatus{Sessions: make([]RDeskSession, a.sessions)}
}

func (a *p2App) SetRDeskSettings(RDeskSettingsChange) error { return nil }

func TestP2DiagRoutes(t *testing.T) {
	srv := newTestServer(t)
	app := &p2App{}
	ro := &atomic.Bool{}
	srv.app, srv.token, srv.readOnly = app, "uygulama-anahtari-123", ro.Load
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.token) }

	if rec := do(t, h, http.MethodGet, "/api/app/diag/flightrec", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/diag/flightrec/freeze", struct{}{}, read); rec.Code != http.StatusForbidden || app.frozen != 0 {
		t.Fatalf("freeze without CSRF: %d", rec.Code)
	}
	// Freezing changes no setting, so it works in read-only mode too.
	ro.Store(true)
	rec := do(t, h, http.MethodPost, "/api/app/diag/flightrec/freeze", struct{}{}, signed)
	var fr FlightRecFreezeReply
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &fr) != nil || fr.Saved.Reason != flightrec.ReasonManual || app.frozen != 1 {
		t.Fatalf("freeze: %d %s", rec.Code, rec.Body)
	}
	ro.Store(false)

	helper, err := bundlecrypt.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec = do(t, h, http.MethodPost, "/api/local/flightrec/export", FlightRecExportRequest{ID: "fr-20261107-120000-manual", To: helper.PublicText()}, bearer)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/octet-stream" || app.exported != "fr-20261107-120000-manual" {
		t.Fatalf("export: %d %s", rec.Code, rec.Body)
	}
	if plain, err := bundlecrypt.Open(helper, rec.Body.Bytes()); err != nil || string(plain) != "kayit" {
		t.Fatalf("exported bundle: %q %v", plain, err)
	}
	for _, bad := range []FlightRecExportRequest{
		{ID: "../../etc/passwd", To: helper.PublicText()},
		{ID: "", To: "osbk1:bozuk"},
	} {
		if rec := do(t, h, http.MethodPost, "/api/local/flightrec/export", bad, bearer); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad export %+v: %d", bad, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/local/flightrec/export", FlightRecExportRequest{ID: "fr-20261107-120000-yok", To: helper.PublicText()}, bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("missing export: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/local/flightrec", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token route without token: %d", rec.Code)
	}

	rec = do(t, h, http.MethodPost, "/api/app/diag/troubleshoot", struct{}{}, signed)
	var rep troubleshoot.Report
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || !rep.OK || app.ran != 1 {
		t.Fatalf("troubleshoot: %d %s", rec.Code, rec.Body)
	}

	var meta PrefMetaReply
	rec = do(t, h, http.MethodGet, "/api/app/prefs/meta", nil, read)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &meta) != nil || len(meta.Prefs) != 1 || meta.RemoteSession {
		t.Fatalf("meta: %d %s", rec.Code, rec.Body)
	}
	app.sessions = 1
	rec = do(t, h, http.MethodGet, "/api/app/prefs/meta", nil, read)
	if json.Unmarshal(rec.Body.Bytes(), &meta) != nil || !meta.RemoteSession {
		t.Fatalf("an active remote desktop session must count as remote: %s", rec.Body)
	}

	// A service without the controls answers 404.
	srv.app = &featureApp{}
	h = srv.Handler()
	if rec := do(t, h, http.MethodGet, "/api/app/diag/flightrec", nil, read); rec.Code != http.StatusNotFound {
		t.Fatalf("no recorder: %d", rec.Code)
	}
}
