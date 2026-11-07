package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/flightrec"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/troubleshoot"
)

// serveP2Fake answers the phase 2 routes of the local API on 127.0.0.1.
func serveP2Fake(t *testing.T, h *harness, report troubleshoot.Report) {
	t.Helper()
	ln, err := panel.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("b", 43)
	mux := http.NewServeMux()
	auth := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fn(w, r)
		}
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /api/local/health", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, panel.HealthReport{Schema: panel.DiagSchema, Live: true})
	}))
	mux.HandleFunc("GET /api/local/flightrec", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, panel.FlightRecStatus{Schema: 1, Enabled: true, AutoFreeze: true, AutoEvery: 900,
			Stats:  flightrec.Stats{Entries: 12, Bytes: 2048, MaxBytes: 4 << 20, MaxAgeS: 1800},
			Stored: []flightrec.Info{{ID: "fr-20261107-120000-tunnel_down", At: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), Reason: "tunnel_down", Size: 900}}})
	}))
	mux.HandleFunc("POST /api/local/flightrec/freeze", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, panel.FlightRecFreezeReply{Schema: 1, Saved: flightrec.Info{ID: "fr-20261107-120500-manual", Reason: "manual"}})
	}))
	mux.HandleFunc("POST /api/local/flightrec/export", auth(func(w http.ResponseWriter, r *http.Request) {
		var req panel.FlightRecExportRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		to, err := bundlecrypt.ParsePublic(req.To)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sealed, err := bundlecrypt.Seal(rand.Reader, to, []byte("kayit:"+req.ID))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(sealed)
	}))
	mux.HandleFunc("POST /api/local/troubleshoot", auth(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, report) }))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dir, _ := h.env.DefaultStateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().String()[strings.LastIndex(ln.Addr().String(), ":")+1:]
	if err := securefile.Replace(filepath.Join(dir, localAPIFile), []byte(`{"port":`+port+`,"token":"`+token+`"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDebugFreezeCommands(t *testing.T) {
	h := newHarness(t)
	serveP2Fake(t, h, troubleshoot.Report{})
	mustContain(t, h.run(exitOK, "debug", "freeze"), "fr-20261107-120500-manual", "--to")
	mustContain(t, h.run(exitOK, "debug", "freezes"), "12 kayıt", "fr-20261107-120000-tunnel_down", "tünel düştü", "15 dakikada")
	h.run(exitUsage, "debug", "freeze", "--id", "../x", "--to", "osbk1:x")
	h.run(exitUsage, "debug", "freeze", "--id", "fr-20261107-120000-tunnel_down")
	h.run(exitUsage, "debug", "freeze", "--to", "osbk1:bozuk")

	helper, err := bundlecrypt.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "kayit.osb")
	mustContain(t, h.run(exitOK, "debug", "freeze", "--id", "fr-20261107-120000-tunnel_down", "--to", helper.PublicText(), "-o", out), "şifreli", bundlecrypt.Fingerprint(helper.Private.PublicKey()))
	sealed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := bundlecrypt.Open(helper, sealed); err != nil || string(plain) != "kayit:fr-20261107-120000-tunnel_down" {
		t.Fatalf("written file: %q %v", plain, err)
	}
	// Never overwrites without --force.
	h.run(exitError, "debug", "freeze", "--to", helper.PublicText(), "-o", out)
}

func TestTroubleshootCommand(t *testing.T) {
	failing := troubleshoot.Report{Schema: 1, OK: false, FirstFailure: 1, Steps: []troubleshoot.Step{
		{Layer: "interface", Status: troubleshoot.Pass, Key: "interface.ok", Title: "Tünel arayüzü", Detail: "Tünel çalışıyor."},
		{Layer: "gateway", Status: troubleshoot.Fail, Key: "gateway.missing", Title: "Yerel ağ geçidi", Code: "OS-3005", Detail: "Yok.", Fix: "Wi-Fi'yi denetleyin."},
		{Layer: "dns", Status: troubleshoot.Skip, Key: "skipped.lower_failed", Title: "DNS"},
	}}
	h := newHarness(t)
	serveP2Fake(t, h, failing)
	mustContain(t, h.run(exitError, "troubleshoot"), "[geçti  ] Tünel arayüzü", "[KALDI  ] Yerel ağ geçidi (OS-3005)", "Öneri: Wi-Fi", "[atlandı] DNS", "openscale explain OS-3005")
	out := h.run(exitError, "troubleshoot", "--json")
	var rep troubleshoot.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.FirstFailure != 1 || len(rep.Steps) != 3 {
		t.Fatalf("--json:\n%s", out)
	}
	h2 := newHarness(t)
	serveP2Fake(t, h2, troubleshoot.Report{Schema: 1, OK: true, FirstFailure: -1, Steps: failing.Steps[:1]})
	mustContain(t, h2.run(exitOK, "troubleshoot"), "Sorun bulunmadı")
}
