package service

import (
	"context"
	"crypto/rand"
	"log/slog"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/flightrec"
	"github.com/openscale/openscale/internal/troubleshoot"
)

func TestRestartsConnectionFlag(t *testing.T) {
	for _, k := range []string{"connected", "mtu", "force-relay", "post-quantum", "keepalive", "static-endpoints", "relay-rate", "coordinator-tcp-listen", "port-map"} {
		if !restartsConnection(k) {
			t.Errorf("%s must be marked as restarting the connection", k)
		}
	}
	for _, k := range []string{"log-level", "shields", "accept-dns", "exit-node", "kill-switch", "nonexistent"} {
		if restartsConnection(k) {
			t.Errorf("%s must not be marked", k)
		}
	}
	prefs := prefsOf(settings{})
	marked := 0
	for _, p := range prefs {
		if p.RestartsConnection != restartsConnection(p.Key) {
			t.Fatalf("prefsOf flag for %s", p.Key)
		}
		if p.RestartsConnection {
			marked++
		}
	}
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if meta := r.PrefMeta(); len(meta) != marked || marked == 0 {
		t.Fatalf("PrefMeta = %d entries, want %d", len(meta), marked)
	}
}

func TestFlightRecorderWire(t *testing.T) {
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if st := r.FlightRecStatus(); st.Enabled || st.Error == "" {
		t.Fatalf("status before start: %+v", st)
	}
	r.fr.rec = flightrec.New(flightrec.Config{Now: r.cfg.Now})
	r.logger = slog.New(r.fr.rec.Handler(r.logger.Handler()))
	r.fr.rec.SetNames([]string{"mutfak-pc"})
	r.logger.Debug("tunnel down", "peer", "mutfak-pc", "endpoint", "203.0.113.5:41641")

	info, err := r.FlightRecFreeze(flightrec.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	st := r.FlightRecStatus()
	if !st.Enabled || len(st.Stored) != 1 || st.Stored[0].ID != info.ID || st.Stats.Entries == 0 {
		t.Fatalf("status = %+v", st)
	}
	helper, err := bundlecrypt.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{info.ID, ""} {
		sealed, err := r.FlightRecExport(id, helper.Private.PublicKey())
		if err != nil {
			t.Fatalf("export %q: %v", id, err)
		}
		plain, err := bundlecrypt.Open(helper, sealed)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := flightrec.DecodeSnapshot(plain)
		if err != nil {
			t.Fatal(err)
		}
		var all strings.Builder
		for _, e := range snap.Entries {
			all.WriteString(e.Msg + " " + e.Attrs + "\n")
		}
		if !strings.Contains(all.String(), "tunnel down") || strings.Contains(all.String(), "mutfak-pc") || strings.Contains(all.String(), "203.0.113.5") {
			t.Fatalf("export %q not masked:\n%s", id, all.String())
		}
	}
}

func TestTroubleshootWithoutNetwork(t *testing.T) {
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	rep := r.Troubleshoot(context.Background())
	if len(rep.Steps) == 0 || rep.Steps[0].Layer != troubleshoot.LayerInterface || rep.Steps[0].Status != troubleshoot.Fail {
		t.Fatalf("a computer without a tunnel must fail at the interface: %+v", rep.Steps)
	}
	for _, s := range rep.Steps[1:] {
		if s.Status != troubleshoot.Skip {
			t.Fatalf("higher layers must be skipped: %+v", s)
		}
	}
}
