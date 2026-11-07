package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sysinfo"
)

// fakeNetPlacesService answers like the desktop service, on 127.0.0.1.
func fakeNetPlacesService(t *testing.T) *bool {
	t.Helper()
	on := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case panel.LocalAPIPrefix + "/health":
			_ = json.NewEncoder(w).Encode(panel.HealthReport{})
		case panel.LocalAPIPrefix + "/netplaces":
			if r.Method == http.MethodPost {
				var req panel.NetPlacesRequest
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &req)
				on = req.On
			}
			_ = json.NewEncoder(w).Encode(panel.NetPlacesStatus{Supported: true, On: on, Admin: true, Ready: true, Shares: 1,
				Devices: []panel.NetPlaceDevice{
					{Name: "nas", Host: "nas.ev.openscale.internal", Known: true, Shares: []sysinfo.Share{{Name: "Arsiv"}}},
					{Name: "tel", Host: "tel.ev.openscale.internal"},
				}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	saved := localAPI
	t.Cleanup(func() { localAPI = saved })
	localAPI.dataDir = func() string { return "svc" }
	localAPI.readToken = func(string) (string, error) { return "tok", nil }
	localAPI.serviceBase = srv.URL
	return &on
}

func TestNetdriveAutoCommands(t *testing.T) {
	h := newHarness(t)
	on := fakeNetPlacesService(t)
	out := h.run(exitOK, "netdrive", "auto", "status")
	if !strings.Contains(out, "Ağ konumları: açık") || !strings.Contains(out, `\\nas.ev.openscale.internal\Arsiv`) || !strings.Contains(out, "rapor yok") {
		t.Fatalf("status:\n%s", out)
	}
	if out := h.run(exitOK, "netdrive", "auto", "off"); !strings.Contains(out, "kapalı") || *on {
		t.Fatalf("off:\n%s", out)
	}
	if out := h.run(exitOK, "netdrive", "auto", "on"); !strings.Contains(out, "açık") || !*on {
		t.Fatalf("on:\n%s", out)
	}
	if out := h.run(exitOK, "netdrive", "auto", "status", "--json"); !strings.Contains(out, `"on": true`) {
		t.Fatalf("json:\n%s", out)
	}
}
