package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/service"
)

func TestWave2Usage(t *testing.T) {
	h := newHarness(t)
	h.run(exitUsage, "up", "--padding", "huge")
	h.run(exitUsage, "up", "--cover-traffic", "10")
	h.run(exitUsage, "up", "--tor-socks", "8.8.8.8:9050")
	h.run(exitUsage, "up", "--port-map", "--port-map-disable", "pcp,natpmp,upnp")
	h.run(exitUsage, "up", "--port-map-disable", "smtp")
	h.run(exitUsage, "up", "--blocklist", "goreli.txt")
	h.run(exitUsage, "up", "--tor-socks", "127.0.0.1:9050", "--disable-tcp-fallback")
	h.run(exitUsage, "up", "--exit-dns-upstream", "ftp://x")
	h.run(exitUsage, "send", "--strip-metadata", "gps", "a.jpg", "laptop")
	h.run(exitUsage, "rule", "add", "--from", "a", "--to", "b", "--ports", "22", "--allow-control")
	h.run(exitUsage, "rule", "add", "--from", "a", "--to", "b", "--ports", "22", "--backup")
	h.run(exitUsage, "rdesk-helper", "extra")
}

func TestSendStripMode(t *testing.T) {
	for in, want := range map[string]filesend.MetadataMode{"": filesend.MetadataKeep, "konum": filesend.MetadataLocation, "all": filesend.MetadataAll, "Hepsi": filesend.MetadataAll} {
		if got, err := sendStripMode(in); err != nil || got != want {
			t.Errorf("%q -> %v %v", in, got, err)
		}
	}
}

func TestReadBootstrap(t *testing.T) {
	good := service.HelperBootstrap{Version: 1, API: "127.0.0.1:47821", Token: strings.Repeat("t", 43), Listen: "100.80.0.3:4047"}
	line, _ := json.Marshal(good)
	b, rest, err := readBootstrap(strings.NewReader(string(line) + "\n"))
	if err != nil || rest == nil || b.Listen != good.Listen {
		t.Fatalf("good bootstrap: %v", err)
	}
	for _, in := range []string{"", "{}\n", "not json\n", `{"v":1,"api":"127.0.0.1:1","token":"x","listen":"100.80.0.3:4047","extra":1}` + "\n", string(line)} {
		if _, _, err := readBootstrap(strings.NewReader(in)); err == nil {
			t.Errorf("%q must be refused", in)
		}
	}
	// Run by hand (no service pipe) the helper refuses to start.
	h := newHarness(t)
	h.run(exitError, "rdesk-helper")
}

func TestHelperClientFailsClosed(t *testing.T) {
	c := &helperClient{base: "http://127.0.0.1:1", token: "x", http: newHTTPClient(), events: make(chan panel.RDeskHelperEvent, 1)}
	if d := c.authorize(netip.MustParseAddr("100.80.0.2"), rdesk.ModeView); d.Allowed {
		t.Fatal("an unreachable service must refuse")
	}
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/app/rdesk-helper/authorize" {
			http.NotFound(w, r)
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(panel.RDeskHelperDecision{Allowed: req["mode"] == "view", Peer: "laptop"})
	}))
	defer srv.Close()
	c.base, c.token = srv.URL, "gizli"
	if d := c.authorize(netip.MustParseAddr("100.80.0.2"), rdesk.ModeView); !d.Allowed || d.Peer != "laptop" || gotAuth != "Bearer gizli" {
		t.Fatalf("decision: %+v auth %q", d, gotAuth)
	}
	if d := c.authorize(netip.MustParseAddr("100.80.0.2"), rdesk.ModeControl); d.Allowed {
		t.Fatal("control refused by the service")
	}
}

func TestConsentAndIndicatorText(t *testing.T) {
	s := consentText(rdesk.ConsentRequest{Peer: "laptop", Mode: rdesk.ModeControl, Code: "123 456", Recording: true})
	for _, want := range []string{"laptop", "kontrol", "123 456", "kaydedilecek"} {
		if !strings.Contains(s, want) {
			t.Errorf("consent text lacks %q: %s", want, s)
		}
	}
	s = indicatorText(rdesk.SessionEvent{Peer: "laptop", Mode: rdesk.ModeView, Unattended: true, Recording: true, Code: "999"})
	for _, want := range []string{"laptop", "izleme", "onaysız", "kaydediliyor", "999"} {
		if !strings.Contains(s, want) {
			t.Errorf("indicator text lacks %q: %s", want, s)
		}
	}
}
