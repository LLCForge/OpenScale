package panel

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

func g3PanelDoc() *trust.Document {
	return &trust.Document{
		DNSDomain: "ev.internal",
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.1")},
			{Name: "masaustu", IPv4: netip.MustParseAddr("100.80.0.2"), IPv6: netip.MustParseAddr("fd00::2")},
		},
		Rules: []trust.Rule{{From: []string{"laptop"}, To: []string{"masaustu"}, Service: trust.ServicePanel}},
	}
}

func TestPanelNameMatches(t *testing.T) {
	doc := g3PanelDoc()
	host := netip.MustParseAddr("100.80.0.2")
	cases := []struct {
		name string
		addr netip.Addr
		want bool
	}{
		{"yonetim.ev.internal", host, true},
		{"YONETIM.ev.internal.", host, true},
		{"yonetim.ev.internal", netip.MustParseAddr("fd00::2"), true},
		{"yonetim.ev.internal", netip.MustParseAddr("100.80.0.1"), false}, // laptop serves no panel
		{"yonetim.evil.example", host, false},
		{"masaustu.ev.internal", host, false},
	}
	for _, c := range cases {
		if got := panelNameMatches(doc, c.name, c.addr); got != c.want {
			t.Errorf("%s @ %s = %v", c.name, c.addr, got)
		}
	}
	doc.Rules = nil
	if panelNameMatches(doc, "yonetim.ev.internal", host) {
		t.Fatal("name accepted without a panel rule")
	}
}

func TestPanelNameView(t *testing.T) {
	v := panelNameView(g3PanelDoc())
	if v.Name != "yonetim.ev.internal" || v.URL != "http://yonetim.ev.internal:4049/" || len(v.Hosts) != 1 || v.Hosts[0] != "masaustu" {
		t.Fatalf("%+v", v)
	}
	empty := panelNameView(&trust.Document{DNSDomain: "ev.internal"})
	if empty.Name != "" || empty.Note == "" || empty.Hosts == nil {
		t.Fatalf("%+v", empty)
	}
}

func TestSignedPanelHostLoopbackAndNoApp(t *testing.T) {
	s := &Server{host: "127.0.0.1:4049"}
	if s.signedPanelHost("yonetim.ev.internal:4049") {
		t.Fatal("loopback panel accepted the tunnel name")
	}
	s.host = "100.80.0.2:4049"
	if s.signedPanelHost("yonetim.ev.internal:4049") {
		t.Fatal("accepted without a network")
	}
	if s.allowedHost("yonetim.ev.internal:4049") {
		t.Fatal("allowedHost accepted without a network")
	}
	w := httptest.NewRecorder()
	s.handleOpsec(w, httptest.NewRequest(http.MethodGet, "/api/app/opsec", nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status %d", w.Code)
	}
}
