package service

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
)

func TestRDeskDecisionFiles(t *testing.T) {
	doc := appsDoc(
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, AllowControl: true},
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceFiles},
		trust.Rule{From: []string{"masaustu"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, AllowControl: true},
	)
	laptop, _ := doc.DeviceByName("laptop")
	desk, _ := doc.DeviceByName("masaustu")
	if d := rdeskDecision(doc, "nas", laptop, rdesk.ModeControl); !d.Allowed || !d.Files {
		t.Fatalf("control with files rule: %+v", d)
	}
	if d := rdeskDecision(doc, "nas", laptop, rdesk.ModeView); d.Files {
		t.Fatal("view session got files")
	}
	if d := rdeskDecision(doc, "nas", desk, rdesk.ModeControl); !d.Allowed || d.Files {
		t.Fatalf("no files rule: %+v", d)
	}
}

func TestRDeskFileRootsSettings(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "paylasim")
	if err := ValidateRDeskFileRoots([]string{root}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"rel/klasor"}, {root, strings.ToUpper(root)}, {root + string(filepath.Separator) + ".." + string(filepath.Separator) + "x"}, {filepath.VolumeName(dir) + string(filepath.Separator)}} {
		if err := ValidateRDeskFileRoots(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := SaveRemoteDesktopSettings(dir, RemoteDesktopSettings{FileRoots: []string{"rel"}}); err == nil {
		t.Fatal("relative folder saved")
	}
	s := RemoteDesktopSettings{LocalLock: true, FileRoots: []string{root}}
	if err := SaveRemoteDesktopSettings(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRemoteDesktopSettings(dir)
	if err != nil || !got.Equal(s) {
		t.Fatalf("%+v %v", got, err)
	}
	// Settings without folders encode as before (omitempty).
	data, _ := json.Marshal(RemoteDesktopSettings{Power: true})
	if string(data) != `{"power":true}` {
		t.Fatalf("encoding changed: %s", data)
	}
	cfg, err := BuildRemoteDesktopConfig(RemoteDesktopServerOptions{Addr: netip.MustParseAddrPort("100.80.0.3:7590"), Authorize: func(netip.Addr, rdesk.Mode) rdesk.Decision { return rdesk.Decision{} },
		Indicator: func(rdesk.SessionEvent) {}, FileRoots: []string{root}})
	if err != nil || len(cfg.FileRoots) != 1 || cfg.FileRoots[0].Name != "paylasim" {
		t.Fatalf("config %+v %v", cfg.FileRoots, err)
	}
	b := HelperBootstrap{Version: HelperBootstrapVersion, API: "127.0.0.1:1", Token: strings.Repeat("a", 43), Listen: "100.80.0.3:7590", FileRoots: []string{"rel"}}
	if b.Validate() == nil {
		t.Fatal("bootstrap with a relative folder accepted")
	}
	var d panel.RDeskHelperDecision
	if data, _ := json.Marshal(d); strings.Contains(string(data), "files") {
		t.Fatalf("decision encoding changed: %s", data)
	}
}
