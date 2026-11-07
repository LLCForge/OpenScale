package panel

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

func TestOSLabel(t *testing.T) {
	cases := []struct {
		goos string
		os   sysinfo.OSDetail
		want string
	}{
		{"windows", sysinfo.OSDetail{Name: "Windows 11 Pro", Version: "26H2", Build: "26300.9818", Kernel: "10.0.26300"}, "Windows 11 Pro 26H2 (26300.9818)"},
		{"linux", sysinfo.OSDetail{Name: "Debian GNU/Linux 13 (trixie)", Version: "13", Kernel: "6.12.113+deb13-amd64"}, "Debian GNU/Linux 13 (trixie) · 6.12.113"},
		{"linux", sysinfo.OSDetail{Name: "Arch Linux", Kernel: "6.17.2-arch1-1"}, "Arch Linux · 6.17.2"},
		{"darwin", sysinfo.OSDetail{Name: "macOS", Version: "15.1", Build: "24B83"}, "macOS 15.1 (24B83)"},
		{"linux", sysinfo.OSDetail{}, ""},
	}
	for _, c := range cases {
		if got := osLabel(c.goos, &sysinfo.Detail{OS: c.os}); got != c.want {
			t.Errorf("osLabel(%s, %+v) = %q, want %q", c.goos, c.os, got, c.want)
		}
	}
	if osLabel("linux", nil) != "" {
		t.Error("label without an inventory")
	}
}

func TestPanelDetailHidesMACPrefix(t *testing.T) {
	d := &sysinfo.Detail{NICs: []sysinfo.NIC{{Name: "eth0", OUI: "aa:bb:cc", RandomMAC: true, Speed: 1000}}}
	out := panelDetail(d)
	if out.NICs[0].OUI != "" || out.NICs[0].RandomMAC || out.NICs[0].Speed != 1000 {
		t.Fatalf("panel copy: %+v", out.NICs[0])
	}
	if d.NICs[0].OUI != "aa:bb:cc" {
		t.Fatal("the cached inventory was changed")
	}
	data, _ := json.Marshal(out)
	if strings.Contains(string(data), "oui") || strings.Contains(string(data), "aa:bb") {
		t.Fatalf("MAC prefix in the API answer: %s", data)
	}
}

func TestUpstreamOf(t *testing.T) {
	if UpstreamOf(sysinfo.Info{}) != nil {
		t.Fatal("upstream without a mode")
	}
	v := UpstreamOf(sysinfo.Info{UpstreamLabel: "Mullvad · İsveç", UpstreamMode: "blocked", UpstreamHandshake: 1_790_000_000})
	if v == nil || v.Label != "Mullvad · İsveç" || v.Mode != "blocked" || v.LastHandshake == nil || v.LastHandshake.Unix() != 1_790_000_000 {
		t.Fatalf("upstream view: %+v", v)
	}
}

// inventoryApp implements only what the device endpoints read; any other
// call panics through the nil embedded interface.
type inventoryApp struct {
	App
	inv Inventory
}

func (a *inventoryApp) Status() AppStatus    { return AppStatus{Mode: ModeAdmin} }
func (a *inventoryApp) Inventory() Inventory { return a.inv }
func (a *inventoryApp) LiveStats() LiveStats { return LiveStats{} }

func TestDeviceDetailInventory(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	add := func(name string) {
		secrets, err := trust.GenerateDeviceSecrets(rand.Reader, now)
		if err != nil {
			t.Fatal(err)
		}
		env, _, err := secrets.NewEnrollmentRequest(name, now)
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.OpenEnrollmentRequest(env, now)
		if err != nil {
			t.Fatal(err)
		}
		n := srv.network()
		plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
			_, err := doc.AddDevice(req, name, nil, now, trust.DefaultDeviceLife)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Commit(plan, []byte(testPass)); err != nil {
			t.Fatal(err)
		}
	}
	add("vps")
	add("eski")
	detail := &sysinfo.Detail{
		Ver: sysinfo.DetailVersion, Users: 1,
		OS:   sysinfo.OSDetail{Name: "Debian GNU/Linux 13 (trixie)", Version: "13", Kernel: "6.12.113+deb13-amd64"},
		NICs: []sysinfo.NIC{{Name: "eth0", Type: "ethernet", OUI: "aa:bb:cc", Speed: 1000}},
	}
	app := &inventoryApp{inv: Inventory{Devices: map[string]Report{
		"vps": {At: now, Info: sysinfo.Info{
			OS: "linux", OSName: "Debian 13", DetailVer: 1, DetailID: strings.Repeat("a", 24), Detail: detail,
			UpstreamLabel: "Mullvad · İsveç", UpstreamMode: "tunnel", UpstreamHandshake: now.Unix() - 30,
		}},
		"eski": {At: now, Info: sysinfo.Info{OS: "windows", OSName: "Windows 10"}},
	}}}
	srv.app = app
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		withOrigin(r)
	}

	rec := do(t, h, http.MethodGet, "/api/devices/detail?name=vps", nil, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if strings.Contains(body, "aa:bb:cc") || strings.Contains(body, `"oui"`) {
		t.Fatalf("MAC prefix in the answer: %s", body)
	}
	var d struct {
		System struct {
			OSLabel  string          `json:"osLabel"`
			Detail   *sysinfo.Detail `json:"detail"`
			Upstream *UpstreamView   `json:"upstream"`
		} `json:"system"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.System.OSLabel != "Debian GNU/Linux 13 (trixie) · 6.12.113" || d.System.Detail == nil || len(d.System.Detail.NICs) != 1 || d.System.Detail.NICs[0].Speed != 1000 {
		t.Fatalf("inventory: %s", body)
	}
	if u := d.System.Upstream; u == nil || u.Label != "Mullvad · İsveç" || u.Mode != "tunnel" || u.LastHandshake == nil {
		t.Fatalf("upstream: %s", body)
	}

	rec = do(t, h, http.MethodGet, "/api/devices/detail?name=eski", nil, auth)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"detail"`) || strings.Contains(rec.Body.String(), `"osLabel"`) {
		t.Fatalf("old device: %d %s", rec.Code, rec.Body)
	}

	// The list carries the label and the upstream, never the inventory.
	rec = do(t, h, http.MethodGet, "/api/devices", nil, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status %d: %s", rec.Code, rec.Body)
	}
	list := rec.Body.String()
	if strings.Contains(list, `"detail"`) || !strings.Contains(list, `"osLabel":"Debian GNU/Linux 13 (trixie) · 6.12.113"`) || !strings.Contains(list, `"mode":"tunnel"`) {
		t.Fatalf("list: %s", list)
	}
}
