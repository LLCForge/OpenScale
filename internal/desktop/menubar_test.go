package desktop

import (
	"bytes"
	"image/png"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

func TestMenuBarIcons(t *testing.T) {
	icons := menuBarIcons(menuBarTemplatePNG)
	if len(icons) != 5 {
		t.Fatalf("got %d icons", len(icons))
	}
	seen := map[string]trayIconState{}
	for state, data := range icons {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%v: %v", state, err)
		}
		if b := img.Bounds(); b.Dx() != 44 || b.Dy() != 44 {
			t.Fatalf("%v: size %v", state, b)
		}
		// A template image is black with alpha only.
		for y := 0; y < 44; y++ {
			for x := 0; x < 44; x++ {
				if r, g, b, _ := img.At(x, y).RGBA(); r|g|b != 0 {
					t.Fatalf("%v: coloured pixel at %d,%d", state, x, y)
				}
			}
		}
		if other, dup := seen[string(data)]; dup {
			t.Fatalf("%v and %v look the same", state, other)
		}
		seen[string(data)] = state
	}
	if menuBarIcons([]byte("not a png")) != nil {
		t.Fatal("bad image accepted")
	}
}

func labels(items []winapp.MenuItem) string {
	var b strings.Builder
	for _, it := range items {
		switch {
		case it.Separator:
			b.WriteString("---\n")
		default:
			b.WriteString(it.Label)
			if len(it.Children) > 0 {
				b.WriteString(" {" + strings.ReplaceAll(strings.TrimSpace(labels(it.Children)), "\n", "; ") + "}")
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func TestMenuBarItemsUnreachable(t *testing.T) {
	exits := map[int]string{1: "x"}
	for svc, want := range map[menuBarService]string{
		serviceMissing:   "Arka plan servisini kur...",
		serviceOutdated:  "Servisi bu sürüme güncelle...",
		serviceInstalled: "Servisi yeniden başlat...",
	} {
		got := labels(menuBarItems(menuBarState{service: svc}, exits))
		if !strings.Contains(got, want) || !strings.Contains(got, "Kill switch'i kaldır") || !strings.HasSuffix(got, "Çık\n") {
			t.Errorf("%v:\n%s", svc, got)
		}
		if strings.Contains(got, "Paneli aç") || strings.Contains(got, "Panik") {
			t.Errorf("%v offers the panel without a service:\n%s", svc, got)
		}
	}
	if len(exits) != 0 {
		t.Fatal("exit choices not cleared")
	}
}

func TestMenuBarItemsMember(t *testing.T) {
	st := panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{
		Name: "mac", IPv4: "100.64.0.2", Running: true, Connected: true,
		ExitNodes:      []panel.PeerInfo{{Name: "ev", IPv4: "100.64.0.1", Country: "TR", Online: true}, {Name: "ofis", IPv4: "100.64.0.3"}},
		ExitNodeWanted: "ev", ExitNode: "ev", KillSwitchSupported: true, KillSwitch: true,
	}, Health: []panel.HealthAlert{{Level: panel.LevelWarning, Message: "DNS ayarı değişti"}, {Level: panel.LevelInfo, Message: "bilgi"}}}
	exits := map[int]string{}
	items := menuBarItems(menuBarState{status: st, reachable: true, autostart: true}, exits)
	got := labels(items)
	for _, want := range []string{"Bağlantıyı kes", "Bağlantıyı süreli kes", "Sorunlar (1) {DNS ayarı değişti}", "Bu cihaz: mac", "Çıkış düğümü {Yok (doğrudan internet); ev; ofis; ---; Kill switch}", "Paneli aç", "Oturum açılınca başlat", "Panik: ağı kilitle...", "Çık"} {
		if !strings.Contains(got, want) {
			t.Errorf("menu lacks %q:\n%s", want, got)
		}
	}
	if exits[mbExitNone] != "" || exits[mbExitBase] != "ev" || exits[mbExitBase+1] != "ofis" {
		t.Fatalf("exits = %v", exits)
	}
	var exitMenu winapp.MenuItem
	for _, it := range items {
		if it.Label == "Çıkış düğümü" {
			exitMenu = it
		}
	}
	if exitMenu.Detail != "ev" || !exitMenu.Children[1].Checked || !exitMenu.Children[2].Disabled || exitMenu.Children[1].Detail != "TR  100.64.0.1" {
		t.Fatalf("exit menu = %+v", exitMenu)
	}
	if tip := menuBarTooltip(menuBarState{status: st, reachable: true}); tip != "OpenScale: Bağlı (çıkış: ev)" && !strings.Contains(tip, "çıkış: ev") {
		t.Fatalf("tooltip = %q", tip)
	}
}

func TestMenuBarItemsSetup(t *testing.T) {
	items := menuBarItems(menuBarState{status: panel.AppStatus{Mode: panel.ModeSetup}, reachable: true}, map[int]string{})
	got := labels(items)
	if strings.Contains(got, "Bağlan") || strings.Contains(got, "Panik") || !strings.Contains(got, "Paneli aç") {
		t.Fatalf("setup menu:\n%s", got)
	}
	for _, it := range items {
		if it.ID == mbOpen && !it.Default {
			t.Fatal("panel item is not the default during setup")
		}
	}
}
