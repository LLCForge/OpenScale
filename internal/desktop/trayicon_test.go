package desktop

import (
	"bytes"
	"image/png"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

func TestIconStateFor(t *testing.T) {
	now := time.Now()
	running := func(mod func(*panel.DeviceStatus), health ...panel.HealthAlert) panel.AppStatus {
		d := &panel.DeviceStatus{Name: "pc", Connected: true, Running: true, LastSync: &now}
		if mod != nil {
			mod(d)
		}
		return panel.AppStatus{Mode: panel.ModeMember, Device: d, Health: health}
	}
	cases := []struct {
		name      string
		st        panel.AppStatus
		reachable bool
		want      trayIconState
	}{
		{"service gone", panel.AppStatus{}, false, iconError},
		{"setup", panel.AppStatus{Mode: panel.ModeSetup}, true, iconOff},
		{"connected", running(nil), true, iconConnected},
		{"exit node", running(func(d *panel.DeviceStatus) { d.ExitNode = "vps" }), true, iconExit},
		{"turned off", running(func(d *panel.DeviceStatus) { d.Connected = false }), true, iconOff},
		{"connecting", running(func(d *panel.DeviceStatus) { d.LastSync = nil }), true, iconOff},
		{"tunnel failed", running(func(d *panel.DeviceStatus) { d.Running = false; d.Error = "Wintun" }), true, iconError},
		{"warning", running(nil, panel.HealthAlert{Level: panel.LevelWarning}), true, iconWarning},
		{"danger", running(func(d *panel.DeviceStatus) { d.ExitNode = "vps" }, panel.HealthAlert{Level: panel.LevelInfo}, panel.HealthAlert{Level: panel.LevelDanger}), true, iconError},
		{"info only", running(nil, panel.HealthAlert{Level: panel.LevelInfo}), true, iconConnected},
	}
	for _, tc := range cases {
		if got := iconStateFor(tc.st, tc.reachable); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, trayStateLabel[got], trayStateLabel[tc.want])
		}
	}
}

func TestTrayIconVariants(t *testing.T) {
	icons := makeTrayIcons(trayIconPNG)
	if len(icons) != len(trayBadgeColors) {
		t.Fatalf("%d variants, want %d", len(icons), len(trayBadgeColors))
	}
	seen := map[string]trayIconState{}
	for s, data := range icons {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", trayStateLabel[s], err)
		}
		b := img.Bounds()
		// The badge sits in the bottom-right corner in the state's color.
		r, g, bl, a := img.At(b.Max.X-b.Dx()/5, b.Max.Y-b.Dy()/5).RGBA()
		want := trayBadgeColors[s]
		if a>>8 != 0xff || uint8(r>>8) != want.R || uint8(g>>8) != want.G || uint8(bl>>8) != want.B {
			t.Errorf("%s: badge pixel %02x%02x%02x/%02x, want %02x%02x%02x", trayStateLabel[s], r>>8, g>>8, bl>>8, a>>8, want.R, want.G, want.B)
		}
		if other, dup := seen[string(data)]; dup {
			t.Errorf("%s and %s render the same icon", trayStateLabel[s], trayStateLabel[other])
		}
		seen[string(data)] = s
	}
	// A broken base falls back to the base itself instead of no icon.
	if got := makeTrayIcons([]byte("png değil")); string(got[iconConnected]) != "png değil" {
		t.Fatal("broken base must fall back")
	}
}

func TestUntilLabel(t *testing.T) {
	now := time.Date(2026, 10, 30, 22, 0, 0, 0, time.Local)
	if got := untilLabel(now.Add(30*time.Minute), now); got != "22:30" {
		t.Fatalf("same day: %q", got)
	}
	if got := untilLabel(time.Date(2026, 10, 31, 8, 0, 0, 0, time.Local), now); got != "yarın 08:00" {
		t.Fatalf("tomorrow: %q", got)
	}
	if got := untilLabel(time.Date(2026, 11, 2, 8, 0, 0, 0, time.Local), now); got != "02.11 08:00" {
		t.Fatalf("later: %q", got)
	}
}
