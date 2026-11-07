package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/svcmgr"
	"github.com/openscale/openscale/internal/version"
	"github.com/openscale/openscale/internal/winapp"
)

func TestG4CommandsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, c := range commands() {
		names[c.name] = true
	}
	for _, want := range []string{"autostart on", "autostart off", "autostart status", "autostart run", "update channel", "about", "window", "panel-window", "commands", "discreet"} {
		if !names[want] {
			t.Errorf("command %q not registered", want)
		}
	}
}

func TestVersionShowsBetaLabel(t *testing.T) {
	h := newHarness(t)
	old := Version
	defer func() { Version = old }()
	Version = "1.0.0-beta.1"
	if out := h.run(exitOK, "version"); !strings.Contains(out, "Beta 1, önsürüm") {
		t.Fatalf("version: %q", out)
	}
	// The JSON form stays machine-readable for the updater.
	if out := h.run(exitOK, "version", "--json"); !strings.Contains(out, `"version":"1.0.0-beta.1"`) {
		t.Fatalf("version --json: %q", out)
	}
	out := h.run(exitOK, "about", "--json")
	var info struct{ Channel, Label string }
	if err := json.Unmarshal([]byte(out), &info); err != nil || info.Channel == "" || info.Label == "" {
		t.Fatalf("about: %q %v", out, err)
	}
	if !strings.Contains(version.Label("2.0.0-beta.3"), "Beta 3") {
		t.Fatal("label")
	}
}

func TestAutostartRunHonoursSetting(t *testing.T) {
	h := newHarness(t)
	dir, _ := h.env.DefaultStateDir()
	if err := svcmgr.SaveAutostartSetting(dir, false); err != nil {
		t.Fatal(err)
	}
	// Off: exits at once without starting anything.
	h.run(exitOK, "autostart", "run")
	out := h.run(exitOK, "autostart", "status")
	if !strings.Contains(out, "kapalı") || !strings.Contains(out, filepath.Join(dir, svcmgr.AutostartSettingFile)) {
		t.Fatalf("status: %q", out)
	}
	out = h.run(exitOK, "autostart", "status", "--json")
	var st autostartStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Enabled || len(st.Entries) != 2 {
		t.Fatalf("status json: %q %v", out, err)
	}
}

func TestCommandsPlatformAndPanelWindowArgs(t *testing.T) {
	h := newHarness(t)
	if out := h.run(exitOK, "commands"); !strings.Contains(out, "split-tunnel") || !strings.Contains(out, "window") {
		t.Fatalf("commands: %q", out)
	}
	if out := h.run(exitOK, "commands", "--json"); !strings.Contains(out, `"command": "app"`) {
		t.Fatalf("commands json: %q", out)
	}
	// No link: exit code 2 for the tray.
	h.run(winapp.PanelWindowExitInvalid, "panel-window")
	// A link outside the loopback origin is refused before any window.
	h.env.Stdin = strings.NewReader("https://example.com/\n")
	h.run(winapp.PanelWindowExitInvalid, "panel-window")
	h.run(exitUsage, "discreet")
	h.run(exitOK, "discreet", "status")
}
