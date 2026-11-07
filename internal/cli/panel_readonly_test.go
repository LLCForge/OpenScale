package cli

import (
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/service"
)

func TestPanelReadOnlyCommand(t *testing.T) {
	dir := t.TempDir()
	elevated := false
	saved := panelReadOnly
	panelReadOnly = panelReadOnlyOps{
		dataDir:  func() string { return dir },
		elevated: func() bool { return elevated },
		set:      service.SetPanelReadOnly,
		get:      service.PanelReadOnly,
	}
	t.Cleanup(func() { panelReadOnly = saved })

	h := newHarness(t)
	h.run(exitUsage, "panel", "readonly")
	h.run(exitUsage, "panel", "readonly", "belki")
	h.run(exitError, "panel", "readonly", "on")
	if service.PanelReadOnly(dir) || !strings.Contains(h.stderr.String(), "yönetici") {
		t.Fatalf("must ask for administrator rights: %q", h.stderr.String())
	}
	elevated = true
	if out := h.run(exitOK, "panel", "readonly", "on"); !strings.Contains(out, "salt okunur") || !service.PanelReadOnly(dir) {
		t.Fatalf("on: %q", out)
	}
	if out := h.run(exitOK, "panel", "readonly", "status"); !strings.Contains(out, "Panel salt okunur:") {
		t.Fatalf("status: %q", out)
	}
	if out := h.run(exitOK, "panel", "readonly", "off"); !strings.Contains(out, "açık") || service.PanelReadOnly(dir) {
		t.Fatalf("off: %q", out)
	}
	// An explicit data directory works without the default location.
	other := t.TempDir()
	if h.run(exitOK, "panel", "readonly", "on", "--data-dir", other); !service.PanelReadOnly(other) {
		t.Fatal("--data-dir ignored")
	}
	h.run(exitError, "panel", "readonly", "on", "--data-dir", other+"/yok")
}
