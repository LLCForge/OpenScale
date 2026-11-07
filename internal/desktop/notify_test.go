package desktop

import (
	"testing"

	"github.com/openscale/openscale/internal/panel"
)

func TestAlertNotifierAnnouncesOncePerAppearance(t *testing.T) {
	var n alertNotifier
	captive := panel.AppStatus{Health: []panel.HealthAlert{{Code: panel.HealthCaptivePortal}, {Code: panel.HealthTunnelDown}}}
	if got := n.update(captive, true); len(got) != 1 {
		t.Fatalf("first appearance: %v", got)
	}
	if got := n.update(captive, true); len(got) != 0 {
		t.Fatalf("repeated: %v", got)
	}
	// An unreachable service forgets nothing.
	if got := n.update(panel.AppStatus{}, false); len(got) != 0 {
		t.Fatal("unreachable")
	}
	if got := n.update(captive, true); len(got) != 0 {
		t.Fatal("still present after an unreachable poll")
	}
	n.update(panel.AppStatus{}, true)
	if got := n.update(captive, true); len(got) != 1 {
		t.Fatalf("appeared again: %v", got)
	}
}
