//go:build windows

package desktop

import (
	"testing"

	"github.com/openscale/openscale/internal/panel"
)

// The tray keeps "Paneli aç", the panic item and the full exit (W2).
func TestTrayMenuHasOpenPanicAndQuit(t *testing.T) {
	st := panel.AppStatus{Device: &panel.DeviceStatus{Name: "dizustu", IPv4: "100.64.0.2", Connected: true}}
	items, _ := buildTrayMenu(st, true, map[int]string{}, map[int]string{})
	want := map[int]string{idOpen: "Paneli aç", idPanic: "Panik: ağı kilitle...", idQuit: "OpenScale'i tamamen kapat"}
	for _, it := range items {
		if label, ok := want[it.ID]; ok && it.Label == label {
			delete(want, it.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing tray items: %v", want)
	}
}
