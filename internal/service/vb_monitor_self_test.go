package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

// TestMonitorSnapshotCountsSelfOnline: the device that runs the engine is
// online in the monitor; before the beta check the panel's monitor page
// listed the own device as "offline" because it never handshakes with
// itself.
func TestMonitorSnapshotCountsSelfOnline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newRuntime(t, ctx, t.TempDir(), "masa")
	if _, err := r.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel", 10*time.Second, func() bool { st := r.Status(); return st.Device != nil && st.Device.Running })
	snap, ok := r.monitorSnapshot()
	if !ok {
		t.Fatal("no snapshot while the tunnel runs")
	}
	seen, has := snap.lastSeen[snap.self.Name]
	if !has || time.Since(seen) > time.Minute {
		t.Fatalf("own device %q not seen as online: %v", snap.self.Name, snap.lastSeen)
	}

	// The same through the panel the tray signs in to: the monitor
	// endpoint reaches the service (not 501) and shows the own device
	// online.
	r.monitor().tick(ctx)
	c := newPanelClient(t, r)
	var v panel.MonitorView
	if code := c.getJSON("/api/g7/monitor", &v); code != http.StatusOK {
		t.Fatalf("monitor endpoint: %d", code)
	}
	found := false
	for _, d := range v.Devices {
		if d.Name == snap.self.Name {
			found = d.Online
		}
	}
	if !found {
		t.Fatalf("own device not online in the panel: %+v", v.Devices)
	}
}
