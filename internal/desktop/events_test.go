package desktop

import (
	"testing"

	"github.com/openscale/openscale/internal/panel"
)

func TestNotificationsFor(t *testing.T) {
	rep := panel.EventStreamReply{Notifications: true, Events: []panel.StreamEvent{
		{Kind: "device_added", Message: "Ağa yeni cihaz eklendi: telefon.", Notify: true},
		{Kind: "peer_online", Message: "telefon çevrimiçi oldu."},
	}}
	got := notificationsFor(rep)
	if len(got) != 1 || got[0] != "Ağa yeni cihaz eklendi: telefon." {
		t.Fatalf("got %q", got)
	}
	rep.Notifications = false
	if got := notificationsFor(rep); got != nil {
		t.Fatalf("notifications off: %q", got)
	}
}

func TestRefreshGate(t *testing.T) {
	g := &refreshGate{}
	if g.skip() {
		t.Fatal("must refresh while the stream is down")
	}
	g.streamUp.Store(true)
	refreshed := 0
	for i := 0; i < slowRefreshTicks*3; i++ {
		if !g.skip() {
			refreshed++
		}
	}
	if refreshed != 3 {
		t.Fatalf("refreshed %d times", refreshed)
	}
}
