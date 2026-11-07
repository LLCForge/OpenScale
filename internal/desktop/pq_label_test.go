package desktop

import (
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

func TestPeerDetail(t *testing.T) {
	p := panel.PeerInfo{IPv4: "100.64.0.2"}
	if got := peerDetail(p); got != "100.64.0.2" {
		t.Fatalf("unknown state: %q", got)
	}
	p.PostQuantum = panel.PostQuantumActive
	if got := peerDetail(p); got != "100.64.0.2  ·  kuantum sonrası" {
		t.Fatalf("pq: %q", got)
	}
	p.PostQuantum = panel.PostQuantumUnsupported
	if got := peerDetail(p); got != "100.64.0.2  ·  klasik" {
		t.Fatalf("classical: %q", got)
	}
}

func TestConnectionLabelOverTCP(t *testing.T) {
	now := time.Now()
	st := panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{Name: "laptop", Connected: true, Running: true, LastSync: &now}}
	if got := connectionLabel(st); got != "Bağlı" {
		t.Fatalf("label = %q", got)
	}
	st.Device.CoordinatorOverTCP = true
	if got := connectionLabel(st); got != "Bağlı (koordinatöre TCP ile)" {
		t.Fatalf("label = %q", got)
	}
}
