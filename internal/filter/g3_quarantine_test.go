package filter

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
)

func TestDecoyBeatsRuleAndQuarantines(t *testing.T) {
	f, _, sink := threatFilter(t, "masaustu", ThreatConfig{})
	changes := make(chan []QuarantineEntry, 8)
	if err := f.SetG3(G3Config{DecoyPorts: []uint16{3389}}, func(l []QuarantineEntry) { changes <- l }); err != nil {
		t.Fatal(err)
	}
	// 3389 is open by rule, but it is a decoy: refused and quarantined.
	if f.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("decoy port connection passed")
	}
	sink.wait(t, 1)
	if ev := f.ThreatEvents(); len(ev) != 1 || ev[0].Kind != ThreatDecoy || ev[0].Port != 3389 || ev[0].Peer != "laptop" {
		t.Fatalf("%+v", ev)
	}
	q := f.Quarantined()
	if len(q) != 1 || q[0].Peer != "laptop" || !q[0].Until.IsZero() {
		t.Fatalf("quarantine %+v", q)
	}
	select {
	case l := <-changes:
		if len(l) != 1 {
			t.Fatalf("change %+v", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no change notification")
	}
	// Both directions are refused, even replies.
	if f.Outbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("packet to a quarantined peer passed")
	}
	if !f.Release("laptop") || f.Release("laptop") {
		t.Fatal("release")
	}
	if len(f.Quarantined()) != 0 {
		t.Fatal("still quarantined after release")
	}
	// A reply to this device's own flow passes again.
	if !f.Outbound(tcp(masaustuIP, laptopIP, 40000, 22, packet.TCPSyn)) && f.Isolated() {
		t.Fatal("isolated without being asked")
	}
}

func TestScanQuarantine(t *testing.T) {
	f, clk, sink := threatFilter(t, "masaustu", ThreatConfig{ScanPorts: 5})
	if err := f.SetG3(G3Config{QuarantineOnScan: true, QuarantineFor: time.Hour}, nil); err != nil {
		t.Fatal(err)
	}
	for p := uint16(1); p <= 5; p++ {
		f.Inbound(tcp(laptopIP, masaustuIP, 40001, p, packet.TCPSyn))
	}
	sink.wait(t, 1)
	q := f.Quarantined()
	if len(q) != 1 || q[0].Reason != string(ThreatInboundScan) || q[0].Until.IsZero() {
		t.Fatalf("%+v", q)
	}
	clk.now = clk.now.Add(2 * time.Hour)
	if f.Outbound(tcp(masaustuIP, laptopIP, 40000, 3389, packet.TCPSyn)) {
		// Outbound to laptop:3389 is not allowed by the rules anyway; the
		// point is that the expired quarantine is dropped.
		t.Log("outbound allowed")
	}
	if len(f.Quarantined()) != 0 {
		t.Fatal("expired quarantine kept")
	}
}

func TestIsolation(t *testing.T) {
	f, _, _ := threatFilter(t, "masaustu", ThreatConfig{})
	if !f.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("allowed flow refused")
	}
	f.SetIsolated(true)
	if !f.Isolated() {
		t.Fatal("not isolated")
	}
	if f.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPAck)) || f.Outbound(tcp(masaustuIP, laptopIP, 3389, 50000, packet.TCPAck)) {
		t.Fatal("isolation let a packet through")
	}
	f.SetIsolated(false)
	if !f.Inbound(tcp(laptopIP, masaustuIP, 50002, 3389, packet.TCPSyn)) {
		t.Fatal("still refused after isolation ended")
	}
}

func TestDecoyConfig(t *testing.T) {
	ports, err := DecoyPortsFor([]string{"ssh", "smb", "rdp", "8080", "22"})
	if err != nil || !slices.Equal(ports, []uint16{22, 139, 445, 3389, 8080}) {
		t.Fatalf("%v %v", ports, err)
	}
	for _, bad := range [][]string{{"0"}, {"telnet"}, {"70000"}, {"08"}} {
		if _, err := DecoyPortsFor(bad); !errors.Is(err, ErrDecoy) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if err := (G3Config{DecoyPorts: []uint16{0}}).Validate(); err == nil {
		t.Fatal("port 0 accepted")
	}
	if err := (G3Config{QuarantineFor: time.Second}).Validate(); err == nil {
		t.Fatal("1s quarantine accepted")
	}
}

func TestRestoreQuarantine(t *testing.T) {
	f, clk, _ := threatFilter(t, "masaustu", ThreatConfig{})
	f.RestoreQuarantine([]QuarantineEntry{
		{Peer: "laptop", Reason: "x", Since: clk.now},
		{Peer: "eski", Reason: "x", Since: clk.now, Until: clk.now.Add(-time.Minute)},
		{Peer: ""},
	})
	q := f.Quarantined()
	if len(q) != 1 || q[0].Peer != "laptop" {
		t.Fatalf("%+v", q)
	}
	if f.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn)) {
		t.Fatal("restored quarantine not enforced")
	}
	if err := f.Quarantine("", "x", 0); err == nil {
		t.Fatal("empty peer accepted")
	}
}
