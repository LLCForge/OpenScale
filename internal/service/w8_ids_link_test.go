package service

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// idsSYN builds an IPv4 TCP SYN header, as the tunnel would hand it to
// the filter (no payload).
func idsSYN(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	pkt[32] = 5 << 4
	pkt[33] = 0x02
	return pkt
}

func idsSetup(t *testing.T) (*idsLink, *filter.Filter, *trust.Document, *w4Sink, string) {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	m := newW4Monitor(dir, func() time.Time { return now })
	sink := &w4Sink{}
	m.event = func(ev panel.DiagEvent) {
		sink.mu.Lock()
		sink.events = append(sink.events, ev)
		sink.mu.Unlock()
	}
	doc := w4Doc(1, "nas", "laptop")
	doc.Rules = []trust.Rule{{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"443"}}}
	f := filter.New(func() time.Time { return now })
	f.Update(doc, doc.Devices[0])
	return newIDSLink(dir, m), f, doc, sink, dir
}

// TestIDSLinkPortScanFromTunnel scans the device's ports from a peer
// through the real packet filter and expects an event without addresses,
// and no quarantine while the owner has not turned it on.
func TestIDSLinkPortScanFromTunnel(t *testing.T) {
	ctx := context.Background()
	l, f, doc, sink, _ := idsSetup(t)
	nas, laptop := doc.Devices[0], doc.Devices[1]
	l.step(ctx, f, doc, nas.Name) // attaches the tap
	if f.FlowTap() == nil {
		t.Fatal("tap not attached")
	}
	for p := uint16(1); p <= 60; p++ {
		f.Inbound(idsSYN(laptop.IPv4, nas.IPv4, 40000+p, p))
	}
	if n := l.step(ctx, f, doc, nas.Name); n != 60 {
		t.Fatalf("drained %d, want 60", n)
	}
	k := sink.kinds()
	if k[EventIDSAlert] == 0 {
		t.Fatalf("no IDS alert: %v", k)
	}
	if k[EventIDSQuarantine] != 0 || len(f.Quarantined()) != 0 {
		t.Fatal("quarantined without the owner's opt-in")
	}
	for _, e := range sink.events {
		if strings.Contains(e.Message, "100.64.") {
			t.Fatalf("address leaked: %+v", e)
		}
		if e.Kind == EventIDSAlert && e.Peer != "laptop" {
			t.Fatalf("subject %q, want laptop", e.Peer)
		}
	}
}

func TestIDSLinkAutoQuarantine(t *testing.T) {
	ctx := context.Background()
	l, f, doc, sink, dir := idsSetup(t)
	if err := SaveIDSConfig(dir, IDSConfig{AutoQuarantine: true, QuarantineMinutes: 15}); err != nil {
		t.Fatal(err)
	}
	nas, laptop := doc.Devices[0], doc.Devices[1]
	l.step(ctx, f, doc, nas.Name)
	for p := uint16(1); p <= 40; p++ {
		f.Inbound(idsSYN(laptop.IPv4, nas.IPv4, 41000+p, p))
	}
	l.step(ctx, f, doc, nas.Name)
	q := f.Quarantined()
	if len(q) != 1 || q[0].Peer != "laptop" || !strings.HasPrefix(q[0].Reason, "ids:") || q[0].Until.IsZero() {
		t.Fatalf("quarantine = %+v", q)
	}
	if sink.kinds()[EventIDSQuarantine] != 1 {
		t.Fatalf("events %v", sink.kinds())
	}
	// The quarantine is local and reversible: the allowed port is refused
	// now and passes again after release.
	if f.Inbound(idsSYN(laptop.IPv4, nas.IPv4, 50000, 443)) {
		t.Fatal("quarantined peer passed")
	}
	if !f.Release("laptop") || !f.Inbound(idsSYN(laptop.IPv4, nas.IPv4, 50001, 443)) {
		t.Fatal("release did not restore the rules")
	}
	// The device itself is never quarantined (own outbound scan).
	for p := uint16(1); p <= 40; p++ {
		f.Outbound(idsSYN(nas.IPv4, laptop.IPv4, 42000+p, p))
	}
	l.step(ctx, f, doc, nas.Name)
	if len(f.Quarantined()) != 0 {
		t.Fatalf("self quarantined: %+v", f.Quarantined())
	}
}

func TestIDSLinkDisabledDetaches(t *testing.T) {
	ctx := context.Background()
	l, f, doc, _, dir := idsSetup(t)
	l.step(ctx, f, doc, "nas")
	if f.FlowTap() == nil {
		t.Fatal("not attached")
	}
	if err := SaveIDSConfig(dir, IDSConfig{Disabled: true}); err != nil {
		t.Fatal(err)
	}
	l.loaded = false
	l.step(ctx, f, doc, "nas")
	if f.FlowTap() != nil {
		t.Fatal("tap stays when disabled")
	}
	// A new engine's filter takes the tap over from the old one.
	if err := os.Remove(filepath.Join(dir, IDSFile)); err != nil {
		t.Fatal(err)
	}
	l.loaded = false
	f2 := filter.New(time.Now)
	l.step(ctx, f, doc, "nas")
	l.step(ctx, f2, doc, "nas")
	if f.FlowTap() != nil || f2.FlowTap() == nil {
		t.Fatal("tap not moved to the new filter")
	}
}

func TestIDSConfigStrict(t *testing.T) {
	dir := t.TempDir()
	bad := []string{
		`{"auto_quarantine":true,"bilinmeyen":1}`,
		`{"quarantine_minutes":5000}`,
		`{"quarantine_minutes":-1}`,
		`{"disabled":true,"auto_quarantine":true}`,
		`{"disabled":false} {}`,
	}
	for i, s := range bad {
		if err := os.WriteFile(filepath.Join(dir, IDSFile), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIDSConfig(dir); err == nil {
			t.Fatalf("%d accepted: %s", i, s)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, IDSFile), []byte(`{"auto_quarantine":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadIDSConfig(dir)
	if err != nil || !c.AutoQuarantine || c.QuarantineFor() != 30*time.Minute {
		t.Fatalf("%+v %v", c, err)
	}
}
