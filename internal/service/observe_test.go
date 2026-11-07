package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

func TestEventBusSinceAndWait(t *testing.T) {
	b := NewEventBus()
	b.Publish(panel.StreamEvent{Kind: "a"})
	b.Publish(panel.StreamEvent{Kind: "b"})
	evs, next := b.Since(context.Background(), 0, 0)
	if len(evs) != 2 || next != 2 || evs[0].Kind != "a" || evs[1].Seq != 2 {
		t.Fatalf("since 0: %+v %d", evs, next)
	}
	if evs, next := b.Since(context.Background(), 2, 0); len(evs) != 0 || next != 2 {
		t.Fatalf("nothing new: %+v %d", evs, next)
	}
	// A waiting reader wakes on the next event.
	got := make(chan []panel.StreamEvent, 1)
	go func() {
		evs, _ := b.Since(context.Background(), 2, 5*time.Second)
		got <- evs
	}()
	time.Sleep(20 * time.Millisecond)
	b.Publish(panel.StreamEvent{Kind: "c"})
	select {
	case evs := <-got:
		if len(evs) != 1 || evs[0].Kind != "c" {
			t.Fatalf("woken with %+v", evs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reader not woken")
	}
	// A position from before a restart starts over.
	if evs, _ := b.Since(context.Background(), 999, 0); len(evs) != 3 {
		t.Fatalf("restart: %d events", len(evs))
	}
	// The ring keeps the newest.
	for i := 0; i < busSize+10; i++ {
		b.Publish(panel.StreamEvent{Kind: "x"})
	}
	evs, _ = b.Since(context.Background(), 0, 0)
	if len(evs) != maxBatch || evs[0].Seq != b.Seq()-busSize+1 {
		t.Fatalf("ring: %d events, first %d", len(evs), evs[0].Seq)
	}
}

func testDoc() *trust.Document {
	return &trust.Document{
		Version: 3,
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.1")},
			{Name: "nas", IPv4: netip.MustParseAddr("100.80.0.2")},
		},
		Rules: []trust.Rule{
			{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}},
			{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}, Disabled: true},
			{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"8080"}},
			{From: []string{"*"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"8080"}, Action: trust.RuleDeny},
		},
	}
}

func TestRuleCause(t *testing.T) {
	doc := testDoc()
	cases := []struct {
		port   uint16
		reason string
		rule   int
	}{
		{22, panel.DenyDisabledRule, 2},
		{8080, panel.DenyDenyRule, 4},
		{3389, panel.DenyNoRule, 0},
	}
	for _, c := range cases {
		reason, rule, why := ruleCause(doc, "laptop", "nas", packet.ProtoTCP, c.port)
		if reason != c.reason || rule != c.rule || why == "" {
			t.Errorf("port %d: %s %d %q", c.port, reason, rule, why)
		}
	}
}

func TestExplainDenialMasksStrangers(t *testing.T) {
	e := explainDenial(filter.Denial{Inbound: true, Remote: netip.MustParseAddr("203.0.113.7"), Proto: packet.ProtoUDP, Port: 53, Reason: filter.DenyUnknownPeer, Count: 2})
	if e.Remote != "203.0.*.*" || e.Peer != "" || e.Direction != "in" || e.Proto != "udp" || e.Why == "" {
		t.Fatalf("%+v", e)
	}
	d := filter.Denial{Peer: "nas", Self: "laptop", Remote: netip.MustParseAddr("100.80.0.2"), Proto: packet.ProtoTCP, Port: 22, Reason: filter.DenyRules, Document: testDoc()}
	e = explainDenial(d)
	if e.Remote != "" || e.Reason != panel.DenyDisabledRule || e.Rule != 2 || e.Direction != "out" {
		t.Fatalf("%+v", e)
	}
}

func TestObserverAuditAndPrefs(t *testing.T) {
	dir := t.TempDir()
	o := NewObserver(ObserverConfig{Dir: dir})
	o.Security("device_added", audit.SeverityInfo, panel.CategoryDevice, "telefon", "Ağa yeni cihaz eklendi: telefon (192.168.1.20).", true)
	rep, err := o.AuditTail(10)
	if err != nil || len(rep.Records) != 1 || !rep.Verify.OK {
		t.Fatalf("audit: %+v %v", rep, err)
	}
	if strings.Contains(rep.Records[0].Message, "192.168.1.20") {
		t.Fatalf("address kept: %q", rep.Records[0].Message)
	}
	evs := o.EventsSince(context.Background(), 0, 0)
	if len(evs.Events) != 1 || !evs.Events[0].Notify || !evs.Notifications {
		t.Fatalf("events: %+v", evs)
	}
	if err := o.WriteMetrics(&bytes.Buffer{}); err != panel.ErrMetricsOff {
		t.Fatalf("metrics default: %v", err)
	}
	on, off := true, false
	if _, err := o.SetObservePrefs(panel.ObservePrefsChange{Metrics: &on, Notifications: &off}); err != nil {
		t.Fatal(err)
	}
	// The switches survive a restart; profiling does not.
	o2 := NewObserver(ObserverConfig{Dir: dir})
	p := o2.ObservePrefs()
	if !p.Metrics || p.Notifications || p.Profiling {
		t.Fatalf("saved prefs: %+v", p)
	}
	var buf bytes.Buffer
	if err := o2.WriteMetrics(&buf); err != nil || !strings.Contains(buf.String(), "openscale_tunnel_up 0") || !strings.Contains(buf.String(), "# TYPE go_goroutines gauge") {
		t.Fatalf("metrics: %v\n%s", err, buf.String())
	}
	if err := o2.Profile(context.Background(), panel.ProfileRequest{Kind: "heap"}, &buf); err != panel.ErrProfilingOff {
		t.Fatalf("profile while off: %v", err)
	}
	if _, err := o2.SetObservePrefs(panel.ObservePrefsChange{Profiling: &on}); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := o2.Profile(context.Background(), panel.ProfileRequest{Kind: "goroutine", Debug: 1}, &buf); err != nil || !strings.Contains(buf.String(), "goroutine") {
		t.Fatalf("profile: %v", err)
	}
	// metrics on, notifications off, profiling on, profile taken: all audited.
	if v, err := audit.Verify(dir); err != nil || !v.OK || v.Records < 4 {
		t.Fatalf("verify: %+v %v", v, err)
	}
}

func TestRedactJSON(t *testing.T) {
	in := `{"tunnel":{"log_level":"info","static_endpoints":["203.0.113.5:41641"]},"app_token":"gizli","nested":[{"private_key":"x"}]}`
	out := RedactJSON([]byte(in))
	for _, bad := range []string{"gizli", "203.0.113.5", `"x"`} {
		if strings.Contains(out, bad) {
			t.Fatalf("%q kept in %s", bad, out)
		}
	}
	if !strings.Contains(out, "log_level") {
		t.Fatalf("too much removed: %s", out)
	}
}

func TestPcapFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := writePcapHeader(&buf, 128); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1700000000, 123456000)
	if _, err := writePcapRecord(&buf, filter.CapturedPacket{At: at, Data: []byte{0x45, 0, 0, 20}, Length: 60}); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if binary.LittleEndian.Uint32(b[0:]) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(b[20:]) != linkTypeRaw || binary.LittleEndian.Uint32(b[16:]) != 128 {
		t.Fatalf("header % x", b[:24])
	}
	r := b[24:]
	if binary.LittleEndian.Uint32(r[0:]) != 1700000000 || binary.LittleEndian.Uint32(r[4:]) != 123456 ||
		binary.LittleEndian.Uint32(r[8:]) != 4 || binary.LittleEndian.Uint32(r[12:]) != 60 || len(r) != 20 {
		t.Fatalf("record % x", r)
	}
}

func TestSecurityWatch(t *testing.T) {
	o := NewObserver(ObserverConfig{Dir: t.TempDir()})
	w := &securityWatch{o: o}
	doc := testDoc()
	w.document(doc)
	next := *doc
	next.Version = 4
	next.Devices = []trust.Device{doc.Devices[0], {Name: "telefon"}}
	next.Revoked = []trust.Revocation{{Name: "nas"}}
	w.document(&next)
	w.syncError("sync: " + trust.ErrRollback.Error())
	w.syncError("sync: " + trust.ErrRollback.Error()) // reported once
	w.killSwitch(panel.AppStatus{Device: &panel.DeviceStatus{KillSwitchActive: true, ExitNodeWanted: "vps"},
		Health: []panel.HealthAlert{{Code: panel.HealthExitUnreachable}}})
	evs := o.EventsSince(context.Background(), 0, 0).Events
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
	}
	want := "document_changed,device_added,device_revoked,document_rollback_refused,killswitch_engaged"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("kinds = %v", kinds)
	}
}

func TestScrubMasksMACs(t *testing.T) {
	out := Scrub("link/ether 3c:22:fb:12:34:56 brd ff:ff:ff:ff:ff:ff\n 9 ...3c 22 fb 12 34 56 ......Intel\n")
	if strings.Contains(out, "12:34:56") || strings.Contains(out, "12 34 56") || !strings.Contains(out, "3c:22:fb:**:**:**") {
		t.Fatalf("%q", out)
	}
}
