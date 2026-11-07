package netwatch

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func testDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("testdata", ".tmp", strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Join("testdata", ".tmp"))
		_ = os.Remove("testdata")
	})
	return dir
}

var (
	srcA = netip.MustParseAddr("100.64.0.7")
	dstB = netip.MustParseAddr("100.64.0.2")
	t0   = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
)

func kinds(as []Alert) map[string]Alert {
	m := map[string]Alert{}
	for _, a := range as {
		m[a.Kind] = a
	}
	return m
}

func TestDetectorPortScan(t *testing.T) {
	d := NewDetector(IDSConfig{})
	var all []Alert
	for p := range 25 {
		all = append(all, d.Observe(Flow{At: t0.Add(time.Duration(p) * time.Second), Src: srcA, Dst: dstB, Proto: 6, Port: uint16(1000 + p)})...)
	}
	k := kinds(all)
	if a, ok := k[KindPortScan]; !ok || !a.Quarantine || a.Src != srcA || a.Count != defaultScanPorts {
		t.Fatalf("%+v", all)
	}
	if len(all) != 1 {
		t.Fatalf("cooldown not applied: %+v", all)
	}
}

func TestDetectorSlowScanNotFlagged(t *testing.T) {
	d := NewDetector(IDSConfig{})
	for p := range 30 {
		if a := d.Observe(Flow{At: t0.Add(time.Duration(p) * 10 * time.Second), Src: srcA, Dst: dstB, Proto: 6, Port: uint16(1000 + p)}); len(a) != 0 {
			t.Fatalf("slow scan flagged at %d: %+v", p, a)
		}
	}
}

func TestDetectorSweepFloodBadBrute(t *testing.T) {
	d := NewDetector(IDSConfig{})
	var all []Alert
	for h := range 16 {
		all = append(all, d.Observe(Flow{At: t0, Src: srcA, Dst: netip.AddrFrom4([4]byte{100, 64, 1, byte(h + 1)}), Proto: 6, Port: 445})...)
	}
	if _, ok := kinds(all)[KindHostSweep]; !ok {
		t.Fatalf("sweep: %+v", all)
	}

	d = NewDetector(IDSConfig{})
	all = nil
	for i := range 200 {
		all = append(all, d.Observe(Flow{At: t0.Add(time.Duration(i) * 10 * time.Millisecond), Src: srcA, Dst: dstB, Proto: 17, Port: 53})...)
	}
	if _, ok := kinds(all)[KindSYNFlood]; !ok {
		t.Fatalf("flood: %+v", all)
	}

	d = NewDetector(IDSConfig{})
	all = nil
	for i, p := range []uint16{4444, 5555, 37215} {
		all = append(all, d.Observe(Flow{At: t0.Add(time.Duration(i) * time.Second), Src: srcA, Dst: dstB, Proto: 6, Port: p})...)
	}
	if a, ok := kinds(all)[KindBadPorts]; !ok || !strings.Contains(a.Message, "4444") {
		t.Fatalf("bad ports: %+v", all)
	}

	d = NewDetector(IDSConfig{})
	all = nil
	for i := range 30 {
		all = append(all, d.Observe(Flow{At: t0.Add(time.Duration(i) * 8 * time.Second), Src: srcA, Dst: dstB, Proto: 6, Port: 3389})...)
	}
	a, ok := kinds(all)[KindBruteForce]
	if !ok || a.Port != 3389 || a.Quarantine {
		t.Fatalf("brute: %+v", all)
	}
}

func TestDetectorBounded(t *testing.T) {
	d := NewDetector(IDSConfig{})
	for i := range maxSources + 10 {
		src := netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)})
		d.Observe(Flow{At: t0.Add(time.Duration(i) * time.Millisecond), Src: src, Dst: dstB, Proto: 6, Port: 80})
	}
	if n := d.Sources(); n > maxSources {
		t.Fatalf("sources %d", n)
	}
	if a := d.Observe(Flow{At: t0}); a != nil {
		t.Fatal("invalid flow produced alerts")
	}
}

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestLANWatchLearnAlarmPersist(t *testing.T) {
	w, err := NewLANWatch()
	if err != nil {
		t.Fatal(err)
	}
	lan := []Neighbor{
		{Addr: netip.MustParseAddr("192.168.1.10"), MAC: mac("00:11:22:33:44:55")},
		{Addr: netip.MustParseAddr("192.168.1.11"), MAC: mac("ff:ff:ff:ff:ff:ff")},
		{Addr: netip.MustParseAddr("192.168.1.12"), MAC: mac("00:00:00:00:00:00")},
	}
	if n := w.Observe(lan, t0); len(n) != 0 || len(w.Known()) != 1 {
		t.Fatalf("learning alarmed: %+v", n)
	}
	lan = append(lan, Neighbor{Addr: netip.MustParseAddr("192.168.1.20"), MAC: mac("a4:b1:c2:00:00:01")}, Neighbor{Addr: netip.MustParseAddr("192.168.1.21"), MAC: mac("02:aa:bb:cc:dd:ee")})
	n := w.Observe(lan, t0.Add(time.Minute))
	if len(n) != 2 || n[0].OUI != "a4:b1:c2" || n[0].Random || !n[1].Random {
		t.Fatalf("%+v", n)
	}
	if !strings.Contains(n[0].Message(), "a4:b1:c2") {
		t.Fatal(n[0].Message())
	}
	if err := w.Label(n[0].Digest, "yazıcı"); err != nil {
		t.Fatal(err)
	}
	dir := testDir(t)
	path := filepath.Join(dir, "lan.json")
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "33:44:55") || strings.Contains(string(raw), "334455") || strings.Contains(string(raw), "192.168.1.") {
		t.Fatalf("full MAC or address stored: %s", raw)
	}
	w2, err := LoadLANWatch(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := w2.Observe(lan, t0.Add(2*time.Minute)); len(n) != 0 {
		t.Fatalf("reloaded watch alarmed again: %+v", n)
	}
	if w2.Digest(mac("00:11:22:33:44:55")) != w.Digest(mac("00:11:22:33:44:55")) {
		t.Fatal("key not persisted")
	}
	other, _ := NewLANWatch()
	if other.Digest(mac("00:11:22:33:44:55")) == w.Digest(mac("00:11:22:33:44:55")) {
		t.Fatal("digest not keyed per installation")
	}
	labeled := false
	for _, k := range w2.Known() {
		if k.Label == "yazıcı" {
			labeled = true
		}
	}
	if !labeled || !w2.Forget(n[0].Digest) {
		t.Fatal("label or forget failed")
	}
}

func TestLANWatchIgnoreRandom(t *testing.T) {
	w, _ := NewLANWatch()
	w.Learning, w.IgnoreRandom = false, true
	if n := w.Observe([]Neighbor{{MAC: mac("02:aa:bb:cc:dd:ee")}}, t0); len(n) != 0 {
		t.Fatal("random MAC alarmed")
	}
}

func TestNeighborsDoesNotPanic(t *testing.T) {
	_ = Neighbors()
}

func TestPublicUnicast(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "100.64.0.1", "127.0.0.1", "192.0.2.5", "169.254.1.1", "::1", "fe80::1", "2001:db8::1", "224.0.0.1"} {
		if publicUnicast(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	if !publicUnicast(netip.MustParseAddr("11.22.33.44")) {
		t.Error("public address refused")
	}
}

func TestTargetsFromReports(t *testing.T) {
	doc := &trust.Document{Devices: []trust.Device{{Name: "ev"}, {Name: "ofis"}, {Name: "nat"}}}
	got := TargetsFromReports(doc, map[string]string{
		"ev":      "11.22.33.44",
		"ofis":    "11.22.33.44", // same address twice: audited once
		"nat":     "100.64.3.3",
		"yabanci": "11.22.33.45",
		"bozuk":   "x",
	})
	if len(got) != 1 || got[0].Device != "ev" {
		t.Fatalf("%+v", got)
	}
}

func TestAuditLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	open := netip.MustParseAddrPort(ln.Addr().String()).Port()
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := netip.MustParseAddrPort(closedLn.Addr().String()).Port()
	_ = closedLn.Close()
	cfg := AuditConfig{Ports: []uint16{open, closed, open}, Gap: minAuditGap, DialTimeout: time.Second, allowLoopback: true}
	f, err := Audit(context.Background(), cfg, []AuditTarget{{Device: "ev", Addr: netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Port != open {
		t.Fatalf("%+v", f)
	}
	opened, gone := AuditDiff(nil, f)
	if len(opened) != 1 || len(gone) != 0 {
		t.Fatal("diff opened")
	}
	opened, gone = AuditDiff(f, nil)
	if len(opened) != 0 || len(gone) != 1 {
		t.Fatal("diff closed")
	}
}

func TestAuditRefusesPrivateAndBadConfig(t *testing.T) {
	cfg := AuditConfig{Ports: []uint16{22}}
	if _, err := Audit(context.Background(), cfg, []AuditTarget{{Device: "x", Addr: netip.MustParseAddr("192.168.1.1")}}); err == nil {
		t.Fatal("private target accepted")
	}
	if _, err := Audit(context.Background(), cfg, []AuditTarget{{Device: "x", Addr: netip.MustParseAddr("127.0.0.1")}}); err == nil {
		t.Fatal("loopback accepted without the test hook")
	}
	if err := (AuditConfig{}).Validate(); err == nil {
		t.Fatal("empty ports accepted")
	}
	if err := (AuditConfig{Ports: []uint16{1}, Gap: time.Millisecond}).Validate(); err == nil {
		t.Fatal("too fast accepted")
	}
}

func TestAuditDue(t *testing.T) {
	if !AuditDue(time.Time{}, t0, 0) || AuditDue(t0, t0.Add(time.Hour), time.Minute) || !AuditDue(t0, t0.Add(MinAuditInterval), time.Minute) {
		t.Fatal("AuditDue")
	}
}
