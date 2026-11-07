package netdrive

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

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

func homeDoc(t *testing.T) *trust.Document {
	t.Helper()
	id, err := trust.NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.NewDocument(id, "ev.test", netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64"), now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"telefon", "nas", "pc", "router", "sunucu"} {
		s, err := trust.GenerateDeviceSecrets(rand.Reader, now)
		if err != nil {
			t.Fatal(err)
		}
		_, req, err := s.NewEnrollmentRequest(n, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := doc.AddDevice(req, n, nil, now, 365*24*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []trust.Rule{
		{From: []string{"telefon"}, To: []string{"pc"}, Service: trust.ServiceWake, Via: []string{"router", "sunucu", "telefon"}},
		{From: []string{"telefon"}, To: []string{"router", "sunucu"}, Protocol: trust.ProtocolTCP, Ports: []string{"4046"}},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	return doc
}

func TestMountValidate(t *testing.T) {
	ok := Mount{Name: "Ev NAS", Device: "nas", Share: "aile", Letter: "Z:", Point: "/Users/ayse/nas"}
	for _, goos := range []string{"windows", "darwin", "linux"} {
		if err := ok.Validate(goos); err != nil {
			t.Errorf("%s: %v", goos, err)
		}
	}
	bad := []Mount{
		{Name: "x", Share: "../etc", Letter: "Z:"},
		{Name: "x", Share: "a", Letter: "C:"},
		{Name: "x", Share: "a", Letter: "Z"},
		{Name: "x", Share: "a", Letter: "Z:", Username: "a b"},
	}
	for _, m := range bad {
		if err := m.Validate("windows"); err == nil {
			t.Errorf("accepted %+v", m)
		}
	}
	for _, p := range []string{"", "rel/dir", "/etc/x", "/", "/a/../b", "/System/Volumes/x"} {
		if err := (Mount{Name: "x", Share: "a", Point: p}).Validate("darwin"); err == nil {
			t.Errorf("point %q accepted", p)
		}
	}
	if err := ok.Validate("plan9"); !errors.Is(err, ErrUnsupported) {
		t.Fatal("unknown OS accepted")
	}
}

func TestResolveHostAndPlans(t *testing.T) {
	doc := homeDoc(t)
	host, err := ResolveHost(doc, "nas")
	if err != nil || !doc.IPv4Prefix.Contains(host) {
		t.Fatalf("%v %v", host, err)
	}
	if _, err := ResolveHost(doc, "yok"); !errors.Is(err, ErrNotTunnel) {
		t.Fatal("unknown device resolved")
	}
	m := Mount{Name: "NAS", Device: "nas", Share: "aile foto", Username: "ayse", Point: "/Users/ayse/nas"}
	c, err := Plan(m, host, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != "/sbin/mount_smbfs" || c.Args[0] != "-N" || c.Args[1] != "//ayse@"+host.String()+"/aile%20foto" || c.Args[2] != m.Point {
		t.Fatalf("%+v", c)
	}
	c, _ = Plan(m, host, "linux")
	if c.Path != "gio" || c.Args[1] != "smb://ayse@"+host.String()+"/aile%20foto" {
		t.Fatalf("%+v", c)
	}
	m.Linux, m.Point, m.CredentialsFile = "cifs", "/mnt/nas", "/home/ayse/.nas-cred"
	c, _ = Plan(m, host, "linux")
	if c.Path != "mount.cifs" || !strings.Contains(c.Args[3], "credentials=/home/ayse/.nas-cred") || !strings.Contains(c.Args[3], "seal") {
		t.Fatalf("%+v", c)
	}
	u, _ := UnmountPlan(m, host, "linux")
	if u.Path != "umount" || u.Args[0] != "/mnt/nas" {
		t.Fatalf("%+v", u)
	}
	m.Letter = "Z:"
	if _, err := Plan(m, host, "windows"); !errors.Is(err, ErrUnsupported) {
		t.Fatal("windows uses the API, not a command")
	}
}

func TestUNCAndURL(t *testing.T) {
	v4 := netip.MustParseAddr("100.64.0.2")
	if got, err := UNC(v4, "aile"); err != nil || got != `\\100.64.0.2\aile` {
		t.Fatal(got, err)
	}
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
	if _, err := UNC(v6, "a"); err == nil {
		t.Fatal("IPv6 UNC accepted")
	}
	if got := SMBURL(v6, "a$", "u@x"); got != "smb://u%40x@[fd7a:115c:a1e0::2]/a%24" {
		t.Fatal(got)
	}
}

func TestOrderRelays(t *testing.T) {
	got := OrderRelays([]string{"a", "b", "self", "pc", "c"}, "self", "pc", func(n string) bool { return n == "c" })
	if strings.Join(got, ",") != "self,c,a,b" {
		t.Fatal(got)
	}
}

func TestWakeTriesRelays(t *testing.T) {
	doc := homeDoc(t)
	var sent []netip.AddrPort
	w := &Waker{
		Online: func(n string) bool { return n == "sunucu" },
		Now:    func() time.Time { return now },
		Send: func(_ context.Context, ap netip.AddrPort, target, mac string) (int, error) {
			sent = append(sent, ap)
			if len(sent) == 1 {
				return 0, errors.New("kapalı")
			}
			if target != "pc" || mac != "00:11:22:33:44:55" {
				return 0, errors.New("yanlış istek")
			}
			return 3, nil
		},
	}
	res, err := w.Wake(context.Background(), doc, "telefon", "pc", "00-11-22-33-44-55")
	if err != nil {
		t.Fatal(err)
	}
	if res.Relay != "router" || strings.Join(res.Tried, ",") != "sunucu,router" || len(sent) != 2 || sent[0].Port() != trust.WakePort {
		t.Fatalf("%+v %v", res, sent)
	}
	if _, err := w.Wake(context.Background(), doc, "telefon", "pc", "00:11:22:33:44:55"); !errors.Is(err, ErrWakeCooldown) {
		t.Fatalf("cooldown: %v", err)
	}
	if _, err := w.Wake(context.Background(), doc, "nas", "pc", "00:11:22:33:44:55"); !errors.Is(err, ErrWakeNoRule) {
		t.Fatalf("no rule: %v", err)
	}
	if _, err := w.Wake(context.Background(), doc, "telefon", "pc", "ff:ff:ff:ff:ff:ff"); err == nil {
		t.Fatal("broadcast MAC accepted")
	}
}

func TestWakeLocalFirst(t *testing.T) {
	doc := homeDoc(t)
	// telefon is itself listed as a relay: it sends on its own LAN first.
	called := false
	w := &Waker{Local: func(_ context.Context, hw net.HardwareAddr) (int, error) {
		called = true
		return 3, nil
	}, Send: func(context.Context, netip.AddrPort, string, string) (int, error) {
		t.Fatal("tunnel used although local send works")
		return 0, nil
	}}
	res, err := w.Wake(context.Background(), doc, "telefon", "pc", "00:11:22:33:44:55")
	if err != nil || !called || res.Relay != "telefon" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestShortNames(t *testing.T) {
	doc := homeDoc(t)
	tbl := ShortNames{Entries: []ShortName{
		{Name: "depo", Device: "nas"},
		{Name: "ha", Device: "sunucu", Port: 8123},
		{Name: "yazici", Device: "router", Port: 631, Scheme: "https", Path: "/printers"},
	}}
	if err := tbl.Validate(doc); err != nil {
		t.Fatal(err)
	}
	e, ok := tbl.Lookup("HA.")
	if !ok {
		t.Fatal("lookup")
	}
	u, err := e.URL(doc)
	if err != nil || u != "http://sunucu.ev.test:8123/" {
		t.Fatalf("%s %v", u, err)
	}
	y, _ := tbl.Lookup("yazici")
	if u, _ := y.URL(doc); u != "https://router.ev.test:631/printers" {
		t.Fatal(u)
	}
	d, _ := tbl.Lookup("depo")
	if _, err := d.URL(doc); err == nil {
		t.Fatal("plain name produced a URL")
	}
	recs := tbl.Records(doc)
	if len(recs) != 3 || !recs[0].IPv4.IsValid() {
		t.Fatalf("%+v", recs)
	}
	for _, bad := range []ShortName{
		{Name: "nas", Device: "nas"},
		{Name: "wpad", Device: "nas"},
		{Name: "Büyük", Device: "nas"},
		{Name: "x", Device: "yok"},
		{Name: "x", Device: "nas", Scheme: "ftp", Port: 21},
		{Name: "x", Device: "nas", Path: "/a"},
		{Name: "x", Device: "nas", Port: 80, Path: "//evil.example.test"},
	} {
		if err := (ShortNames{Entries: []ShortName{bad}}).Validate(doc); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	path := filepath.Join(testDir(t), ShortNamesFile)
	if err := SaveShortNames(path, doc, tbl); err != nil {
		t.Fatal(err)
	}
	got, err := LoadShortNames(path)
	if err != nil || len(got.Entries) != 3 {
		t.Fatalf("%+v %v", got, err)
	}
}
