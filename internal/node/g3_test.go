package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

func TestCloneFlips(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }
	// Forward roaming: home, phone, office. No flip.
	roam := []EndpointChange{{At: at(-9), Endpoint: "198.51.100.1:5000"}, {At: at(-8), Endpoint: "203.0.113.7:6000"}, {At: at(-7), Endpoint: "192.0.2.9:7000"}}
	if n, _ := cloneFlips(roam, now, 10*time.Minute); n != 0 {
		t.Fatalf("roaming counted %d flips", n)
	}
	// A copied key: two places answer in turn.
	var clone []EndpointChange
	for i := 0; i < 6; i++ {
		ep := "198.51.100.1:5000"
		if i%2 == 1 {
			ep = "203.0.113.7:6000"
		}
		clone = append(clone, EndpointChange{At: at(-6 + i), Endpoint: ep})
	}
	n, addrs := cloneFlips(clone, now, 10*time.Minute)
	if n != 4 || len(addrs) != 2 {
		t.Fatalf("clone: %d flips, %v", n, addrs)
	}
	// Relayed entries, port-only changes and old entries do not count.
	noise := []EndpointChange{{At: at(-3), Endpoint: "198.51.100.1:5000"}, {At: at(-2), Endpoint: "198.51.100.1:5001"},
		{At: at(-1), Endpoint: "relay-00", Relayed: true}, {At: at(-30), Endpoint: "203.0.113.7:6000"}}
	if n, _ := cloneFlips(noise, now, 10*time.Minute); n != 0 {
		t.Fatalf("noise counted %d", n)
	}
	if (CloneWatchConfig{Flips: 1}).validate() == nil || (CloneWatchConfig{Window: time.Second}).validate() == nil {
		t.Fatal("bad clone watch accepted")
	}
}

// tlsServer serves TLS handshakes with cert on 127.0.0.1 until the test ends.
func tlsServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func loopDial(ctx context.Context, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}

func TestProbeCanary(t *testing.T) {
	now := time.Now()
	real, realPin, err := obfs.GenerateCertificate([]string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	evil, _, _ := obfs.GenerateCertificate([]string{"127.0.0.1"}, now)
	roots := x509.NewCertPool()
	roots.AddCert(real.Leaf)
	good := tlsServer(t, real)
	mitm := tlsServer(t, evil)
	ctx := context.Background()

	if r := probeCanary(ctx, loopDial, good, nil, roots, now); r.Status != CanaryLearned || r.Pin != realPin.String() {
		t.Fatalf("learn: %+v", r)
	}
	if r := probeCanary(ctx, loopDial, good, []obfs.Pin{realPin}, roots, now); r.Status != CanaryOK {
		t.Fatalf("ok: %+v", r)
	}
	if r := probeCanary(ctx, loopDial, mitm, []obfs.Pin{realPin}, roots, now); r.Status != CanaryMITM {
		t.Fatalf("mitm: %+v", r)
	}
	// Without a pin, a chain the system does not trust is still reported.
	if r := probeCanary(ctx, loopDial, mitm, nil, roots, now); r.Status != CanaryUntrusted {
		t.Fatalf("untrusted: %+v", r)
	}
	if r := probeCanary(ctx, func(context.Context, string) (net.Conn, error) { return nil, errors.New("x") }, good, nil, roots, now); r.Status != CanaryUnreachable {
		t.Fatalf("unreachable: %+v", r)
	}
}

func TestExitCanaryConfig(t *testing.T) {
	bad := []ExitCanaryConfig{
		{Interval: time.Minute},
		{Targets: []CanaryTarget{{Address: "no-port"}}},
		{Targets: []CanaryTarget{{Address: "h:0"}}},
		{Targets: []CanaryTarget{{Address: "h:443", Pins: []string{"x"}}}},
		{Targets: make([]CanaryTarget, MaxCanaryTargets+1)},
	}
	for _, c := range bad {
		if c.validate() == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if err := (ExitCanaryConfig{Targets: []CanaryTarget{{Address: "bank.example:443"}}}).validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedTLS(t *testing.T) {
	cert, pin, err := obfs.GenerateCertificate([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := obfs.GenerateCertificate([]string{"127.0.0.1"}, time.Now())
	addr := tlsServer(t, cert)
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	try := func(pins []obfs.Pin) error {
		cfg := pinnedTLS(pins)("127.0.0.1")
		cfg.RootCAs = roots
		c, err := tls.Dial("tcp", addr, cfg)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	if err := try([]obfs.Pin{pin}); err != nil {
		t.Fatalf("right pin refused: %v", err)
	}
	if err := try([]obfs.Pin{other}); !errors.Is(err, obfs.ErrPinMismatch) {
		t.Fatalf("wrong pin: %v", err)
	}
}

func TestExitDNSPinValidation(t *testing.T) {
	e := &Engine{}
	pin := "sha256/" + "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	cases := []struct {
		up      string
		pins    []string
		require bool
		ok      bool
	}{
		{"https://dns.example/dns-query", []string{pin}, true, true},
		{"tls://dns.example", []string{pin}, false, true},
		{"1.1.1.1", []string{pin}, false, false},
		{"recursive", nil, true, false},
		{"https://dns.example/dns-query", nil, true, false},
		{"https://dns.example/dns-query", []string{"bad"}, false, false},
		{"", nil, false, true},
	}
	for _, c := range cases {
		e.cfg.ExitDNSUpstream = c.up
		e.cfg.G3 = G3Config{ExitDNSPins: c.pins, ExitDNSRequirePins: c.require}
		if err := e.validateExitDNSPins(); (err == nil) != c.ok {
			t.Errorf("%q %v %v: %v", c.up, c.pins, c.require, err)
		}
	}
	e.cfg.ExitDNSUpstream = "1.1.1.1"
	e.cfg.G3 = G3Config{ExitDNSRequirePins: true}
	if _, err := e.g3ExitForwarder(); !errors.Is(err, errExitDNSUnpinned) {
		t.Fatalf("unpinned upstream used: %v", err)
	}
}

func chainDoc() *trust.Document {
	return &trust.Document{Devices: []trust.Device{
		{Name: "laptop"},
		{Name: "ev", Roles: []trust.Role{trust.RoleExitNode}},
		{Name: "vps", Roles: []trust.Role{trust.RoleExitNode}},
		{Name: "telefon"},
	}}
}

func TestChainPlan(t *testing.T) {
	doc := chainDoc()
	self, _ := doc.DeviceByName("laptop")
	if _, _, err := chainPlan(doc, self, "ev", "vps"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"ev", "ev"}, {"telefon", "vps"}, {"laptop", "vps"}, {"", "vps"}, {"ev", "yok"}} {
		if _, _, err := chainPlan(doc, self, c[0], c[1]); !errors.Is(err, ErrChain) {
			t.Errorf("%v: %v", c, err)
		}
	}
	none := []string{}
	doc.ExitUsers = &none
	if _, _, err := chainPlan(doc, self, "ev", "vps"); !errors.Is(err, ErrChain) {
		t.Fatal("chain allowed without exit permission")
	}
}

func TestChainEncap(t *testing.T) {
	self := netip.MustParseAddr("100.80.0.1")
	target := netip.MustParseAddrPort("203.0.113.7:51820")
	dg := []byte{4, 0, 0, 0, 1, 2, 3}
	pkt, err := encapChain(self, target, dg)
	if err != nil {
		t.Fatal(err)
	}
	in, err := packet.Parse(pkt)
	if err != nil || in.Dst != target.Addr() || in.DstPort != target.Port() || in.SrcPort != chainPort {
		t.Fatalf("%+v %v", in, err)
	}
	reply, _ := packet.BuildUDP4(target.Addr(), self, target.Port(), chainPort, dg)
	got, ok := decapChain(reply, self, target)
	if !ok || string(got) != string(dg) {
		t.Fatal("decap failed")
	}
	other, _ := packet.BuildUDP4(netip.MustParseAddr("198.51.100.1"), self, target.Port(), chainPort, dg)
	if _, ok := decapChain(other, self, target); ok {
		t.Fatal("packet from another host accepted")
	}
	if _, err := encapChain(self, netip.MustParseAddrPort("[2001:db8::1]:51820"), dg); err == nil {
		t.Fatal("IPv6 target accepted")
	}
}

func TestOpsecSettingsFile(t *testing.T) {
	dir := t.TempDir()
	var s OpsecSettings
	s.Obfs.Mode = "on"
	s.Obfs.JitterMS = 20
	s.Obfs.TLS = &obfs.ClientTLS{ServerName: "cdn.example.test"}
	s.ExitChainEntry = "ev"
	s.DecoyPorts = []uint16{22, 3389}
	s.QuarantineOnScan = true
	if err := SaveOpsecSettings(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOpsecSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	var g G3Config
	if err := got.Apply(&g); err != nil {
		t.Fatal(err)
	}
	if g.Obfs.Mode != obfs.ModeOn || g.Obfs.Jitter.Max != 20*time.Millisecond || g.Obfs.TLS == nil || g.ExitChain.Entry != "ev" ||
		len(g.Decoys.DecoyPorts) != 2 || !g.Decoys.QuarantineOnScan {
		t.Fatalf("%+v", g)
	}
	// The caller's explicit choice wins over the file.
	explicit := G3Config{Obfs: ObfsConfig{Mode: obfs.ModeAuto}}
	if err := got.Apply(&explicit); err != nil || explicit.Obfs.Mode != obfs.ModeAuto {
		t.Fatalf("%v %v", explicit.Obfs.Mode, err)
	}
	bad := OpsecSettings{}
	bad.Obfs.JitterMS = 5
	if SaveOpsecSettings(dir, bad) == nil {
		t.Fatal("jitter without disguise saved")
	}
	bad = OpsecSettings{DecoyPorts: []uint16{0}}
	if SaveOpsecSettings(dir, bad) == nil {
		t.Fatal("decoy port 0 saved")
	}
	if err := securefileWrite(dir, `{"obfs":{},"unknown":1}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOpsecSettings(dir); err == nil {
		t.Fatal("unknown key accepted")
	}
	if s, err := LoadOpsecSettings(t.TempDir()); err != nil || s.Obfs.Mode != "" {
		t.Fatal("missing file")
	}
}

func securefileWrite(dir, content string) error {
	return os.WriteFile(filepath.Join(dir, OpsecFileName), []byte(content), 0o600)
}
