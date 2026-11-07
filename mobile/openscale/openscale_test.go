package openscale

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/trust"
)

var (
	testPass = []byte("mobil test parolası 7")
	testOpts = admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
)

// enroll turns device key file bytes into a verified request.
func enroll(t *testing.T, secrets []byte, host string) *trust.EnrollmentRequest {
	t.Helper()
	out, err := EnrollmentRequest(secrets, host)
	if err != nil {
		t.Fatal(err)
	}
	line, fp, ok := strings.Cut(out, "\n")
	if !ok || fp == "" {
		t.Fatalf("enrollment output %q lacks the fingerprint line", out)
	}
	env, err := trust.DecodeEnrollment(line)
	if err != nil {
		t.Fatal(err)
	}
	req, err := trust.OpenEnrollmentRequest(env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if req.Fingerprint() != fp {
		t.Fatal("fingerprint differs from the request's")
	}
	return req
}

type testNet struct {
	dir     string
	secrets []byte
	net     *admin.Network
}

// newJoinedPhone builds a network with this phone, an exit node "home"
// and a plain device "laptop", and joins the phone's state directory.
func newJoinedPhone(t *testing.T) testNet {
	t.Helper()
	n, err := admin.Init(filepath.Join(t.TempDir(), "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, testPass, testOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	phone, err := GenerateDeviceSecrets()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := GenerateDeviceSecrets()
	laptop, _ := GenerateDeviceSecrets()
	coord, _ := GenerateDeviceSecrets()
	cs, err := parseSecrets(coord)
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := cs.PublicKeys()
	reqs := map[string]*trust.EnrollmentRequest{
		"telefon": enroll(t, phone, "telefon"),
		"home":    enroll(t, home, "home"),
		"laptop":  enroll(t, laptop, "laptop"),
	}
	now := time.Now()
	if _, err := n.Apply(testPass, now, func(doc *trust.Document) error {
		if err := doc.SetCoordinator("192.0.2.1:41820", coordWG); err != nil {
			return err
		}
		for _, name := range []string{"telefon", "home", "laptop"} {
			var roles []trust.Role
			if name == "home" {
				roles = []trust.Role{trust.RoleExitNode}
			}
			if _, err := doc.AddDevice(reqs[name], name, roles, now, 30*24*time.Hour); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "openscale")
	if IsJoined(dir) {
		t.Fatal("joined before Join")
	}
	if _, err := Join(dir, bundle, "yanlis-parmak-izi"); err == nil {
		t.Fatal("wrong root fingerprint accepted")
	}
	sum, err := Join(dir, bundle, n.RootFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	var js joinSummary
	if err := json.Unmarshal([]byte(sum), &js); err != nil || js.NetworkID == "" || js.Domain != trust.DefaultDNSDomain {
		t.Fatalf("summary %q: %v", sum, err)
	}
	if !IsJoined(dir) {
		t.Fatal("not joined after Join")
	}
	return testNet{dir: dir, secrets: phone, net: n}
}

func TestPlanSplitAndFullTunnel(t *testing.T) {
	tn := newJoinedPhone(t)
	out, err := Plan(tn.dir, tn.secrets, "")
	if err != nil {
		t.Fatal(err)
	}
	var p vpnPlan
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if p.FullTunnel || p.ExitNode != "" || len(p.DNSServers) != 0 || p.MTU != node.DefaultMTU {
		t.Fatalf("split plan = %+v", p)
	}
	if len(p.Addresses) != 2 || !strings.HasSuffix(p.Addresses[0], "/16") || !strings.HasPrefix(p.Routes[0], "100.80.0.0/16") || len(p.Routes) != 2 {
		t.Fatalf("split plan = %+v", p)
	}
	for _, r := range p.Routes {
		if r == "0.0.0.0/0" || r == "::/0" {
			t.Fatal("default route without an exit node")
		}
	}

	out, err = Plan(tn.dir, tn.secrets, `{"exit_node":"home","mtu":1280}`)
	if err != nil {
		t.Fatal(err)
	}
	p = vpnPlan{}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatal(err)
	}
	if !p.FullTunnel || p.ExitNode != "home" || !reflect.DeepEqual(p.Routes[2:], []string{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("full plan = %+v", p)
	}
	if !reflect.DeepEqual(p.DNSServers, []string{"100.80.255.254"}) || !reflect.DeepEqual(p.SearchDomains, []string{trust.DefaultDNSDomain}) {
		t.Fatalf("full plan DNS = %+v", p)
	}

	for _, bad := range []string{`{"exit_node":"laptop"}`, `{"exit_node":"telefon"}`, `{"exit_node":"yok"}`, `{"exitnode":"home"}`, `{"mtu":100}`, `{"force_relay":true,"mtu":1400}`, "{"} {
		if _, err := Plan(tn.dir, tn.secrets, bad); err == nil {
			t.Errorf("options %s accepted", bad)
		}
	}
	other, _ := GenerateDeviceSecrets()
	if _, err := Plan(tn.dir, other, ""); err == nil {
		t.Fatal("plan for a device not in the document")
	}
	if _, err := Plan("relative", tn.secrets, ""); err == nil {
		t.Fatal("relative state dir accepted")
	}
	if _, err := Plan(tn.dir, nil, ""); err == nil {
		t.Fatal("missing secrets accepted")
	}
}

func TestPlanForwardsDNSWithNetworkResolvers(t *testing.T) {
	tn := newJoinedPhone(t)
	doc, err := tn.net.Document()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := doc.DeviceByName("home")
	self, _ := doc.DeviceByName("telefon")
	doc.DNS = &trust.DNSSettings{Nameservers: []netip.Addr{home.IPv4}}
	p, err := planFor(doc, self, startOptions{MTU: node.DefaultMTU}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.FullTunnel || len(p.DNSServers) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	expired := home
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	if _, err := exitDevice(&trust.Document{Devices: []trust.Device{expired}}, self, "home", time.Now()); err == nil {
		t.Fatal("expired exit node accepted")
	}
}

func TestOptionsAndProfile(t *testing.T) {
	o, err := parseOptions("")
	if err != nil || !o.batterySaver() || o.MTU != node.DefaultMTU {
		t.Fatalf("defaults = %+v %v", o, err)
	}
	o, _ = parseOptions(`{"battery_saver":false}`)
	if o.batterySaver() {
		t.Fatal("battery saver not turned off")
	}
	if _, err := parseOptions(strings.Repeat(" ", maxOptions+1)); err == nil {
		t.Fatal("huge options accepted")
	}
	var cfg node.Config
	profileFor(true).apply(&cfg)
	if !cfg.LazyPeers || cfg.Keepalive != node.MaxKeepalive || !cfg.AdaptiveKeepalive || cfg.PollInterval != batteryPollInterval {
		t.Fatalf("battery profile = %+v", cfg)
	}
	if err := node.ValidateKeepalive(cfg.Keepalive); err != nil {
		t.Fatalf("battery keepalive rejected by the engine: %v", err)
	}
	cfg = node.Config{}
	profileFor(false).apply(&cfg)
	if cfg.LazyPeers || cfg.Keepalive != 0 || !cfg.AdaptiveKeepalive || cfg.PollInterval != 0 {
		t.Fatalf("normal profile = %+v", cfg)
	}
}

func TestGenerateAndEnrollment(t *testing.T) {
	a, err := GenerateDeviceSecrets()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateDeviceSecrets()
	if string(a) == string(b) {
		t.Fatal("two generated keys are equal")
	}
	if _, err := EnrollmentRequest([]byte("not json"), "x"); err == nil {
		t.Fatal("garbage secrets accepted")
	}
	if _, err := EnrollmentRequest(a, strings.Repeat("a", maxHostname+1)); err == nil {
		t.Fatal("long hostname accepted")
	}
	// parseSecrets must not wipe the caller's bytes.
	before := string(a)
	s, err := parseSecrets(a)
	if err != nil {
		t.Fatal(err)
	}
	wipeSecrets(s)
	if string(a) != before {
		t.Fatal("caller's key bytes changed")
	}
	for _, x := range s.WireGuardPrivate {
		if x != 0 {
			t.Fatal("parsed key not wiped")
		}
	}
}

// fakePlatform records callbacks.
type fakePlatform struct {
	mu        sync.Mutex
	protected []int
	refuse    bool
	logs      []int
	statuses  []string
}

func (p *fakePlatform) Protect(fd int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.protected = append(p.protected, fd)
	return !p.refuse
}
func (p *fakePlatform) Log(level int, _ string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logs = append(p.logs, level)
}
func (p *fakePlatform) StatusChanged(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses = append(p.statuses, s)
}

// peekBind is a conn.Bind whose sockets have fixed descriptors.
type peekBind struct {
	conn.Bind
	closed bool
	v6err  error
}

func (b *peekBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 4242, nil }
func (b *peekBind) Close() error                                    { b.closed = true; return nil }
func (b *peekBind) PeekLookAtSocketFd4() (int, error)               { return 11, nil }
func (b *peekBind) PeekLookAtSocketFd6() (int, error)               { return 12, b.v6err }

func TestProtectBind(t *testing.T) {
	p := &fakePlatform{}
	b := &protectBind{Bind: &peekBind{v6err: errors.New("no ipv6")}, protect: p.Protect}
	if _, port, err := b.Open(0); err != nil || port != 4242 {
		t.Fatalf("open = %d %v", port, err)
	}
	if !reflect.DeepEqual(p.protected, []int{11}) {
		t.Fatalf("protected = %v", p.protected)
	}
	p2 := &fakePlatform{refuse: true}
	inner := &peekBind{}
	b2 := &protectBind{Bind: inner, protect: p2.Protect}
	if _, _, err := b2.Open(0); !errors.Is(err, errProtect) || !inner.closed {
		t.Fatalf("refused protect: err=%v closed=%v", err, inner.closed)
	}
}

func TestPlatformWriterLevels(t *testing.T) {
	p := &fakePlatform{}
	w := platformWriter{p}
	for _, line := range []string{`{"level":"DEBUG"}`, `{"level":"INFO"}`, `{"level":"WARN"}`, `{"level":"ERROR"}`, `not json`} {
		if n, err := w.Write([]byte(line + "\n")); err != nil || n != len(line)+1 {
			t.Fatal(n, err)
		}
	}
	if !reflect.DeepEqual(p.logs, []int{LogDebug, LogInfo, LogWarn, LogError, LogInfo}) {
		t.Fatalf("levels = %v", p.logs)
	}
}

func TestTunnelStartRefusals(t *testing.T) {
	tn := newJoinedPhone(t)
	p := &fakePlatform{}
	if _, err := NewTunnel(tn.dir, nil); err == nil {
		t.Fatal("nil platform accepted")
	}
	if _, err := NewTunnel("rel", p); err == nil {
		t.Fatal("relative dir accepted")
	}
	tun, err := NewTunnel(tn.dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := tun.Start(-1, tn.secrets, ""); err == nil {
		t.Fatal("negative descriptor accepted")
	}
	if err := tun.Start(1<<20, tn.secrets, `{"exit_node":"laptop"}`); err == nil {
		t.Fatal("non-exit node accepted")
	}
	other, _ := GenerateDeviceSecrets()
	if err := tun.Start(1<<20, other, ""); err == nil {
		t.Fatal("foreign device accepted")
	}
	if tun.Running() {
		t.Fatal("running after refusals")
	}
	tun.Stop()
	tun.NetworkChanged()
	var st tunnelStatus
	if err := json.Unmarshal([]byte(tun.Status()), &st); err != nil || st.Running {
		t.Fatalf("status = %+v %v", st, err)
	}
	if Version() == "" {
		t.Fatal("no version")
	}
}
