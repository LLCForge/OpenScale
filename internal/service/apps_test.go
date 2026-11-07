package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/speedtest"
	"github.com/openscale/openscale/internal/trust"
)

// appsFakeEngine serves a fixed document as one of its devices.
type appsFakeEngine struct {
	mu   sync.Mutex
	doc  *trust.Document
	self string
}

func (e *appsFakeEngine) Document() *trust.Document {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.doc
}

func (e *appsFakeEngine) Self() (trust.Device, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.doc.DeviceByName(e.self)
	if !ok {
		return trust.Device{}, errors.New("not a member")
	}
	return d, nil
}

func (e *appsFakeEngine) setRules(version uint64, rules []trust.Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := *e.doc
	next.Version = version
	next.Rules = rules
	e.doc = &next
}

func appsDoc(rules ...trust.Rule) *trust.Document {
	dev := func(name, v4 string) trust.Device {
		return trust.Device{Name: name, IPv4: netip.MustParseAddr(v4), IPv6: netip.MustParseAddr("fd12:3456:789a::" + v4[len("100.80.0."):])}
	}
	return &trust.Document{
		Version:    1,
		DNSDomain:  "openscale.internal",
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd12:3456:789a::/48"),
		Devices:    []trust.Device{dev("laptop", "100.80.0.2"), dev("nas", "100.80.0.3"), dev("masaustu", "100.80.0.4")},
		Rules:      rules,
	}
}

var appsLoopback = netip.MustParseAddr("127.0.0.1")

// testApps runs Apps as device self on appsLoopback with any port; every
// connection appears to come from device peer.
func testApps(t *testing.T, self, peer string, interactive bool, rules ...trust.Rule) (*Apps, *appsFakeEngine) {
	t.Helper()
	doc := appsDoc(rules...)
	eng := &appsFakeEngine{doc: doc, self: self}
	peerDev, _ := doc.DeviceByName(peer)
	a := NewApps(AppsConfig{
		Dir:         t.TempDir(),
		Engine:      func() AppEngine { return eng },
		Interactive: interactive,
		Interval:    20 * time.Millisecond,
	})
	a.listenHost, a.anyPort = appsLoopback, true
	a.mapPeer = func(netip.Addr) netip.Addr { return peerDev.IPv4 }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return a, eng
}

func appsWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func boundAddr(t *testing.T, a *Apps, svc trust.RuleService) netip.AddrPort {
	t.Helper()
	var addr netip.AddrPort
	appsWait(t, string(svc)+" to listen", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		r := a.runners[svc]
		if r != nil && r.running {
			addr = r.bound
			return true
		}
		return false
	})
	return addr
}

func TestAppsListenOnlyWithRules(t *testing.T) {
	a, eng := testApps(t, "nas", "laptop", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSpeedtest},
	)
	boundAddr(t, a, trust.ServiceSpeedtest)
	st := a.AppsStatus()
	if !st.Speedtest.Running || st.SSH.Hosted || st.Files.Hosted || st.Wake.Hosted {
		t.Fatalf("status: %+v", st)
	}
	// Removing the rule stops the server.
	eng.setRules(2, nil)
	appsWait(t, "speedtest to stop", func() bool { return !a.AppsStatus().Speedtest.Running })
	// A disabled rule does not start it either.
	eng.setRules(3, []trust.Rule{{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSpeedtest, Disabled: true}})
	time.Sleep(100 * time.Millisecond)
	if a.AppsStatus().Speedtest.Running {
		t.Fatal("disabled rule must not start the server")
	}
}

func TestAppsSpeedtestAuthorization(t *testing.T) {
	a, _ := testApps(t, "nas", "laptop", false,
		trust.Rule{From: []string{"masaustu"}, To: []string{"nas"}, Service: trust.ServiceSpeedtest},
	)
	addr := boundAddr(t, a, trust.ServiceSpeedtest)
	// The connection maps to laptop, which no rule allows.
	if _, err := speedtest.Run(context.Background(), addr, speedtest.Download, 200*time.Millisecond); !errors.Is(err, speedtest.ErrDenied) {
		t.Fatalf("laptop must be denied: %v", err)
	}
	a.mapPeer = func(netip.Addr) netip.Addr { return netip.MustParseAddr("100.80.0.4") }
	res, err := speedtest.Run(context.Background(), addr, speedtest.Download, 200*time.Millisecond)
	if err != nil || res.Bytes == 0 {
		t.Fatalf("masaustu: %v %+v", err, res)
	}
}

func TestAppsSSHAuthorize(t *testing.T) {
	user := "ali"
	if runtime.GOOS == "windows" {
		user = trust.SSHWindowsUser
	}
	a, eng := testApps(t, "nas", "laptop", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSSH, Users: []string{user}, AllowForward: true},
	)
	laptop := netip.MustParseAddr("100.80.0.2")
	if ok, _ := a.authorizeSSH(laptop, user); !ok {
		t.Fatal("rule user must be allowed")
	}
	if ok, _ := a.authorizeSSH(laptop, "root"); ok {
		t.Fatal("root needs allow_root")
	}
	if runtime.GOOS == "windows" {
		if ok, _ := a.authorizeSSH(laptop, "SYSTEM"); !ok {
			t.Fatal("SYSTEM maps to system")
		}
		if ok, _ := a.authorizeSSH(laptop, "ali"); ok {
			t.Fatal("Windows accepts only system")
		}
	}
	// Forwards may not reach other devices of the network.
	if ok, _ := a.authorizeForward(laptop, user, netip.MustParseAddrPort("127.0.0.1:80")); !ok {
		t.Fatal("local forward must be allowed")
	}
	if ok, _ := a.authorizeForward(laptop, user, netip.MustParseAddrPort("100.80.0.4:3389")); ok {
		t.Fatal("forward to another device must be refused")
	}
	// Without the rule nothing is allowed.
	eng.setRules(2, nil)
	if ok, _ := a.authorizeSSH(laptop, user); ok {
		t.Fatal("removed rule must deny")
	}
	if ok, _ := a.authorizeSSH(netip.MustParseAddr("100.80.9.9"), user); ok {
		t.Fatal("unknown source must be denied")
	}
}

func TestAppsSSHServerStarts(t *testing.T) {
	user := "ali"
	if runtime.GOOS == "windows" {
		user = trust.SSHWindowsUser
	}
	a, _ := testApps(t, "nas", "laptop", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSSH, Users: []string{user}},
	)
	boundAddr(t, a, trust.ServiceSSH)
	st := a.AppsStatus()
	if st.SSHFingerprint == "" || HostKeyFingerprint(a.cfg.Dir) != st.SSHFingerprint {
		t.Fatalf("fingerprint: %+v", st)
	}
}

func TestAppsFileOffers(t *testing.T) {
	a, _ := testApps(t, "nas", "laptop", true,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceFiles},
	)
	addr := boundAddr(t, a, trust.ServiceFiles)
	src := filepath.Join(t.TempDir(), "rapor.txt")
	if err := os.WriteFile(src, []byte("merhaba dünya"), 0o600); err != nil {
		t.Fatal(err)
	}
	send := func() chan error {
		errc := make(chan error, 1)
		go func() {
			_, err := filesend.Send(context.Background(), addr, src, nil)
			errc <- err
		}()
		return errc
	}

	// Rejected by the owner.
	errc := send()
	appsWait(t, "offer", func() bool { return len(a.Inbox().Pending) == 1 })
	if err := a.DecideOffer(a.Inbox().Pending[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, filesend.ErrRejected) {
		t.Fatalf("rejected offer: %v", err)
	}
	// Accepted by the owner.
	errc = send()
	appsWait(t, "offer", func() bool { return len(a.Inbox().Pending) == 1 })
	if a.AppsStatus().PendingOffers != 1 {
		t.Fatal("status must count the offer")
	}
	if err := a.DecideOffer(a.Inbox().Pending[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("accepted offer: %v", err)
	}
	// The receiver records the sender after its final reply.
	appsWait(t, "inbox entry", func() bool { f := a.Inbox().Files; return len(f) == 1 && f[0].From != "" })
	inbox := a.Inbox()
	if len(inbox.Files) != 1 || inbox.Files[0].Name != "rapor.txt" || inbox.Files[0].From != "laptop" {
		t.Fatalf("inbox: %+v", inbox)
	}
	// Auto-accept needs no decision.
	if err := a.SetAutoAccept("laptop", true); err != nil {
		t.Fatal(err)
	}
	if err := <-send(); err != nil {
		t.Fatalf("auto-accepted: %v", err)
	}
	appsWait(t, "second file", func() bool { return len(a.Inbox().Files) == 2 })
	f, info, err := a.OpenInboxFile("rapor.txt")
	if err != nil || info.Size != int64(len("merhaba dünya")) {
		t.Fatalf("open: %v %+v", err, info)
	}
	_ = f.Close()
	for _, bad := range []string{"../app.token", ".openscale-partial", "", `..\x`} {
		if _, _, err := a.OpenInboxFile(bad); err == nil {
			t.Errorf("OpenInboxFile(%q) must fail", bad)
		}
	}
	if err := a.DeleteInboxFile("rapor.txt"); err != nil {
		t.Fatal(err)
	}
	if len(a.Inbox().Files) != 1 {
		t.Fatal("delete")
	}
}

func TestAppsFileOfferWithoutRule(t *testing.T) {
	a, _ := testApps(t, "nas", "masaustu", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceFiles},
	)
	if err := SetAutoAccept(a.cfg.Dir, "masaustu", true); err != nil {
		t.Fatal(err)
	}
	addr := boundAddr(t, a, trust.ServiceFiles)
	src := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(src, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	// Auto-accept never overrides the rules.
	if _, err := filesend.Send(context.Background(), addr, src, nil); !errors.Is(err, filesend.ErrRejected) {
		t.Fatalf("send without rule: %v", err)
	}
}

func TestAppsWakeRelay(t *testing.T) {
	a, _ := testApps(t, "nas", "laptop", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Service: trust.ServiceWake, Via: []string{"nas"}},
	)
	var (
		mu   sync.Mutex
		macs []string
	)
	a.wakeSend = func(_ context.Context, _ *trust.Document, mac net.HardwareAddr) (int, error) {
		mu.Lock()
		macs = append(macs, mac.String())
		mu.Unlock()
		return 1, nil
	}
	addr := boundAddr(t, a, trust.ServiceWake)
	ctx := context.Background()
	if n, err := SendWakeRequest(ctx, addr, "masaustu", "AA-BB-CC-DD-EE-02"); err != nil || n != 1 {
		t.Fatalf("wake: %d %v", n, err)
	}
	// Too soon from the same source.
	if _, err := SendWakeRequest(ctx, addr, "masaustu", "aa:bb:cc:dd:ee:02"); err == nil {
		t.Fatal("rate limit must refuse")
	}
	// Another target is not covered by the rule.
	if _, err := SendWakeRequest(ctx, addr, "laptop", "aa:bb:cc:dd:ee:03"); !errors.Is(err, ErrWakeDenied) {
		t.Fatalf("other target: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(macs) != 1 || macs[0] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("packets: %v", macs)
	}
}

func TestWakeMACs(t *testing.T) {
	a, _ := testApps(t, "laptop", "nas", false)
	if err := a.SetWakeMAC("masaustu", "aa-bb-cc-dd-ee-04"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetWakeMAC("masaustu", "ff:ff:ff:ff:ff:ff"); err == nil {
		t.Fatal("broadcast MAC must be refused")
	}
	macs, err := LoadWakeMACs(a.cfg.Dir)
	if err != nil || WakeMACFor(macs, "masaustu") != "aa:bb:cc:dd:ee:04" {
		t.Fatalf("macs: %v %v", macs, err)
	}
	v, err := a.RemoteDevice("masaustu")
	if err != nil || v.WakeMAC != "aa:bb:cc:dd:ee:04" || len(v.WakeRelays) != 0 {
		t.Fatalf("remote view: %+v %v", v, err)
	}
	if _, err := a.Wake(context.Background(), "masaustu"); err == nil {
		t.Fatal("wake without a rule must fail")
	}
}
