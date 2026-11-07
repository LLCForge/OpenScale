package service

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/dnsguard"
	"github.com/openscale/openscale/internal/trust"
)

// fakeDNSApplier records what the loop asks for; nothing reaches the host.
type fakeDNSApplier struct {
	mu    sync.Mutex
	calls []string
	last  []dnsguard.Rule
}

func (f *fakeDNSApplier) Apply(rules []dnsguard.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "apply")
	f.last = slices.Clone(rules)
	return nil
}

func (f *fakeDNSApplier) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "remove")
	return nil
}

func (f *fakeDNSApplier) snapshot() ([]string, []dnsguard.Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls), slices.Clone(f.last)
}

type fakeNamedDev string

func (d fakeNamedDev) Name() (string, error) { return string(d), nil }

func waitCalls(t *testing.T, f *fakeDNSApplier, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if calls, _ := f.snapshot(); strings.Join(calls, " ") == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	calls, _ := f.snapshot()
	t.Fatalf("çağrılar %q, beklenen %q", strings.Join(calls, " "), want)
}

func kickDNSEnforce(r *Runtime) {
	r.dnsEnf.mu.Lock()
	k := r.dnsEnf.kick
	r.dnsEnf.mu.Unlock()
	select {
	case k <- struct{}{}:
	default:
	}
}

type dnsEnforceWorld struct {
	mu   sync.Mutex
	up   bool
	exit string
}

func newDNSEnforceRuntime(t *testing.T, f *fakeDNSApplier, w *dnsEnforceWorld) (*Runtime, *trust.Document) {
	t.Helper()
	doc := &trust.Document{
		IPv4Prefix: netip.MustParsePrefix("100.64.0.0/24"),
		Devices:    []trust.Device{{Name: "cikis", IPv4: netip.MustParseAddr("100.64.0.9")}},
	}
	r := &Runtime{
		cfg:    Config{DataDir: t.TempDir(), Hooks: Hooks{DNSEnforce: f}, Now: time.Now},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r.dnsEnf.ifaceUp = func(string) bool { w.mu.Lock(); defer w.mu.Unlock(); return w.up }
	r.dnsEnf.exitOf = func() (string, *trust.Document) { w.mu.Lock(); defer w.mu.Unlock(); return w.exit, doc }
	return r, doc
}

func TestDNSEnforcePrefs(t *testing.T) {
	keys := PrefKeys()
	for _, k := range []string{"dns-enforce", "dns-enforce-doh-list"} {
		if !slices.Contains(keys, k) {
			t.Fatalf("%s ayarı listede yok", k)
		}
	}
	var topt tunnelOptions
	if ok, err := applyTunnelPref(&topt, "dns-enforce", "true"); !ok || err != nil || !topt.DNSEnforce.On {
		t.Fatalf("dns-enforce: %v %v %+v", ok, err, topt.DNSEnforce)
	}
	if _, err := applyTunnelPref(&topt, "dns-enforce", "evet"); err == nil {
		t.Fatal("geçersiz değer kabul edildi")
	}
	// The exit node resolver keys still reach their handler.
	if ok, err := applyTunnelPref(&topt, "exit-dns-serve-stale", "true"); !ok || err != nil || !topt.ExitDNSGuard.ServeStale {
		t.Fatalf("P05 anahtarı kayboldu: %v %v", ok, err)
	}
	dir := t.TempDir()
	if _, err := applyTunnelPref(&topt, "dns-enforce-doh-list", filepath.Join(dir, "yok.txt")); err == nil {
		t.Fatal("olmayan dosya kabul edildi")
	}
	bad := filepath.Join(dir, "kotu.txt")
	if err := os.WriteFile(bad, []byte("0.0.0.0/1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := applyTunnelPref(&topt, "dns-enforce-doh-list", bad); err == nil {
		t.Fatal("çok geniş aralık kabul edildi")
	}
	good := filepath.Join(dir, "doh.txt")
	if err := os.WriteFile(good, []byte("# sahibin listesi\n192.0.2.53\ndoh.example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := applyTunnelPref(&topt, "dns-enforce-doh-list", good); err != nil || topt.DNSEnforce.DoHList != good {
		t.Fatalf("geçerli liste: %v", err)
	}
	// Older settings files without the field keep their behaviour.
	var old tunnelOptions
	if old.DNSEnforce.On || !old.wave2Options.equal(wave2Options{}) {
		t.Fatal("sıfır değer kapalı olmalı")
	}
}

func TestDNSEnforceFollowsTunnelAndExit(t *testing.T) {
	f := &fakeDNSApplier{}
	w := &dnsEnforceWorld{up: true, exit: "cikis"}
	r, doc := newDNSEnforceRuntime(t, f, w)
	doh := filepath.Join(r.cfg.DataDir, "doh.txt")
	if err := os.WriteFile(doh, []byte("192.0.2.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.updateSettings(func(st *settings) (bool, error) {
		topt := st.tunnel()
		topt.DNSEnforce = dnsEnforceOptions{On: true, DoHList: doh}
		st.Tunnel = &topt
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	stop := r.startDNSEnforce(context.Background(), fakeNamedDev("OpenScale"), doc)
	// Stale rules of an earlier run go first, then the rule set.
	waitCalls(t, f, "remove apply")
	_, rules := f.snapshot()
	if a, ok := dnsguard.Evaluate(rules, "OpenScale", dnsguard.ProtoUDP, netip.MustParseAddr("100.64.0.9"), 53); !ok || a != dnsguard.ActionAllow {
		t.Fatal("çıkış düğümü çözücüsüne izin yok")
	}
	if a, ok := dnsguard.Evaluate(rules, "OpenScale", dnsguard.ProtoUDP, doc.DNSResolverIPv4(), 53); !ok || a != dnsguard.ActionAllow {
		t.Fatal("MagicDNS çözücüsüne izin yok")
	}
	if a, ok := dnsguard.Evaluate(rules, "Wi-Fi", dnsguard.ProtoUDP, netip.MustParseAddr("192.168.1.1"), 53); !ok || a != dnsguard.ActionDrop {
		t.Fatal("tünel dışı DNS düşürülmüyor")
	}
	if a, ok := dnsguard.Evaluate(rules, "OpenScale", dnsguard.ProtoTCP, netip.MustParseAddr("192.0.2.53"), 443); !ok || a != dnsguard.ActionDrop {
		t.Fatal("listedeki DoH uç noktası düşürülmüyor")
	}
	waitActive(t, r, true)
	if st, err := r.DNSEnforceStatus(); err != nil || !st.Active || !st.On || st.DoHRanges != 1 {
		t.Fatalf("durum: %+v %v", st, err)
	}

	// The tunnel interface goes down: the rules are removed.
	w.mu.Lock()
	w.up = false
	w.mu.Unlock()
	kickDNSEnforce(r)
	waitCalls(t, f, "remove apply remove")
	waitActive(t, r, false)
	if st, _ := r.DNSEnforceStatus(); st.Active || st.Reason == "" {
		t.Fatalf("tünel yokken etkin görünüyor: %+v", st)
	}
	// Up again but without an exit node: still nothing is applied.
	w.mu.Lock()
	w.up, w.exit = true, ""
	w.mu.Unlock()
	kickDNSEnforce(r)
	time.Sleep(100 * time.Millisecond)
	waitCalls(t, f, "remove apply remove")
	// The exit node is back: applied again; the end of the run removes.
	w.mu.Lock()
	w.exit = "cikis"
	w.mu.Unlock()
	kickDNSEnforce(r)
	waitCalls(t, f, "remove apply remove apply")
	waitActive(t, r, true)
	stop()
	waitCalls(t, f, "remove apply remove apply remove")
	if st, _ := r.DNSEnforceStatus(); st.Active {
		t.Fatal("tünel bitti ama etkin görünüyor")
	}
}

func TestDNSEnforceNeverWithoutTunnel(t *testing.T) {
	f := &fakeDNSApplier{}
	w := &dnsEnforceWorld{up: false, exit: "cikis"}
	r, doc := newDNSEnforceRuntime(t, f, w)
	if err := r.updateSettings(func(st *settings) (bool, error) {
		topt := st.tunnel()
		topt.DNSEnforce.On = true
		st.Tunnel = &topt
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	stop := r.startDNSEnforce(context.Background(), fakeNamedDev("OpenScale"), doc)
	kickDNSEnforce(r)
	time.Sleep(150 * time.Millisecond)
	stop()
	// Only the cleanup at the start; Sync removes nothing it never installed.
	waitCalls(t, f, "remove")
}

func TestDNSEnforceOffAndUnsupported(t *testing.T) {
	f := &fakeDNSApplier{}
	w := &dnsEnforceWorld{up: true, exit: "cikis"}
	r, doc := newDNSEnforceRuntime(t, f, w)
	stop := r.startDNSEnforce(context.Background(), fakeNamedDev("OpenScale"), doc)
	kickDNSEnforce(r)
	time.Sleep(100 * time.Millisecond)
	stop()
	waitCalls(t, f, "remove") // the switch is off by default
	if st, err := r.DNSEnforceStatus(); err != nil || st.On || !st.Supported {
		t.Fatalf("varsayılan durum: %+v %v", st, err)
	}

	none := &Runtime{cfg: Config{DataDir: t.TempDir(), Now: time.Now}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	none.startDNSEnforce(context.Background(), fakeNamedDev("OpenScale"), doc)()
	if _, err := none.SetDNSEnforce(true); err == nil {
		t.Fatal("uygulayıcı yokken açıldı")
	}
	if st, err := none.DNSEnforceStatus(); err != nil || st.Supported {
		t.Fatalf("desteklenmeyen sistem: %+v %v", st, err)
	}
}

func waitActive(t *testing.T, r *Runtime, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := r.DNSEnforceStatus(); err == nil && st.Active == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("etkinlik %v olmadı", want)
}
