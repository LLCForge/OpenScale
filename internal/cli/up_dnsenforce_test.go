package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/dnsguard"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

// fakeUpDNSApplier records the calls; nothing reaches the host.
type fakeUpDNSApplier struct {
	mu       sync.Mutex
	calls    []string
	last     []dnsguard.Rule
	applyErr error
}

func (f *fakeUpDNSApplier) Apply(rules []dnsguard.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "apply")
	f.last = slices.Clone(rules)
	return f.applyErr
}

func (f *fakeUpDNSApplier) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "remove")
	return nil
}

func (f *fakeUpDNSApplier) got() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, " ")
}

func (f *fakeUpDNSApplier) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func upDNSTestDoc() *trust.Document {
	return &trust.Document{
		IPv4Prefix: netip.MustParsePrefix("100.64.0.0/24"),
		Devices:    []trust.Device{{Name: "cikis", IPv4: netip.MustParseAddr("100.64.0.9")}},
	}
}

func newUpDNSEnforcerForTest(f *fakeUpDNSApplier, up *bool, exit *string) (*upDNSEnforcer, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	doc := upDNSTestDoc()
	return &upDNSEnforcer{
		applier:  f,
		enf:      &dnsguard.Enforcer{Applier: f},
		iface:    "OpenScale",
		tunnelUp: func(string) bool { return *up },
		exitOf:   func() (string, *trust.Document) { return *exit, doc },
		stdout:   &stdout,
		stderr:   &stderr,
	}, &stdout, &stderr
}

// The rules hold only while the tunnel is up and an exit node is in use.
func TestUpDNSEnforceFollowsTunnelAndExit(t *testing.T) {
	f := &fakeUpDNSApplier{}
	up, exit := false, ""
	u, stdout, _ := newUpDNSEnforcerForTest(f, &up, &exit)

	u.tick()
	up = true
	u.tick()
	if f.got() != "" {
		t.Fatalf("koşullar yokken çağrı: %q", f.got())
	}
	exit = "cikis"
	u.tick()
	u.tick()
	if f.got() != "apply" {
		t.Fatalf("çıkış düğümüyle bir kez uygulanmalı: %q", f.got())
	}
	exit = ""
	u.tick()
	if f.got() != "apply remove" {
		t.Fatalf("çıkış düğümü kapanınca kaldırılmalı: %q", f.got())
	}
	exit = "cikis"
	u.tick()
	up = false
	u.tick()
	if f.got() != "apply remove apply remove" {
		t.Fatalf("tünel kapanınca kaldırılmalı: %q", f.got())
	}
	for _, want := range []string{"DNS zorlama açık", "DNS zorlama kaldırıldı", "DNS zorlama bekliyor"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("çıktıda yok: %q\n%s", want, stdout.String())
		}
	}
	// Unknown exit node: nothing to allow, so nothing is blocked.
	up, exit = true, "yok"
	f.reset()
	u.tick()
	if f.got() != "" {
		t.Fatalf("bilinmeyen çıkış düğümüyle çağrı: %q", f.got())
	}
}

// What the installed rules let through: the systemd-resolved stub on
// loopback and the resolvers in the tunnel; DNS to anywhere else is dropped.
func TestUpDNSEnforceKeepsLocalStubAndDropsOutside(t *testing.T) {
	f := &fakeUpDNSApplier{}
	up, exit := true, "cikis"
	u, _, _ := newUpDNSEnforcerForTest(f, &up, &exit)
	u.tick()
	if f.got() != "apply" {
		t.Fatalf("uygulanmadı: %q", f.got())
	}
	for _, c := range []struct {
		iface string
		dst   string
		want  dnsguard.Action
	}{
		{"lo", "127.0.0.53", dnsguard.ActionAllow},
		{"lo", "::1", dnsguard.ActionAllow},
		{"OpenScale", "100.64.0.9", dnsguard.ActionAllow},
		{"eth0", "192.168.1.1", dnsguard.ActionDrop},
		{"eth0", "100.64.0.9", dnsguard.ActionDrop},
	} {
		got, ok := dnsguard.Evaluate(f.last, c.iface, dnsguard.ProtoUDP, netip.MustParseAddr(c.dst), 53)
		if !ok || got != c.want {
			t.Errorf("%s %s:53 = %v %v, beklenen %v", c.iface, c.dst, got, ok, c.want)
		}
	}
	if got, ok := dnsguard.Evaluate(f.last, "eth0", dnsguard.ProtoTCP, netip.MustParseAddr("192.0.2.1"), 853); !ok || got != dnsguard.ActionDrop {
		t.Errorf("tünel dışı DoT geçti: %v %v", got, ok)
	}
}

func upDNSFlags(t *testing.T, args ...string) upDNSEnforceFlags {
	t.Helper()
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := addUpDNSEnforceFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return f
}

func upDNSWorld() (func(string) bool, func() (string, *trust.Document)) {
	doc := upDNSTestDoc()
	return func(string) bool { return true }, func() (string, *trust.Document) { return "cikis", doc }
}

func upDNSEnv() *Env { return &Env{Stdout: io.Discard, Stderr: io.Discard} }

func waitUpDNSCalls(t *testing.T, f *fakeUpDNSApplier, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f.got() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("çağrılar %q, beklenen %q", f.got(), want)
}

// Every run clears what a crashed run left; the switch off installs nothing.
func TestUpDNSEnforceOffOnlyClearsStaleRules(t *testing.T) {
	f := &fakeUpDNSApplier{}
	up, exitOf := upDNSWorld()
	stop := upDNSFlags(t).startWith(context.Background(), upDNSEnv(), f, "OpenScale", true, up, exitOf)
	stop()
	if f.got() != "remove" {
		t.Fatalf("anahtar kapalıyken çağrılar: %q", f.got())
	}
}

// Start clears, the loop installs, stop removes before it returns.
func TestUpDNSEnforceStartStop(t *testing.T) {
	f := &fakeUpDNSApplier{}
	up, exitOf := upDNSWorld()
	stop := upDNSFlags(t, "--dns-enforce").startWith(context.Background(), upDNSEnv(), f, "OpenScale", true, up, exitOf)
	waitUpDNSCalls(t, f, "remove apply")
	stop()
	if f.got() != "remove apply remove" {
		t.Fatalf("durdurunca çağrılar: %q", f.got())
	}
}

// The context of the tunnel run ending removes the rules too.
func TestUpDNSEnforceStopsWithContext(t *testing.T) {
	f := &fakeUpDNSApplier{}
	up, exitOf := upDNSWorld()
	ctx, cancel := context.WithCancel(context.Background())
	stop := upDNSFlags(t, "--dns-enforce").startWith(ctx, upDNSEnv(), f, "OpenScale", true, up, exitOf)
	defer stop()
	waitUpDNSCalls(t, f, "remove apply")
	cancel()
	waitUpDNSCalls(t, f, "remove apply remove")
}

// Without MagicDNS the system's names do not go to the tunnel, so blocking
// outside DNS would only cut the computer off.
func TestUpDNSEnforceNotWithoutMagicDNS(t *testing.T) {
	f := &fakeUpDNSApplier{}
	up, exitOf := upDNSWorld()
	var stderr bytes.Buffer
	env := &Env{Stdout: io.Discard, Stderr: &stderr}
	stop := upDNSFlags(t, "--dns-enforce").startWith(context.Background(), env, f, "OpenScale", false, up, exitOf)
	stop()
	if f.got() != "remove" {
		t.Fatalf("MagicDNS yokken çağrılar: %q", f.got())
	}
	if !strings.Contains(stderr.String(), "MagicDNS") {
		t.Fatalf("uyarı yok: %q", stderr.String())
	}
}

// A failed Apply (macOS without the kill switch anchor) is reported once,
// retried, and what pfctl may have loaded is removed at the end.
func TestUpDNSEnforceFailedApplyIsReportedAndCleaned(t *testing.T) {
	f := &fakeUpDNSApplier{applyErr: errors.New("etkin değil")}
	up, exit := true, "cikis"
	u, stdout, stderr := newUpDNSEnforcerForTest(f, &up, &exit)
	u.tick()
	u.tick()
	if f.got() != "apply apply" {
		t.Fatalf("yeniden denenmedi: %q", f.got())
	}
	if n := strings.Count(stderr.String(), "etkin değil"); n != 1 {
		t.Fatalf("uyarı %d kez: %q", n, stderr.String())
	}
	if strings.Contains(stdout.String(), "DNS zorlama açık") {
		t.Fatalf("başarısız uygulama açık sayıldı: %q", stdout.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.reset()
	u.run(ctx, time.Hour)
	if !strings.HasSuffix(f.got(), "remove") {
		t.Fatalf("çıkışta kaldırılmadı: %q", f.got())
	}
}

// A DoH file that breaks during the run keeps 53 and 853 in force.
func TestUpDNSEnforceDoHList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "doh.txt")
	if err := os.WriteFile(p, []byte("192.0.2.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeUpDNSApplier{}
	up, exit := true, "cikis"
	u, _, stderr := newUpDNSEnforcerForTest(f, &up, &exit)
	u.dohPath = p
	u.tick()
	if got, ok := dnsguard.Evaluate(f.last, "OpenScale", dnsguard.ProtoTCP, netip.MustParseAddr("192.0.2.53"), 443); !ok || got != dnsguard.ActionDrop {
		t.Fatalf("listedeki DoH uç noktası geçti: %v %v", got, ok)
	}
	if err := os.WriteFile(p, []byte("gecersiz satir burada\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u.tick()
	if !strings.Contains(stderr.String(), "DoH listesi") {
		t.Fatalf("bozuk dosya bildirilmedi: %q", stderr.String())
	}
	if !u.enf.Installed() {
		t.Fatal("bozuk DoH dosyası kuralları kaldırdı")
	}
	if got, ok := dnsguard.Evaluate(f.last, "eth0", dnsguard.ProtoUDP, netip.MustParseAddr("192.168.1.1"), 53); !ok || got != dnsguard.ActionDrop {
		t.Fatalf("bozuk dosyayla tünel dışı DNS geçti: %v %v", got, ok)
	}
}

// The flags are read from the command line, the environment and the file
// the service units use, and a bad DoH file is refused while they are read,
// before "up" changes anything on the system.
func TestUpDNSEnforceFlagSources(t *testing.T) {
	for _, name := range []string{"dns-enforce", "dns-enforce-doh-list"} {
		if !slices.Contains(upEnvFlags, name) {
			t.Errorf("%s upEnvFlags içinde değil", name)
		}
	}
	dir := t.TempDir()
	list := filepath.Join(dir, "doh.txt")
	if err := os.WriteFile(list, []byte("192.0.2.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := upDNSFlags(t, "--dns-enforce", "--dns-enforce-doh-list", list); !*f.on || f.list.path != list {
		t.Fatalf("bayraklar: %v %q", *f.on, f.list.path)
	}
	if f := upDNSFlags(t); *f.on || f.list.path != "" {
		t.Fatalf("varsayılan kapalı olmalı: %v %q", *f.on, f.list.path)
	}

	bad := filepath.Join(dir, "bozuk.txt")
	if err := os.WriteFile(bad, []byte("gecersiz satir burada\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{bad, "goreli/yol.txt", filepath.Join(dir, "yok.txt")} {
		fs := flag.NewFlagSet("up", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		addUpDNSEnforceFlags(fs)
		if err := fs.Parse([]string{"--dns-enforce-doh-list", v}); err == nil {
			t.Errorf("%q kabul edildi", v)
		}
	}

	// The service units run "up --config <file>".
	cfg := filepath.Join(dir, "device.json")
	body := `{"dns-enforce": true, "dns-enforce-doh-list": ` + strings.ReplaceAll(`"`+list+`"`, `\`, `\\`) + `}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := addUpDNSEnforceFlags(fs)
	if err := parseFlagsWithEnv(fs, []string{"--config", cfg}, upEnvFlags); err != nil {
		t.Fatal(err)
	}
	if !*f.on || f.list.path != list {
		t.Fatalf("yapılandırma dosyası okunmadı: %v %q", *f.on, f.list.path)
	}
	for _, finding := range checkUpConfig(upDNSEnv(), "up", cfg) {
		if finding.Level == service.FindingError {
			t.Errorf("yapılandırma denetimi reddetti: %s", finding.Message)
		}
	}

	env := map[string]string{EnvName("dns-enforce"): "true"}
	lookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	defer func() { lookupEnv = func(string) (string, bool) { return "", false } }()
	fs = flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f = addUpDNSEnforceFlags(fs)
	if err := parseFlagsWithEnv(fs, nil, upEnvFlags); err != nil {
		t.Fatal(err)
	}
	if !*f.on {
		t.Fatal("ortam değişkeni okunmadı")
	}
}

// cmdUp cannot run in a test (it creates a real interface), so the wiring is
// checked in its source: the flags are declared, the loop starts after the
// engine exists and is stopped when the run ends.
func TestCmdUpWiresDNSEnforce(t *testing.T) {
	data, err := os.ReadFile("net.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	declare := strings.Index(src, "addUpDNSEnforceFlags(fs)")
	engine := strings.Index(src, "engine, err := node.New(")
	start := strings.Index(src, "defer dnsEnforceFlags.start(ctx, env, engine, name, magicOK)()")
	if declare < 0 || start < 0 {
		t.Fatalf("cmdUp DNS zorlamaya bağlı değil (bildirim %d, başlatma %d)", declare, start)
	}
	if declare > engine || start < engine {
		t.Fatalf("sıra yanlış: bildirim %d, motor %d, başlatma %d", declare, engine, start)
	}
	if run := strings.Index(src, "return engine.Run(ctx)"); start > run {
		t.Fatalf("başlatma engine.Run'dan sonra: %d > %d", start, run)
	}
}
