package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// Tests never reach a real OpenScale service or read the real environment.
func init() {
	localAPI.dataDir = func() string { return "" }
	lookupEnv = func(string) (string, bool) { return "", false }
	environ = func() []string { return nil }
}

// fakeDiag answers the diagnostics API for command tests.
type fakeDiag struct {
	pings  int
	direct int // the ping that sees a direct path (1-based); 0 never
	set    map[string]string
	level  string
}

func (f *fakeDiag) DiagStatus() (panel.DiagStatus, error) {
	ms := 4.25
	hs := time.Now().Add(-30 * time.Second)
	return panel.DiagStatus{Schema: panel.DiagSchema, Mode: panel.ModeMember, Running: true, Connected: true,
		Self: &panel.DiagSelf{Name: "laptop", FQDN: "laptop.ag.test", IPv4: "100.64.0.2", IPv6: "fd00::2"},
		Peers: []panel.DiagPeer{
			{Name: "nas", IPv4: "100.64.0.3", Online: true, Path: panel.PathDirect, Endpoint: "192.0.2.7:41641", LastHandshake: &hs, RxBytes: 2048, LatencyMS: &ms},
			{Name: "telefon", IPv4: "100.64.0.4", Path: panel.PathRelay},
		}, Health: []panel.HealthAlert{}}, nil
}
func (f *fakeDiag) DiagNetCheck(context.Context) (node.NetReport, error) {
	return node.NetReport{CoordinatorReachable: true, NAT: node.NATHard, Notes: []string{"not"}}, nil
}
func (f *fakeDiag) DiagPaths() ([]node.PeerPath, error) {
	return []node.PeerPath{{Name: "nas", Endpoint: "192.0.2.7:41641", Class: "genel"}}, nil
}
func (f *fakeDiag) DiagReconnect() error { return nil }
func (f *fakeDiag) DiagRelayTest(context.Context, string) (time.Duration, error) {
	return 20 * time.Millisecond, nil
}
func (f *fakeDiag) DiagPing(_ context.Context, peer string) (panel.PingResult, error) {
	if peer != "nas" {
		return panel.PingResult{}, errors.New("ağ belgesinde böyle bir cihaz yok")
	}
	f.pings++
	ms := 3.0
	path := panel.PathRelay
	if f.direct > 0 && f.pings >= f.direct {
		path = panel.PathDirect
	}
	return panel.PingResult{Schema: panel.DiagSchema, Peer: peer, IPv4: "100.64.0.3", Path: path, RTTMS: &ms, Method: panel.PingICMP}, nil
}
func (f *fakeDiag) DiagDNS() (panel.DNSStatus, error) {
	return panel.DNSStatus{Schema: panel.DiagSchema, Domain: "ag.test", Resolver: "100.64.0.254", Nameservers: []string{}, Split: []panel.SplitDNSInfo{}}, nil
}
func (f *fakeDiag) DiagDNSQuery(_ context.Context, name string) (panel.DNSQueryResult, error) {
	return panel.DNSQueryResult{Schema: panel.DiagSchema, Name: name + ".ag.test", Addrs: []string{"100.64.0.3"}}, nil
}
func (f *fakeDiag) DiagWhois(q string) (panel.WhoisResult, error) {
	return panel.WhoisResult{Schema: panel.DiagSchema, Query: q, Device: &panel.WhoisDevice{Name: "nas", FQDN: "nas.ag.test", Self: q == ""}}, nil
}
func (f *fakeDiag) DiagEvents() []panel.DiagEvent { return nil }
func (f *fakeDiag) DiagWireGuard() (panel.WGShow, error) {
	return panel.WGShow{Schema: panel.DiagSchema, Interface: "OpenScale", PublicKey: "pub", Peers: []panel.WGPeer{{Name: "nas", PublicKey: "k", AllowedIPs: []string{"100.64.0.3/32"}}}}, nil
}
func (f *fakeDiag) DiagPacketTrace(req panel.TraceRequest) (panel.TraceResult, error) {
	return panel.TraceResult{Schema: panel.DiagSchema, Src: req.Src, Dst: req.Dst, Proto: req.Proto, Port: req.Port, Verdict: "İzin verilir."}, nil
}
func (f *fakeDiag) DiagHealth() panel.HealthReport {
	return panel.HealthReport{Schema: panel.DiagSchema, Live: true, Ready: false, Reasons: []string{"koordinatöre ulaşılamıyor"}, Alerts: []panel.HealthAlert{}}
}
func (f *fakeDiag) DiagLogLevel() string { return f.level }
func (f *fakeDiag) DiagSetLogLevel(l string) error {
	f.level = l
	return nil
}
func (f *fakeDiag) DiagPrefs() ([]panel.Pref, error) {
	return []panel.Pref{{Key: "shields", Value: "false", Default: "false"}, {Key: "mtu", Value: "1420", Default: "0"}}, nil
}
func (f *fakeDiag) DiagSetPrefs(c map[string]string) ([]panel.Pref, error) {
	f.set = c
	return f.DiagPrefs()
}

// serveFake starts the local API of a foreground tunnel and records it in
// the harness's default state directory, as "openscale up" does.
func serveFake(t *testing.T, h *harness, d *fakeDiag) {
	t.Helper()
	ln, err := panel.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 43)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = panel.ServeLocalAPI(ctx, ln, panel.LocalAPIConfig{Diag: d, Token: token})
	}()
	t.Cleanup(func() { cancel(); <-done })
	dir, _ := h.env.DefaultStateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().String()[strings.LastIndex(ln.Addr().String(), ":")+1:]
	if err := securefile.Replace(filepath.Join(dir, localAPIFile), []byte(`{"port":`+port+`,"token":"`+token+`"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDiagCommandsWithoutTunnel(t *testing.T) {
	h := newHarness(t)
	out := h.run(exitError, "status")
	if !strings.Contains(out, "tüneli bulunamadı") {
		t.Fatalf("no tunnel:\n%s", out)
	}
	h.run(exitUsage, "ping")
	h.run(exitUsage, "status", "--peers", "--self")
	h.run(exitUsage, "set")
	h.run(exitUsage, "set", "shields")
	h.run(exitUsage, "log", "level", "trace")
	h.run(exitUsage, "packet-trace", "a", "b")
	h.run(exitUsage, "down", "--for", "2h")
}

func TestDiagCommandsThroughLocalAPI(t *testing.T) {
	h := newHarness(t)
	d := &fakeDiag{level: "info", direct: 2}
	serveFake(t, h, d)

	mustContain(t, h.run(exitOK, "status"), "laptop.ag.test", "nas", "doğrudan", "192.0.2.7:41641", "2.0 KiB", "4.2 ms", "aktarıcı")
	out := h.run(exitOK, "status", "--json", "--peers")
	var st panel.DiagStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Schema != 1 || st.Self != nil || len(st.Peers) != 2 {
		t.Fatalf("status --json --peers:\n%s", out)
	}
	mustContain(t, h.run(exitOK, "ping", "nas", "-c", "2", "-i", "200ms"), "yanıt: 3.0 ms", "2 gönderildi, 2 yanıt")
	d.pings = 0
	mustContain(t, h.run(exitOK, "ping", "--until-direct", "nas", "-i", "200ms"), "Doğrudan yol kuruldu")
	if d.pings != 2 {
		t.Fatalf("--until-direct must stop at the direct path: %d pings", d.pings)
	}
	d.pings, d.direct = 0, 0
	mustContain(t, h.run(exitError, "ping", "nas", "--until-direct", "-c", "2", "-i", "200ms"), "doğrudan yol kurulamadı")
	out = h.run(exitOK, "ping", "nas", "-c", "1", "--json")
	if !strings.HasPrefix(out, `{"schema":1`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("ping --json is one line per result:\n%s", out)
	}
	mustContain(t, h.run(exitError, "ping", "yok", "-c", "1"), "böyle bir cihaz yok")
	mustContain(t, h.run(exitOK, "netcheck"), "zor", "Notlar")
	mustContain(t, h.run(exitOK, "netcheck", "--json"), `"schema": 1`, `"nat": "zor"`)
	mustContain(t, h.run(exitOK, "debug", "reconnect"), "sıfırlandı")
	mustContain(t, h.run(exitOK, "debug", "relay-test", "nas"), "20.0 ms")
	mustContain(t, h.run(exitOK, "debug", "endpoints"), "nas", "192.0.2.7:41641")
	mustContain(t, h.run(exitOK, "dns", "status"), "ag.test", "100.64.0.254")
	mustContain(t, h.run(exitOK, "dns", "query", "nas"), "nas.ag.test -> 100.64.0.3")
	mustContain(t, h.run(exitOK, "whois", "100.64.0.3"), "nas.ag.test")
	mustContain(t, h.run(exitOK, "whoami"), "(bu cihaz)")
	mustContain(t, h.run(exitOK, "wg", "show"), "interface: OpenScale", "allowed ips: 100.64.0.3/32")
	mustContain(t, h.run(exitOK, "packet-trace", "laptop", "nas", "tcp", "22"), "laptop -> nas tcp/22", "İzin verilir")
	h.run(exitUsage, "packet-trace", "laptop", "nas", "tcp", "99999")
	mustContain(t, h.run(exitError, "health"), "hazır: false", "hazır değil")
	mustContain(t, h.run(exitOK, "health", "--live"), "canlı: true")
	mustContain(t, h.run(exitOK, "log", "level", "debug"), "debug", "uç nokta")
	if d.level != "debug" {
		t.Fatal("log level not sent")
	}
	mustContain(t, h.run(exitOK, "get"), "* mtu", "1420")
	mustContain(t, h.run(exitOK, "get", "mtu", "--json"), `"key": "mtu"`)
	h.run(exitUsage, "get", "yok")
	mustContain(t, h.run(exitOK, "set", "shields=true", "mtu=1280"), "shields = false")
	if d.set["shields"] != "true" || d.set["mtu"] != "1280" {
		t.Fatalf("set sent %v", d.set)
	}
	h.run(exitUsage, "set", "shields=true", "shields=false")
	// A foreground tunnel is stopped with Ctrl+C, not through the API.
	mustContain(t, h.run(exitError, "down"), "Ctrl+C")
}

func TestConfigFileAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "up.json")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newFS := func() (*flag.FlagSet, *int, *bool, *listFlag) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(discard{})
		port := fs.Int("listen-port", 0, "")
		dbg := fs.Bool("debug", false, "")
		eps := &listFlag{}
		fs.Var(eps, "static-endpoint", "")
		return fs, port, dbg, eps
	}
	allowed := []string{"listen-port", "debug", "static-endpoint"}
	env := map[string]string{}
	lookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	defer func() { lookupEnv = func(string) (string, bool) { return "", false } }()

	write(`{"listen-port": 41641, "debug": true, "static-endpoint": ["203.0.113.5:1", "203.0.113.6:2"]}`)
	fs, port, dbg, eps := newFS()
	if err := parseFlagsWithEnv(fs, []string{"--config", path}, allowed); err != nil {
		t.Fatal(err)
	}
	if *port != 41641 || !*dbg || len(eps.vals) != 2 {
		t.Fatalf("file values: %d %v %v", *port, *dbg, eps.vals)
	}
	// Environment over the file, command line over both; lists replace.
	env["OPENSCALE_LISTEN_PORT"] = "5000"
	env["OPENSCALE_STATIC_ENDPOINT"] = "203.0.113.9:9"
	fs, port, _, eps = newFS()
	if err := parseFlagsWithEnv(fs, []string{"--config=" + path}, allowed); err != nil {
		t.Fatal(err)
	}
	if *port != 5000 || len(eps.vals) != 1 || eps.vals[0] != "203.0.113.9:9" {
		t.Fatalf("env over file: %d %v", *port, eps.vals)
	}
	fs, port, _, eps = newFS()
	if err := parseFlagsWithEnv(fs, []string{"--config", path, "--listen-port", "6000", "--static-endpoint", "203.0.113.10:10"}, allowed); err != nil {
		t.Fatal(err)
	}
	if *port != 6000 || len(eps.vals) != 1 || eps.vals[0] != "203.0.113.10:10" {
		t.Fatalf("command line over env: %d %v", *port, eps.vals)
	}
	// OPENSCALE_CONFIG names the file when --config is not given.
	env["OPENSCALE_CONFIG"] = path
	delete(env, "OPENSCALE_LISTEN_PORT")
	fs, port, _, _ = newFS()
	if err := parseFlagsWithEnv(fs, nil, allowed); err != nil || *port != 41641 {
		t.Fatalf("OPENSCALE_CONFIG: %d %v", *port, err)
	}
	delete(env, "OPENSCALE_CONFIG")
	env["OPENSCALE_LISTEN_PORT"] = "abc"
	fs, _, _, _ = newFS()
	if err := parseFlagsWithEnv(fs, nil, allowed); err == nil || !strings.Contains(err.Error(), "OPENSCALE_LISTEN_PORT") {
		t.Fatalf("bad env value: %v", err)
	}
	delete(env, "OPENSCALE_LISTEN_PORT")
	for _, bad := range []string{`{"listen-prot": 1}`, `{"debug": {"a": 1}}`, `[1]`, `{"debug": true} {}`, `{"listen-port": "x"}`} {
		write(bad)
		fs, _, _, _ = newFS()
		if err := parseFlagsWithEnv(fs, []string{"--config", path}, allowed); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	if EnvName("exit-dns-upstream") != "OPENSCALE_EXIT_DNS_UPSTREAM" {
		t.Fatal(EnvName("exit-dns-upstream"))
	}
}

func TestUpReadsConfigFile(t *testing.T) {
	h := newHarness(t)
	empty := t.TempDir()
	path := filepath.Join(t.TempDir(), "up.json")
	if err := os.WriteFile(path, []byte(`{"mtu": 1500}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.run(exitUsage, "up", "--state-dir", empty, "--config", path), "--mtu")
	if err := os.WriteFile(path, []byte(`{"bilinmeyen": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.run(exitError, "up", "--state-dir", empty, "--config", path), "bilinmeyen alan")
	mustContain(t, h.run(exitUsage, "up", "--state-dir", empty, "--static-endpoint", "127.0.0.1:5"), "--static-endpoint")
	mustContain(t, h.run(exitUsage, "up", "--state-dir", empty, "--conntrack-max-flows", "5"), "bağlantı takibi")
	// Valid options pass validation; the missing network fails next.
	h.run(exitError, "up", "--state-dir", empty, "--static-endpoint", "203.0.113.5:41641", "--hide-local-candidates",
		"--disable-udp-offload", "--magicdns-all-devices", "--conntrack-tcp-timeout", "1h", "--candidate-skip-interfaces", "docker,veth")
	if err := os.WriteFile(path, []byte(`{"relay-rate": 1048576}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "coordinator", "run", "--state-dir", empty, "--config", path)
}

func TestConfigtest(t *testing.T) {
	h := newHarness(t)
	stateDir := t.TempDir()
	good := filepath.Join(t.TempDir(), "up.json")
	if err := os.WriteFile(good, []byte(`{"listen-port": 41641, "magicdns-all-devices": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.run(exitOK, "configtest", "--state-dir", stateDir, "--config", good), "geçerli")
	out := h.run(exitOK, "configtest", "--state-dir", stateDir, "--config", good, "--json")
	var res struct {
		Schema   int  `json:"schema"`
		OK       bool `json:"ok"`
		Findings []struct{ Level string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Schema != 1 || !res.OK || len(res.Findings) == 0 {
		t.Fatalf("configtest --json:\n%s", out)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"mtu": 9000, "yok": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustContain(t, h.run(exitError, "configtest", "--state-dir", stateDir, "--config", bad), "HATA", "sorun bulundu")
	if err := os.WriteFile(bad, []byte(`{"relay-rate": 5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "configtest", "--state-dir", stateDir, "--config", bad, "--for", "coordinator")
	h.run(exitUsage, "configtest", "--for", "panel")
}

func TestPacketTraceAndFakeDeviceOffline(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	_ = pass
	before := h.run(exitOK, "network", "show", "--dir", h.netDir)
	out := h.run(exitOK, "packet-trace", "laptop", "masaustu", "tcp", "22", "--dir", h.netDir)
	mustContain(t, out, "laptop -> masaustu tcp/22", "Sonuç:")
	out = h.run(exitOK, "packet-trace", "laptop", "masaustu", "icmp", "--dir", h.netDir, "--json")
	var tr panel.TraceResult
	if err := json.Unmarshal([]byte(out), &tr); err != nil || tr.Schema != 1 || len(tr.Steps) == 0 {
		t.Fatalf("packet-trace --json:\n%s", out)
	}
	h.run(exitError, "packet-trace", "yok", "masaustu", "tcp", "22", "--dir", h.netDir)

	h.run(exitUsage, "debug", "fake-device", "deneme", "--dir", h.netDir)
	h.run(exitUsage, "debug", "fake-device", "Kötü Ad", "--dir", h.netDir, "--dry-run")
	out = h.run(exitOK, "debug", "fake-device", "deneme", "--dir", h.netDir, "--dry-run", "--tags", "test")
	mustContain(t, out, "deneme", "Kuru çalıştırma", "etiketler: test")
	out = h.run(exitOK, "debug", "fake-device", "deneme", "--dir", h.netDir, "--dry-run", "--json")
	mustContain(t, out, `"dry_run": true`, `"schema": 1`)
	if after := h.run(exitOK, "network", "show", "--dir", h.netDir); after != before || strings.Contains(after, "deneme") {
		t.Fatal("the dry run changed the network")
	}
}
