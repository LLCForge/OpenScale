package service

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func traceDoc() *trust.Document {
	exitUsers := []string{"group:ev"}
	return &trust.Document{
		DNSDomain:  "ag.test",
		IPv4Prefix: netip.MustParsePrefix("100.64.0.0/24"),
		IPv6Prefix: netip.MustParsePrefix("fd00:64::/64"),
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.64.0.2"), IPv6: netip.MustParseAddr("fd00:64::2"), Tags: []string{"is"}},
			{Name: "nas", IPv4: netip.MustParseAddr("100.64.0.3"), IPv6: netip.MustParseAddr("fd00:64::3")},
			{Name: "telefon", IPv4: netip.MustParseAddr("100.64.0.4"), IPv6: netip.MustParseAddr("fd00:64::4"), Tags: []string{"mobil"}},
			{Name: "cikis", IPv4: netip.MustParseAddr("100.64.0.5"), IPv6: netip.MustParseAddr("fd00:64::5"), Roles: []trust.Role{trust.RoleExitNode}},
		},
		Groups: []trust.Group{{Name: "ev", Members: []string{"laptop", "tag:mobil"}}},
		Rules: []trust.Rule{
			{From: []string{"group:ev"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"22", "80-90"}},
			{From: []string{"telefon"}, To: []string{"nas"}, Protocol: trust.ProtocolUDP, Ports: []string{"53"}, Action: trust.RuleDeny},
			{From: []string{"tag:is"}, To: []string{"telefon"}, Protocol: trust.ProtocolICMP, Disabled: true},
			{From: []string{"*"}, To: []string{"cikis"}, Protocol: trust.Protocol("47")},
			{From: []string{"group:ev"}, To: []string{"nas"}, Protocol: trust.ProtocolUDP, Ports: []string{"53"}},
		},
		ExitUsers: &exitUsers,
	}
}

// The trace must reach the same verdict as AllowsIP, the packet filter's
// own decision, for every combination.
func TestTracePacketAgreesWithFilter(t *testing.T) {
	doc := traceDoc()
	protos := []struct {
		name string
		num  uint8
	}{{"tcp", 6}, {"udp", 17}, {"icmp", 1}, {"47", 47}}
	for _, src := range doc.Devices {
		for _, dst := range doc.Devices {
			for _, p := range protos {
				for _, port := range []int{22, 53, 85, 443} {
					req := panel.TraceRequest{Src: src.Name, Dst: dst.IPv4.String(), Proto: p.name, Port: port}
					res, err := TracePacket(doc, "", false, req)
					if err != nil {
						t.Fatal(err)
					}
					var dport uint16
					if p.num == 6 || p.num == 17 {
						dport = uint16(port)
					}
					want := doc.AllowsIP(src.Name, dst.Name, p.num, dport)
					if res.Allowed != want {
						t.Errorf("%s -> %s %s/%d: trace %v, filter %v", src.Name, dst.Name, p.name, port, res.Allowed, want)
					}
					for _, s := range res.Steps {
						if s.Outcome == "uyuşmazlık" {
							t.Errorf("%s -> %s %s/%d: explanation disagreed with the filter", src.Name, dst.Name, p.name, port)
						}
					}
				}
			}
		}
	}
	// The deny rule wins over the later allow rule and is named.
	res, err := TracePacket(doc, "", false, panel.TraceRequest{Src: "telefon", Dst: "nas", Proto: "udp", Port: 53})
	if err != nil || res.Allowed || !strings.Contains(res.Verdict, "kural 2") {
		t.Fatalf("deny rule: %+v %v", res, err)
	}
	res, _ = TracePacket(doc, "", false, panel.TraceRequest{Src: "laptop.ag.test", Dst: "nas", Proto: "tcp", Port: 85})
	if !res.Allowed || !strings.Contains(res.Verdict, "kural 1") {
		t.Fatalf("allow by group and port range: %+v", res)
	}
}

func TestTracePacketShieldsInternetAndErrors(t *testing.T) {
	doc := traceDoc()
	res, err := TracePacket(doc, "nas", true, panel.TraceRequest{Src: "laptop", Dst: "nas", Proto: "tcp", Port: 22})
	if err != nil || res.Allowed || !strings.Contains(res.Verdict, "kalkan") {
		t.Fatalf("shields on the destination: %+v %v", res, err)
	}
	res, _ = TracePacket(doc, "laptop", true, panel.TraceRequest{Src: "laptop", Dst: "nas", Proto: "tcp", Port: 22})
	if !res.Allowed {
		t.Fatal("shields of the source do not refuse its own connections")
	}
	res, _ = TracePacket(doc, "", false, panel.TraceRequest{Src: "telefon", Dst: "1.1.1.1", Proto: "udp", Port: 53})
	if !res.Allowed {
		t.Fatalf("exit user through the exit node: %+v", res)
	}
	res, _ = TracePacket(doc, "", false, panel.TraceRequest{Src: "nas", Dst: "1.1.1.1", Proto: "tcp", Port: 443})
	if res.Allowed || !strings.Contains(res.Verdict, "exit_users") {
		t.Fatalf("non exit user: %+v", res)
	}
	for _, req := range []panel.TraceRequest{
		{Src: "yok", Dst: "nas", Proto: "tcp", Port: 22},
		{Src: "laptop", Dst: "yok", Proto: "tcp", Port: 22},
		{Src: "laptop", Dst: "nas", Proto: "tcp"},
		{Src: "laptop", Dst: "nas", Proto: "sctpx"},
		{Src: "laptop", Dst: "nas", Proto: "256"},
	} {
		if _, err := TracePacket(doc, "", false, req); err == nil {
			t.Errorf("%+v must be refused", req)
		}
	}
}

func TestEventLogRing(t *testing.T) {
	l := NewEventLog(3)
	if len(l.List()) != 0 {
		t.Fatal("new log must be empty")
	}
	for i := 0; i < 5; i++ {
		l.Add(panel.DiagEvent{Message: strconv.Itoa(i)})
	}
	got := l.List()
	if len(got) != 3 || got[0].Message != "4" || got[2].Message != "2" {
		t.Fatalf("ring order: %+v", got)
	}
}

func TestEventWatcherTransitions(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	w := &EventWatcher{Log: NewEventLog(50), Now: func() time.Time { return now }}
	obs := func(running bool, peers map[string]peerSeen, captive, syncFail bool) {
		w.apply(observation{running: running, peers: peers, captive: captive, syncFailing: syncFail})
	}
	// The first look only sets the baseline.
	obs(true, map[string]peerSeen{"nas": {online: true, path: panel.PathDirect}}, false, false)
	if n := len(w.Log.List()); n != 0 {
		t.Fatalf("baseline produced %d events", n)
	}
	obs(true, map[string]peerSeen{"nas": {online: true, path: panel.PathRelay}, "yeni": {online: true}}, true, true)
	obs(true, map[string]peerSeen{"nas": {online: false, path: panel.PathRelay}, "yeni": {online: true}}, false, false)
	obs(false, nil, false, false)
	obs(true, map[string]peerSeen{"nas": {online: true, path: panel.PathDirect}}, false, false)
	var kinds []string
	for _, e := range w.Log.List() {
		kinds = append([]string{e.Kind}, kinds...)
		for _, bad := range []string{"100.64", ":", "fd00"} {
			if strings.Contains(e.Message, bad) && bad != ":" {
				t.Fatalf("event holds an address: %q", e.Message)
			}
		}
	}
	want := []string{panel.EventPeerRelayed, panel.EventCaptive, panel.EventSyncLost, panel.EventPeerOffline,
		panel.EventCaptiveClear, panel.EventSyncBack, panel.EventTunnelDown, panel.EventTunnelUp}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("events:\n got %v\nwant %v", kinds, want)
	}
}

func TestPreferenceParsing(t *testing.T) {
	var o tunnelOptions
	for k, v := range map[string]string{
		"static-endpoints": "203.0.113.5:41641, [2001:db8::1]:41641", "hide-local-candidates": "true",
		"candidate-skip-interfaces": "docker,veth", "conntrack-tcp-timeout": "2h", "conntrack-max-flows": "4096",
		"log-level": "WARN",
	} {
		if ok, err := applyTunnelPref(&o, k, v); !ok || err != nil {
			t.Fatalf("%s=%s: %v %v", k, v, ok, err)
		}
	}
	if err := o.validate(); err != nil {
		t.Fatal(err)
	}
	if o.LogLevel != "warn" || len(o.StaticEndpoints) != 2 || o.ConnTrack.TCPTimeout != 2*time.Hour {
		t.Fatalf("parsed: %+v", o)
	}
	if ok, _ := applyTunnelPref(&o, "shields", "true"); ok {
		t.Fatal("shields is not a tunnel option")
	}
	for _, bad := range []tunnelOptions{
		{StaticEndpoints: []string{"127.0.0.1:1"}},
		{StaticEndpoints: []string{"203.0.113.5"}},
		{CandidateSkipInterfaces: []string{"a b"}},
		{ConnTrack: filter.Limits{TCPTimeout: time.Second}},
		{LogLevel: "trace"},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%+v must be refused", bad)
		}
	}
	if _, err := applyTunnelPref(&o, "hide-local-candidates", "belki"); err == nil {
		t.Fatal("a bad boolean must be refused")
	}
	prefs := prefsOf(settings{})
	if len(prefs) != len(prefSpecs) {
		t.Fatal("every key must be listed")
	}
	for _, p := range prefs {
		if p.Value != p.Default {
			t.Errorf("%s: default settings show %q, documented default %q", p.Key, p.Value, p.Default)
		}
	}
}

func TestWithTunnelOptionsSkipsUnusableValues(t *testing.T) {
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	st := settings{Tunnel: &tunnelOptions{StaticEndpoints: []string{"127.0.0.1:5"}, MagicDNSAllDevices: true, DisableUDPOffload: true,
		ConnTrack: filter.Limits{MaxFlows: 4096}}}
	cfg := r.withTunnelOptions(st, node.Config{})
	if len(cfg.StaticEndpoints) != 0 || !cfg.MagicDNSAllDevices || cfg.ConnTrack.MaxFlows != 4096 || cfg.KillSwitchActive == nil || cfg.KillSwitchActive() {
		t.Fatalf("config: %+v", cfg)
	}
	if !tunOptionsFrom(withTUNOptions(context.Background(), tunOptionsFor(st))).DisableOffload {
		t.Fatal("the TUN options must reach OpenTunnel")
	}
	if tunOptionsFrom(context.Background()).DisableOffload {
		t.Fatal("no options means offloads on")
	}
}

func TestDiagSetPrefsWithoutMembership(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer LogLevel.Set(0)
	prefs, err := r.DiagSetPrefs(map[string]string{"log-level": "debug"})
	if err != nil {
		t.Fatal(err)
	}
	if LogLevel.Level() >= 0 || r.DiagLogLevel() != "debug" {
		t.Fatalf("level not applied: %s", r.DiagLogLevel())
	}
	found := false
	for _, p := range prefs {
		found = found || (p.Key == "log-level" && p.Value == "debug")
	}
	if !found {
		t.Fatalf("prefs: %+v", prefs)
	}
	st, err := loadSettings(dir)
	if err != nil || st.Tunnel == nil || st.Tunnel.LogLevel != "debug" {
		t.Fatalf("not saved: %+v %v", st, err)
	}
	for _, change := range []map[string]string{
		{"yok-boyle": "1"},
		{"hide-local-candidates": "true"},
		{"mtu": "9000"},
		{"shields": "evet"},
	} {
		if _, err := r.DiagSetPrefs(change); err == nil {
			t.Errorf("%v must be refused", change)
		}
	}
	if err := r.DiagSetLogLevel("trace"); err == nil {
		t.Fatal("bad level")
	}
}

func TestWhoisAndFindDevice(t *testing.T) {
	doc := traceDoc()
	doc.Coordinator = &trust.Coordinator{IPv4: netip.MustParseAddr("100.64.0.1")}
	self := doc.Devices[0]
	now := time.Now()
	stats := map[trust.Key]wgconf.PeerStatus{doc.Devices[2].WireGuardKey: {Relayed: true, LastHandshakeUnix: now.Unix()}}
	res, err := Whois(doc, self, "", stats, now)
	if err != nil || res.Device == nil || !res.Device.Self || res.Device.Name != "laptop" || len(res.Device.Groups) != 1 {
		t.Fatalf("whoami: %+v %v", res, err)
	}
	for _, q := range []string{"telefon", "TELEFON.ag.test.", "100.64.0.4", "fd00:64::4"} {
		res, err := Whois(doc, self, q, stats, now)
		if err != nil || res.Device == nil || res.Device.Name != "telefon" || res.Device.Groups[0] != "ev" {
			t.Fatalf("whois %q: %+v %v", q, res, err)
		}
	}
	if res, _ := Whois(doc, self, "100.64.0.1", nil, now); !res.Coordinator {
		t.Fatal("the coordinator's address")
	}
	if _, err := Whois(doc, self, "100.64.0.99", nil, now); err == nil {
		t.Fatal("unknown address")
	}
}

func TestHealthOf(t *testing.T) {
	now := time.Now()
	ready := HealthOf(panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{Connected: true, Running: true, LastSync: &now}})
	if !ready.Live || !ready.Ready || ready.Schema != panel.DiagSchema {
		t.Fatalf("ready: %+v", ready)
	}
	for _, st := range []panel.AppStatus{
		{Mode: panel.ModeSetup},
		{Mode: panel.ModeMember, Device: &panel.DeviceStatus{Connected: false}},
		{Mode: panel.ModeMember, Device: &panel.DeviceStatus{Connected: true, Running: true}},
		{Mode: panel.ModeMember, Device: &panel.DeviceStatus{Connected: true, Running: true, LastSync: &now, LastSyncError: "x"}},
		{Mode: panel.ModeAdmin, Device: &panel.DeviceStatus{Connected: true, Running: true, LastSync: &now}, Coordinator: &panel.CoordinatorStatus{Error: "x"}},
	} {
		if h := HealthOf(st); h.Ready || len(h.Reasons) == 0 {
			t.Errorf("%+v must not be ready", st)
		}
	}
}

func findingWith(fs []Finding, level, text string) bool {
	for _, f := range fs {
		if f.Level == level && strings.Contains(f.Message, text) {
			return true
		}
	}
	return false
}

func TestCheckDataDir(t *testing.T) {
	dir := t.TempDir()
	// A port held by another program is found (loopback only).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	out := CheckDataDir(dir, time.Now(), false, busy)
	if !findingWith(out, FindingOK, "settings.json yok") || !findingWith(out, FindingError, strconv.Itoa(busy)) {
		t.Fatalf("empty data dir: %+v", out)
	}
	if !findingWith(CheckDataDir(dir, time.Now(), true, busy), FindingOK, "servis çalışıyor") {
		t.Fatal("a running service owns its ports")
	}
	write := func(v string) {
		if err := securefile.Replace(filepath.Join(dir, settingsFile), []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"coordinator_port": 41820, "gelecek_alan": 1, "mtu": 9000}`)
	out = CheckDataDir(dir, time.Now(), true, busy)
	if !findingWith(out, FindingWarn, "tanımadığı") || !findingWith(out, FindingWarn, "mtu") {
		t.Fatalf("unknown field and bad MTU: %+v", out)
	}
	write(`{"coordinator_port": "x"`)
	if out := CheckDataDir(dir, time.Now(), true, busy); !findingWith(out, FindingError, "settings.json") {
		t.Fatalf("corrupt settings: %+v", out)
	}
	data, _ := json.Marshal(settings{Tunnel: &tunnelOptions{LogLevel: "debug"}})
	write(string(data))
	if out := CheckDataDir(dir, time.Now(), true, busy); !findingWith(out, FindingOK, "geçerli") {
		t.Fatalf("valid settings: %+v", out)
	}
	if err := os.MkdirAll(filepath.Join(dir, DeviceDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DeviceDir, "anchor.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := CheckDataDir(dir, time.Now(), true, busy); !findingWith(out, FindingError, "okunamadı") {
		t.Fatalf("broken membership: %+v", out)
	}
	if out := CheckStateDir(filepath.Join(dir, "yok"), time.Now()); !findingWith(out, FindingInfo, "yok") {
		t.Fatalf("missing state dir: %+v", out)
	}
}

func TestParseLogLevel(t *testing.T) {
	for in, want := range map[string]string{"debug": "debug", "INFO": "info", "warning": "warn", "error": "error", "": "info"} {
		l, err := ParseLogLevel(in)
		if err != nil || LevelName(l) != want {
			t.Errorf("%q: %v %v", in, LevelName(l), err)
		}
	}
}

// The diagnostics answer from a running service: through the methods and
// through the token-protected loopback API the command line uses.
func TestDiagnosticsOnRunningService(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(t.TempDir(), "owner")
	r := newRuntime(t, ctx, dir, "Masaustu")
	if _, err := r.DiagWireGuard(); err == nil {
		t.Fatal("wg show without a tunnel must fail")
	}
	if h := r.DiagHealth(); !h.Live || h.Ready {
		t.Fatalf("setup mode health: %+v", h)
	}
	if _, err := r.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel running and synced", 20*time.Second, func() bool {
		return r.DiagHealth().Ready
	})
	st, err := r.DiagStatus()
	if err != nil || !st.Running || st.Self == nil || st.Self.Name != "masaustu" || st.Mode != panel.ModeAdmin || st.Schema != panel.DiagSchema {
		t.Fatalf("status: %+v %v", st, err)
	}
	who, err := r.DiagWhois("")
	if err != nil || who.Device == nil || !who.Device.Self {
		t.Fatalf("whoami: %+v %v", who, err)
	}
	wg, err := r.DiagWireGuard()
	if err != nil || wg.PublicKey == "" || len(wg.Peers) == 0 || wg.Peers[0].Name != "koordinatör" {
		t.Fatalf("wg show: %+v %v", wg, err)
	}
	for _, p := range wg.Peers {
		if strings.Contains(strings.ToLower(p.PostQuantum), "key=") {
			t.Fatal("a pre-shared key leaked")
		}
	}
	if _, err := r.DiagPaths(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DiagPing(ctx, "yok"); err == nil {
		t.Fatal("ping to an unknown device")
	}
	if _, err := r.DiagPing(ctx, "masaustu"); err == nil {
		t.Fatal("ping to itself")
	}
	tr, err := r.DiagPacketTrace(panel.TraceRequest{Src: "masaustu", Dst: "masaustu", Proto: "tcp", Port: 22})
	if err != nil || tr.Allowed {
		t.Fatalf("trace to itself: %+v %v", tr, err)
	}
	dns, err := r.DiagDNS()
	if err != nil || dns.Domain == "" || dns.Resolver == "" {
		t.Fatalf("dns: %+v %v", dns, err)
	}
	if err := r.DiagReconnect(); err != nil {
		t.Fatal(err)
	}

	// The command line's view: the same answers with the app token only.
	token, err := ReadToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path, tok string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(r.cfg.PanelPort)+panel.LocalAPIPrefix+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/status", ""); code != http.StatusUnauthorized {
		t.Fatalf("status without token: %d", code)
	}
	code, body := get("/status", token)
	if code != http.StatusOK || !strings.Contains(body, `"schema":1`) || !strings.Contains(body, `"masaustu"`) {
		t.Fatalf("status over the API: %d %s", code, body)
	}
	if code, body := get("/prefs", token); code != http.StatusOK || !strings.Contains(body, `"log-level"`) {
		t.Fatalf("prefs over the API: %d %s", code, body)
	}
}
