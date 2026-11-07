package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/logcrypt"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/syncdir"
	"github.com/openscale/openscale/internal/trust"
)

func TestRDeskDecision(t *testing.T) {
	doc := appsDoc(
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, AllowControl: true},
		trust.Rule{From: []string{"masaustu"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, AllowUnattended: true},
	)
	laptop, _ := doc.DeviceByName("laptop")
	desk, _ := doc.DeviceByName("masaustu")
	cases := []struct {
		dev                 trust.Device
		mode                rdesk.Mode
		allowed, unattended bool
	}{
		{laptop, rdesk.ModeView, true, false},
		{laptop, rdesk.ModeControl, true, false},
		{desk, rdesk.ModeView, true, true},
		// Control is refused, never silently downgraded to view.
		{desk, rdesk.ModeControl, false, false},
		{laptop, 0, false, false},
	}
	for i, c := range cases {
		d := rdeskDecision(doc, "nas", c.dev, c.mode)
		if d.Allowed != c.allowed || d.Unattended != c.unattended || d.Peer != c.dev.Name {
			t.Errorf("case %d: %+v", i, d)
		}
	}
	// A deny rule wins.
	doc.Rules = append(doc.Rules, trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop, Action: trust.RuleDeny})
	if rdeskDecision(doc, "nas", laptop, rdesk.ModeView).Allowed {
		t.Fatal("deny rule must win")
	}
}

// fakeRDeskHost records what Apps asks of a host.
type fakeRDeskHost struct {
	serving    atomic.Int32
	starts     atomic.Int32
	revalidate atomic.Int32
	mu         sync.Mutex
	env        RemoteDesktopEnv
}

func (h *fakeRDeskHost) Kind() string { return "fake" }
func (h *fakeRDeskHost) Revalidate()  { h.revalidate.Add(1) }
func (h *fakeRDeskHost) Serve(ctx context.Context, ln net.Listener, env RemoteDesktopEnv) error {
	h.mu.Lock()
	h.env = env
	h.mu.Unlock()
	h.starts.Add(1)
	h.serving.Add(1)
	defer h.serving.Add(-1)
	<-ctx.Done()
	return ln.Close()
}

func TestAppsRemoteDesktopHost(t *testing.T) {
	rule := trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop}
	// Without a host the rule stays unserved (fail closed).
	a, _ := testApps(t, "nas", "laptop", false, rule)
	appsWait(t, "rdesk error", func() bool { return a.RDeskStatus().Error != "" })
	if st := a.RDeskStatus(); st.Running || st.Supported || !st.Hosted {
		t.Fatalf("status without host: %+v", st)
	}

	host := &fakeRDeskHost{}
	doc := appsDoc(rule)
	eng := &appsFakeEngine{doc: doc, self: "nas"}
	laptop, _ := doc.DeviceByName("laptop")
	b := NewApps(AppsConfig{Dir: t.TempDir(), Engine: func() AppEngine { return eng }, Interval: 20 * time.Millisecond, RemoteDesktop: host})
	b.listenHost, b.anyPort = appsLoopback, true
	b.mapPeer = func(netip.Addr) netip.Addr { return laptop.IPv4 }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	appsWait(t, "host to serve", func() bool { return host.serving.Load() == 1 })
	host.mu.Lock()
	env := host.env
	host.mu.Unlock()
	if !env.Settings.Equal(RemoteDesktopSettings{}) || env.Device != "nas" {
		t.Fatalf("env: %+v", env)
	}
	if d := env.Authorize(appsLoopback, rdesk.ModeView); !d.Allowed || d.Peer != "laptop" {
		t.Fatalf("authorize view: %+v", d)
	}
	if d := env.Authorize(appsLoopback, rdesk.ModeControl); d.Allowed {
		t.Fatal("control must need allow_control")
	}
	// A rule change revalidates sessions.
	eng.setRules(2, []trust.Rule{rule, {From: []string{"masaustu"}, To: []string{"nas"}, Service: trust.ServiceRemoteDesktop}})
	appsWait(t, "revalidate", func() bool { return host.revalidate.Load() > 0 })
	// New owner settings restart the server with them.
	on := true
	if err := b.SetRDeskSettings(panel.RDeskSettingsChange{LocalLock: &on}); err != nil {
		t.Fatal(err)
	}
	appsWait(t, "restart", func() bool { return host.starts.Load() >= 2 && host.serving.Load() == 1 })
	host.mu.Lock()
	if !host.env.Settings.LocalLock {
		t.Fatal("restarted host must get the new settings")
	}
	host.mu.Unlock()
	bad := 0
	if err := b.SetRDeskSettings(panel.RDeskSettingsChange{RecordingDays: &bad}); err == nil {
		t.Fatal("0 days must be refused")
	}
	// Removing the rule stops it.
	eng.setRules(3, nil)
	appsWait(t, "host to stop", func() bool { return host.serving.Load() == 0 })
}

func TestRDeskTracker(t *testing.T) {
	tr := newRDeskTracker(time.Now, slog.New(slog.DiscardHandler))
	tr.event("h1", rdesk.SessionEvent{Kind: rdesk.EventStart, ID: 1, Peer: "laptop", Mode: rdesk.ModeControl, Code: "123456", Recording: true})
	tr.event("h1", rdesk.SessionEvent{Kind: rdesk.EventChange, ID: 1, Clipboard: true})
	tr.event("h2", rdesk.SessionEvent{Kind: rdesk.EventStart, ID: 1, Peer: "masaustu", Mode: rdesk.ModeView})
	active, _ := tr.snapshot()
	if len(active) != 2 || active[0].Code != "123456" || !active[0].Recording || !active[0].Clipboard || active[0].Mode != "control" {
		t.Fatalf("active: %+v", active)
	}
	tr.endSource("h1", "yardımcı durdu")
	active, recent := tr.snapshot()
	if len(active) != 1 || active[0].Peer != "masaustu" || len(recent) != 1 || recent[0].Reason != "yardımcı durdu" || recent[0].Ended == nil {
		t.Fatalf("after endSource: %+v %+v", active, recent)
	}
}

// fakeLauncher records the bootstrap and simulates a helper process.
type fakeLauncher struct {
	mu      sync.Mutex
	boot    []byte
	session atomic.Uint32
	procs   []*fakeProc
}

type fakeProc struct {
	pid     uint32
	done    chan struct{}
	stopped atomic.Bool
	once    sync.Once
}

func (p *fakeProc) PID() uint32           { return p.pid }
func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Stop(time.Duration) {
	p.stopped.Store(true)
	p.once.Do(func() { close(p.done) })
}

func (l *fakeLauncher) ConsoleSession() uint32 { return l.session.Load() }
func (l *fakeLauncher) Launch(boot []byte) (helperProc, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.boot = append([]byte(nil), boot...)
	p := &fakeProc{pid: uint32(1000 + len(l.procs)), done: make(chan struct{})}
	l.procs = append(l.procs, p)
	return p, nil
}

func TestHelperHostTokenAndProcess(t *testing.T) {
	l := &fakeLauncher{}
	l.session.Store(1)
	var callerPID atomic.Uint32
	var restarted atomic.Bool
	h := &helperHost{
		launcher:  l,
		apiAddr:   func() string { return "127.0.0.1:47821" },
		lookupPID: func(string, string) (uint32, error) { return callerPID.Load(), nil },
		events:    func(string, rdesk.SessionEvent) {},
		restart:   func(context.Context, string) error { restarted.Store(true); return nil },
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env := RemoteDesktopEnv{Addr: netip.MustParseAddrPort("100.80.0.3:4047"), Device: "nas", Dir: t.TempDir(),
		Authorize: func(netip.Addr, rdesk.Mode) rdesk.Decision { return rdesk.Decision{Allowed: true, Peer: "laptop"} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = h.Serve(ctx, ln, env); close(done) }()
	appsWait(t, "helper launch", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.pid != 0 })
	l.mu.Lock()
	var boot HelperBootstrap
	err = json.Unmarshal(bytes.TrimSpace(l.boot), &boot)
	l.mu.Unlock()
	if err != nil || boot.Validate() != nil || boot.Listen != "100.80.0.3:4047" || boot.RecordingKey != "" || boot.Power || boot.LocalLock {
		t.Fatalf("bootstrap: %+v %v", boot, err)
	}
	callerPID.Store(1000)
	if !h.Allowed(boot.Token, "127.0.0.1:5000", "127.0.0.1:47821") {
		t.Fatal("the helper must be allowed")
	}
	if h.Allowed(boot.Token+"x", "127.0.0.1:5000", "127.0.0.1:47821") || h.Allowed("", "", "") {
		t.Fatal("a wrong token must be refused")
	}
	callerPID.Store(4242)
	if h.Allowed(boot.Token, "127.0.0.1:5000", "127.0.0.1:47821") {
		t.Fatal("another process with the token must be refused")
	}
	if d := h.Authorize(netip.MustParseAddr("100.80.0.2"), "control"); !d.Allowed || d.Peer != "laptop" {
		t.Fatalf("authorize: %+v", d)
	}
	if d := h.Authorize(netip.MustParseAddr("100.80.0.2"), "admin"); d.Allowed {
		t.Fatal("unknown mode must be refused")
	}
	g := h.State().Generation
	h.Revalidate()
	if h.State().Generation == g {
		t.Fatal("revalidate must change the generation")
	}
	// Power is off by default; safe mode is never done.
	if err := h.Power(panel.RDeskHelperPower{Peer: "laptop"}); err == nil || restarted.Load() {
		t.Fatal("restart must be off by default")
	}
	// A console session change restarts the helper with a new token.
	old := boot.Token
	l.session.Store(2)
	appsWait(t, "second helper", func() bool { l.mu.Lock(); defer l.mu.Unlock(); return len(l.procs) == 2 })
	l.mu.Lock()
	first := l.procs[0]
	_ = json.Unmarshal(bytes.TrimSpace(l.boot), &boot)
	l.mu.Unlock()
	if !first.stopped.Load() || boot.Token == old {
		t.Fatal("session change must stop the old helper and use a new token")
	}
	callerPID.Store(1000)
	appsWait(t, "new pid", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.pid == 1001 })
	if h.Allowed(old, "127.0.0.1:5000", "127.0.0.1:47821") {
		t.Fatal("the old helper's token must be dead")
	}
	cancel()
	<-done
	if h.Allowed(boot.Token, "127.0.0.1:5000", "127.0.0.1:47821") {
		t.Fatal("nothing may be allowed after stop")
	}
}

func TestHelperHostPowerAndRecording(t *testing.T) {
	dir := t.TempDir()
	var restarted atomic.Bool
	h := &helperHost{apiAddr: func() string { return "127.0.0.1:1" }, restart: func(context.Context, string) error { restarted.Store(true); return nil }}
	h.env = RemoteDesktopEnv{Settings: RemoteDesktopSettings{Power: true}}
	if err := h.Power(panel.RDeskHelperPower{Peer: "laptop", SafeMode: true}); err == nil || restarted.Load() {
		t.Fatal("safe mode must be refused")
	}
	if err := h.Power(panel.RDeskHelperPower{Peer: "laptop"}); err != nil || !restarted.Load() {
		t.Fatalf("restart: %v", err)
	}
	env := RemoteDesktopEnv{Addr: netip.MustParseAddrPort("100.80.0.3:4047"), Dir: dir, Settings: RemoteDesktopSettings{Recording: true}}
	boot, err := h.bootstrap(env, strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	var b HelperBootstrap
	if err := json.Unmarshal(boot, &b); err != nil {
		t.Fatal(err)
	}
	if _, err := rdesk.ParseRecordingKey([]byte(b.RecordingKey)); err != nil || b.RecordingDays != defaultRecordingDays {
		t.Fatalf("recording key in bootstrap: %v %+v", err, b)
	}
	// The key file stays owner-only in the data directory.
	if _, err := os.Stat(RecordingKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
}

func TestHelperBootstrapValidate(t *testing.T) {
	good := HelperBootstrap{Version: 1, API: "127.0.0.1:47821", Token: strings.Repeat("x", 43), Listen: "100.80.0.3:4047"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*HelperBootstrap){
		func(b *HelperBootstrap) { b.Version = 2 },
		func(b *HelperBootstrap) { b.API = "10.0.0.1:47821" },
		func(b *HelperBootstrap) { b.Token = "short" },
		func(b *HelperBootstrap) { b.Listen = "0.0.0.0:4047" },
		func(b *HelperBootstrap) { b.Listen = "100.80.0.3:0" },
	}
	for i, f := range bad {
		b := good
		f(&b)
		if b.Validate() == nil {
			t.Errorf("case %d must fail", i)
		}
	}
}

func TestBuildRemoteDesktopConfig(t *testing.T) {
	auth := func(netip.Addr, rdesk.Mode) rdesk.Decision { return rdesk.Decision{} }
	ind := func(rdesk.SessionEvent) {}
	cfg, err := BuildRemoteDesktopConfig(RemoteDesktopServerOptions{Addr: netip.MustParseAddrPort("100.80.0.3:4047"), Authorize: auth, Indicator: ind})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Recording != nil || cfg.NewLocalLock != nil || cfg.Power != nil || cfg.AllowLegacyV1 {
		t.Fatal("recording, local lock, power and legacy clients are off by default")
	}
	if _, err := BuildRemoteDesktopConfig(RemoteDesktopServerOptions{Addr: netip.MustParseAddrPort("100.80.0.3:4047"), Authorize: auth}); err == nil {
		t.Fatal("the indicator is required")
	}
	if _, err := BuildRemoteDesktopConfig(RemoteDesktopServerOptions{Addr: netip.MustParseAddrPort("0.0.0.0:4047"), Authorize: auth, Indicator: ind}); err == nil {
		t.Fatal("wildcard address must be refused")
	}
	key, _ := rdesk.LoadOrCreateRecordingKey(filepath.Join(t.TempDir(), "k"))
	if _, err := BuildRemoteDesktopConfig(RemoteDesktopServerOptions{Addr: netip.MustParseAddrPort("100.80.0.3:4047"), Authorize: auth, Indicator: ind, RecordingKey: key}); err == nil {
		t.Fatal("recording needs a folder")
	}
}

// --- sync ---

func TestSyncServesSharedFolderReadOnly(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "a.txt"), []byte("merhaba"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, eng := testApps(t, "nas", "laptop", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSync, Folders: []string{"belgeler"}},
	)
	if err := a.SetSyncFolder(panel.SyncFolderChange{ID: "belgeler", Path: share, Mode: "sendonly"}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetSyncFolder(panel.SyncFolderChange{ID: "gizli", Path: t.TempDir(), Mode: "sendonly"}); err != nil {
		t.Fatal(err)
	}
	addr := boundAddr(t, a, trust.ServiceSync)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl, err := syncdir.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ix, err := cl.Folder("belgeler").Index(ctx)
	if err != nil || len(ix) != 1 {
		t.Fatalf("index: %v %v", ix, err)
	}
	if _, err := cl.Folder("gizli").Index(ctx); !errors.Is(err, syncdir.ErrDenied) {
		t.Fatalf("a folder the rule does not name must be refused: %v", err)
	}
	st := a.SyncStatus()
	if !st.Hosted || !st.Running || len(st.Folders) != 2 || len(st.Folders[0].ServedTo) != 1 || st.Folders[0].ServedTo[0] != "laptop" {
		t.Fatalf("status: %+v", st)
	}
	// Withdrawing the rule refuses the open connection's next request.
	eng.setRules(2, []trust.Rule{{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSync, Backup: true}})
	if _, err := cl.Folder("belgeler").Index(ctx); err == nil {
		t.Fatal("withdrawn access must be refused")
	}
}

func TestSyncFolderAndBackupChecks(t *testing.T) {
	a, _ := testApps(t, "laptop", "nas", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSync, Backup: true},
	)
	folder := t.TempDir()
	bad := []panel.SyncFolderChange{
		{ID: "Belgeler", Path: folder, Mode: "sendreceive"},
		{ID: "a", Path: "goreli/yol", Mode: "sendreceive"},
		{ID: "a", Path: folder, Mode: "push"},
		{ID: "a", Path: a.cfg.Dir, Mode: "sendreceive"},
		{ID: "a", Path: filepath.Join(a.cfg.Dir, "apps"), Mode: "sendreceive"},
		{ID: "a", Path: filepath.VolumeName(folder) + string(filepath.Separator), Mode: "sendreceive"},
		{ID: "a", Path: folder, Mode: "sendonly", Peers: []string{"nas"}},
		{ID: "a", Path: folder, Mode: "sendreceive", Peers: []string{"NAS!"}},
	}
	for i, c := range bad {
		if err := a.SetSyncFolder(c); err == nil {
			t.Errorf("folder %d must be refused: %+v", i, c)
		}
	}
	if err := a.SetSyncFolder(panel.SyncFolderChange{ID: "belgeler", Path: folder, Mode: "sendreceive", Peers: []string{"nas"}}); err != nil {
		t.Fatal(err)
	}
	// Backups need the exported key.
	if err := a.SetSyncBackup(panel.SyncBackupChange{Enabled: true, Target: "nas", Folders: []string{"belgeler"}}); err == nil {
		t.Fatal("backup without exported key must be refused")
	}
	if a.SyncStatus().Backup.KeyExported {
		t.Fatal("key must not count as exported")
	}
	text, err := a.ExportBackupKey([]byte("uzun-bir-yedek-parolasi"))
	if err != nil || text == "" {
		t.Fatal(err)
	}
	k, err := syncdir.ImportBackupKey(text, []byte("uzun-bir-yedek-parolasi"))
	if err != nil {
		t.Fatal(err)
	}
	st := a.SyncStatus()
	if !st.Backup.KeyExported || st.Backup.KeyFingerprint != k.Fingerprint() || len(st.BackupTargets) != 1 || st.BackupTargets[0] != "nas" {
		t.Fatalf("status after export: %+v", st.Backup)
	}
	if err := a.SetSyncBackup(panel.SyncBackupChange{Enabled: true, Target: "masaustu", Folders: []string{"belgeler"}}); err == nil {
		t.Fatal("a target without a backup rule must be refused")
	}
	if err := a.SetSyncBackup(panel.SyncBackupChange{Enabled: true, Target: "nas", Folders: []string{"yok"}}); err == nil {
		t.Fatal("unknown folder must be refused")
	}
	if err := a.SetSyncBackup(panel.SyncBackupChange{Enabled: true, Target: "nas", Folders: []string{"belgeler"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveSyncFolder("belgeler"); err != nil {
		t.Fatal(err)
	}
	if st := a.SyncStatus(); len(st.Folders) != 0 || len(st.Backup.Folders) != 0 {
		t.Fatalf("removal: %+v", st)
	}
}

func TestQueueFileWaitsForRecipient(t *testing.T) {
	a, _ := testApps(t, "laptop", "nas", false,
		trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceFiles},
	)
	a.ext().noKick = true
	if _, err := a.QueueFile("masaustu", "a.txt", strings.NewReader("x"), 1, ""); err == nil {
		t.Fatal("no rule to masaustu")
	}
	if _, err := a.QueueFile("nas", "a.txt", strings.NewReader("x"), 1, "gps"); err == nil {
		t.Fatal("bad strip mode")
	}
	id, err := a.QueueFile("nas", "a.txt", strings.NewReader("merhaba"), 7, "location")
	if err != nil {
		t.Fatal(err)
	}
	st := a.SyncStatus()
	if len(st.Outbox) != 1 || st.Outbox[0].ID != id || st.Outbox[0].Strip != "location" || st.Outbox[0].Peer != "nas" {
		t.Fatalf("outbox: %+v", st.Outbox)
	}
	if err := a.RemoveOutbox(id); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(a.appsPath(queueDir))
	if len(entries) != 0 || len(a.SyncStatus().Outbox) != 0 {
		t.Fatal("removed item must delete its stored copy")
	}
}

// --- preferences ---

func TestWave2Prefs(t *testing.T) {
	var topt tunnelOptions
	for k, v := range map[string]string{
		"port-map": "true", "port-map-disable": "upnp", "padding": "buckets", "cover-traffic": "1024",
		"interactive-priority": "true", "tor-socks": "127.0.0.1:9050", "exit-dns-upstream": "recursive-dnssec",
		"threat-block": "false", "threat-block-for": "30m", "canary-ports": "2222,4444",
	} {
		if ok, err := applyTunnelPref(&topt, k, v); !ok || err != nil {
			t.Fatalf("%s: %v %v", k, ok, err)
		}
	}
	if err := topt.validate(); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{logger: slog.New(slog.DiscardHandler)}
	cfg := r.withWave2Options(topt.wave2Options, topt.transportOptions, node.Config{})
	if !cfg.PortMap.Enabled || !cfg.PortMap.DisableUPnP || cfg.PortMap.DisablePCP || cfg.Padding != node.PaddingBuckets || cfg.CoverTraffic != 1024 ||
		!cfg.InteractivePriority || cfg.TorSOCKS != "127.0.0.1:9050" || cfg.ExitDNSUpstream != "recursive-dnssec" ||
		!cfg.Threats.DisableBlock || cfg.Threats.BlockFor != 30*time.Minute || len(cfg.Threats.CanaryPorts) != 2 || cfg.OnThreat == nil {
		t.Fatalf("engine config: %+v", cfg)
	}
	// The same values compare equal after a round trip (no needless restart).
	clone := topt
	clone.wave2Options = topt.wave2Options.clone()
	if !tunnelEqualIgnoringLog(topt, clone) {
		t.Fatal("equal options must compare equal")
	}
	bad := map[string]string{"padding": "huge", "cover-traffic": "10", "port-map-disable": "smtp", "canary-ports": "70000", "canary-addrs": "x"}
	for k, v := range bad {
		var o tunnelOptions
		ok, err := applyTunnelPref(&o, k, v)
		if ok && err == nil {
			err = o.validate()
		}
		if err == nil {
			t.Errorf("%s=%s must be refused", k, v)
		}
	}
	for _, o := range []tunnelOptions{
		{wave2Options: wave2Options{TorSOCKS: "10.0.0.1:9050"}},
		{wave2Options: wave2Options{TorSOCKS: "127.0.0.1:9050"}, transportOptions: transportOptions{DisableTCPFallback: true}},
		{wave2Options: wave2Options{PortMap: true, PortMapDisable: []string{"pcp", "natpmp", "upnp"}}},
		{wave2Options: wave2Options{ExitDNSUpstream: "ftp://x"}},
		{wave2Options: wave2Options{ExitDNSBlocklist: "goreli.txt"}},
		{wave2Options: wave2Options{DNSSECTrustAnchors: filepath.Join(t.TempDir(), "yok.txt")}},
	} {
		if err := o.validate(); err == nil {
			t.Errorf("must be refused: %+v", o.wave2Options)
		}
	}
	// Every new key is documented for "openscale get".
	for _, k := range []string{"port-map", "padding", "cover-traffic", "tor-socks", "exit-dns-upstream", "threat-scan"} {
		if _, ok := findPref(k); !ok {
			t.Errorf("pref %s missing", k)
		}
	}
	// Unknown saved values never stop the tunnel: they fall back to off.
	cfg = r.withWave2Options(wave2Options{Padding: "x", CoverTraffic: 5, TorSOCKS: "8.8.8.8:1"}, transportOptions{}, node.Config{})
	if cfg.Padding != node.PaddingOff || cfg.CoverTraffic != 0 || cfg.TorSOCKS != "" {
		t.Fatalf("fallback: %+v", cfg)
	}
}

func TestShapingCostText(t *testing.T) {
	lines := ShapingCostText(node.PaddingMTU, 2048, 0)
	if len(lines) != 2 || !strings.Contains(lines[0], "%") || !strings.Contains(lines[1], "GiB") {
		t.Fatalf("cost text: %q", lines)
	}
	if len(ShapingCostText(node.PaddingOff, 0, 0)) != 0 {
		t.Fatal("nothing costs nothing")
	}
}

func TestThreatText(t *testing.T) {
	ev := filter.ThreatEvent{Kind: filter.ThreatInboundScan, Peer: "laptop", Count: 25, BlockedUntil: time.Now().Add(time.Minute)}
	if s := ThreatText(ev); !strings.Contains(s, "laptop") || !strings.Contains(s, "25") || !strings.Contains(s, "reddediliyor") {
		t.Fatalf("text: %s", s)
	}
}

// --- encrypted debug log ---

func TestDebugLogIsSealed(t *testing.T) {
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{7}, 32)
	var plain bytes.Buffer
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	h, closer := NewDebugCryptHandler(slog.NewJSONHandler(&plain, &slog.HandlerOptions{Level: level}), dir,
		func() ([]byte, error) { return append([]byte(nil), seed...), nil }, level)
	log := slog.New(h).With("role", "device")
	log.Debug("endpoint", "addr", "203.0.113.7:51820")
	log.Info("tunnel up")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "203.0.113.7") || !strings.Contains(plain.String(), "tunnel up") {
		t.Fatalf("plain log: %s", plain.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "debug-*.oslog"))
	if len(files) != 1 {
		t.Fatalf("sealed files: %v", files)
	}
	data, _ := os.ReadFile(files[0])
	if bytes.Contains(data, []byte("203.0.113.7")) {
		t.Fatal("debug file must be encrypted")
	}
	var out bytes.Buffer
	if _, err := logcrypt.Decrypt(&out, bytes.NewReader(data), seed); err != nil || !strings.Contains(out.String(), "203.0.113.7") || !strings.Contains(out.String(), `"role":"device"`) {
		t.Fatalf("decrypt: %v %s", err, out.String())
	}
	// Without a device key debug records are dropped, never written plain.
	plain.Reset()
	h2, c2 := NewDebugCryptHandler(slog.NewJSONHandler(&plain, &slog.HandlerOptions{Level: level}), t.TempDir(),
		func() ([]byte, error) { return nil, os.ErrNotExist }, level)
	slog.New(h2).Debug("endpoint", "addr", "203.0.113.8:1")
	_ = c2.Close()
	if strings.Contains(plain.String(), "203.0.113.8") {
		t.Fatal("debug record leaked into the plain log")
	}
	_ = io.Discard
}
