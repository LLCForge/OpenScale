package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// The desktop service's side of the diagnostics API (panel.Diagnostics).

// LogLevel is the level of the service's log; the desktop service builds
// its logger with it, so "openscale log level" takes effect at once
// (F-188, F-196).
var LogLevel = new(slog.LevelVar)

// diagEvery is how often the event watcher looks at the tunnel.
const diagEvery = 5 * time.Second

// diagState is the Runtime's diagnostics state; the zero value is ready.
type diagState struct {
	mu     sync.Mutex
	events *EventLog
	// obs is the observability state (observe_runtime.go, ADR-0105).
	obs     *Observer
	obsOnce sync.Once
}

var _ panel.Diagnostics = (*Runtime)(nil)

func (r *Runtime) eventLog() *EventLog {
	r.diag.mu.Lock()
	defer r.diag.mu.Unlock()
	if r.diag.events == nil {
		r.diag.events = NewEventLog(MaxEvents)
		r.diag.events.SetOnAdd(r.observer().PublishDiag) // event stream (F-182)
	}
	return r.diag.events
}

func (r *Runtime) currentEngine() *node.Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engine
}

func (r *Runtime) engineDiag() *EngineDiag {
	return &EngineDiag{Engine: r.currentEngine, Interface: r.tunnelInterface, Now: r.cfg.Now}
}

// diagLoop applies the saved log level and records events (F-017).
func (r *Runtime) diagLoop(ctx context.Context) {
	if st, err := r.currentSettings(); err == nil {
		if l, err := ParseLogLevel(st.tunnel().LogLevel); err == nil {
			LogLevel.Set(l)
		}
	}
	every := diagEvery
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < every {
		every = r.cfg.PollInterval
	}
	w := &EventWatcher{Log: r.eventLog(), Now: r.cfg.Now}
	r.spawn(func() { r.observer().Run(ctx) }) // security events and audit log (#187, #188)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		w.Observe(r.currentEngine())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// captiveAlertLocked reports a captive portal the engine found (F-018).
// Called with r.mu held.
func (r *Runtime) captiveAlertLocked() (panel.HealthAlert, bool) {
	if r.engine == nil {
		return panel.HealthAlert{}, false
	}
	cp := r.engine.CaptivePortal()
	if !cp.Detected {
		return panel.HealthAlert{}, false
	}
	msg := "Bu ağ bir giriş sayfası (captive portal) bekliyor; tünel bu sayfayı gizliyor. Kill switch açıksa Çıkış düğümü kartındaki \"Giriş sayfasına izin ver\" ile ağ geçidine birkaç dakikalık izin açıp tarayıcıda oturum açın; izin kendiliğinden kapanır."
	if cp.Location != "" {
		msg += " Giriş sayfası: " + cp.Location
	}
	return panel.HealthAlert{Code: panel.HealthCaptivePortal, Level: panel.LevelWarning, Message: msg}, true
}

// memberView returns this computer's document and its own entry, also
// while the tunnel is down.
func (r *Runtime) memberView() (*trust.Document, trust.Device, error) {
	store, err := member.Open(r.path(DeviceDir))
	if err != nil {
		return nil, trust.Device{}, errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	doc := store.Document()
	secrets, err := readSecrets(r.path(DeviceDir, deviceKeyFile))
	if err != nil {
		return doc, trust.Device{}, err
	}
	self, err := selfDevice(doc, secrets)
	return doc, self, err
}

// DiagStatus implements panel.Diagnostics (F-191).
func (r *Runtime) DiagStatus() (panel.DiagStatus, error) {
	out, err := r.engineDiag().BaseStatus()
	if err != nil {
		return out, err
	}
	st := r.Status()
	out.Mode, out.Health = st.Mode, st.Health
	if ds := st.Device; ds != nil {
		out.Connected = ds.Connected
		if out.DocumentVersion == 0 {
			out.DocumentVersion = ds.DocumentVersion
		}
	}
	if out.Self == nil {
		if doc, self, err := r.memberView(); err == nil {
			out.Self = SelfOf(doc, self)
		}
	}
	return out, nil
}

// DiagNetCheck implements panel.Diagnostics (F-015).
func (r *Runtime) DiagNetCheck(ctx context.Context) (node.NetReport, error) {
	return r.engineDiag().DiagNetCheck(ctx)
}

// DiagPaths implements panel.Diagnostics (F-016).
func (r *Runtime) DiagPaths() ([]node.PeerPath, error) { return r.engineDiag().DiagPaths() }

// DiagReconnect implements panel.Diagnostics (F-016).
func (r *Runtime) DiagReconnect() error {
	if err := r.engineDiag().DiagReconnect(); err != nil {
		return err
	}
	r.logger.Info("reconnect requested")
	return nil
}

// DiagRelayTest implements panel.Diagnostics (F-016).
func (r *Runtime) DiagRelayTest(ctx context.Context, peer string) (time.Duration, error) {
	return r.engineDiag().DiagRelayTest(ctx, peer)
}

// DiagPing implements panel.Diagnostics (F-014).
func (r *Runtime) DiagPing(ctx context.Context, peer string) (panel.PingResult, error) {
	return r.engineDiag().DiagPing(ctx, peer)
}

// DiagDNSQuery implements panel.Diagnostics (F-057).
func (r *Runtime) DiagDNSQuery(ctx context.Context, name string) (panel.DNSQueryResult, error) {
	return r.engineDiag().DiagDNSQuery(ctx, name)
}

// DiagWireGuard implements panel.Diagnostics (F-208).
func (r *Runtime) DiagWireGuard() (panel.WGShow, error) { return r.engineDiag().DiagWireGuard() }

// DiagEvents implements panel.Diagnostics (F-017).
func (r *Runtime) DiagEvents() []panel.DiagEvent { return r.eventLog().List() }

// DiagWhois implements panel.Diagnostics (F-110); it works from the
// document while the tunnel is down.
func (r *Runtime) DiagWhois(q string) (panel.WhoisResult, error) {
	if r.currentEngine() != nil {
		return r.engineDiag().DiagWhois(q)
	}
	doc, self, err := r.memberView()
	if err != nil {
		return panel.WhoisResult{}, err
	}
	return Whois(doc, self, q, nil, r.cfg.Now())
}

// DiagDNS implements panel.Diagnostics (F-057).
func (r *Runtime) DiagDNS() (panel.DNSStatus, error) {
	doc, _, err := r.memberView()
	if doc == nil {
		return panel.DNSStatus{}, err
	}
	st, _ := r.currentSettings()
	out := panel.DNSStatus{Schema: panel.DiagSchema, Domain: doc.DNSDomain, Resolver: doc.DNSResolverIPv4().String(),
		MagicDNSAllDevices: st.tunnel().MagicDNSAllDevices, NetworkDNSAccepted: !st.IgnoreNetworkDNS,
		Nameservers: []string{}, Split: []panel.SplitDNSInfo{}}
	r.mu.Lock()
	out.MagicDNSError, out.NetworkDNSActive, out.NetworkDNSError = r.dnsErr, r.netDNSActive, r.netDNSErr
	r.mu.Unlock()
	if d := doc.DNS; d != nil {
		for _, a := range d.Nameservers {
			out.Nameservers = append(out.Nameservers, a.String())
		}
		for _, s := range d.Split {
			info := panel.SplitDNSInfo{Domain: s.Domain, Nameservers: []string{}}
			for _, a := range s.Nameservers {
				info.Nameservers = append(info.Nameservers, a.String())
			}
			out.Split = append(out.Split, info)
		}
	}
	return out, nil
}

// DiagPacketTrace implements panel.Diagnostics (F-187). The owner's own
// document is used when this computer holds the network, since it may be
// newer than the member copy.
func (r *Runtime) DiagPacketTrace(req panel.TraceRequest) (panel.TraceResult, error) {
	var doc *trust.Document
	r.mu.Lock()
	n := r.network
	r.mu.Unlock()
	if n != nil {
		if d, err := n.Document(); err == nil {
			doc = d
		}
	}
	memberDoc, self, err := r.memberView()
	if doc == nil {
		doc = memberDoc
	}
	if doc == nil {
		return panel.TraceResult{}, err
	}
	st, _ := r.currentSettings()
	return TracePacket(doc, self.Name, st.Shields, req)
}

// DiagHealth implements panel.Diagnostics (F-192).
func (r *Runtime) DiagHealth() panel.HealthReport {
	return HealthOf(r.Status())
}

// HealthOf derives liveness and readiness from the service status.
func HealthOf(st panel.AppStatus) panel.HealthReport {
	h := panel.HealthReport{Schema: panel.DiagSchema, Live: true, Ready: true, Reasons: []string{}, Alerts: st.Health}
	if h.Alerts == nil {
		h.Alerts = []panel.HealthAlert{}
	}
	notReady := func(why string) {
		h.Ready = false
		h.Reasons = append(h.Reasons, why)
	}
	switch st.Mode {
	case panel.ModeSetup:
		notReady("kurulum tamamlanmadı: bu bilgisayar bir ağa bağlı değil")
	case panel.ModeJoining:
		notReady("ağa katılım sürüyor")
	}
	if ds := st.Device; ds != nil {
		switch {
		case ds.Removed:
			notReady("bu bilgisayar ağdan çıkarılmış")
		case !ds.Connected:
			notReady("bağlantı kapalı")
		case !ds.Running:
			notReady("tünel çalışmıyor")
		case ds.LastSyncError != "":
			notReady("koordinatöre ulaşılamıyor")
		case ds.LastSync == nil:
			notReady("koordinatörle henüz eşitlenilmedi")
		}
	}
	if c := st.Coordinator; c != nil && !c.Running && c.Error != "" {
		notReady("bu bilgisayardaki koordinatör çalışmıyor")
	}
	return h
}

// DiagLogLevel implements panel.Diagnostics (F-188).
func (r *Runtime) DiagLogLevel() string { return LevelName(LogLevel.Level()) }

// DiagSetLogLevel implements panel.Diagnostics: the level changes at once
// and is kept across restarts.
func (r *Runtime) DiagSetLogLevel(level string) error {
	l, err := ParseLogLevel(level)
	if err != nil {
		return err
	}
	if err := r.updateSettings(func(st *settings) (bool, error) {
		t := st.tunnel()
		t.LogLevel = LevelName(l)
		st.Tunnel = &t
		return true, nil
	}); err != nil {
		return err
	}
	LogLevel.Set(l)
	r.auditLocal("log_level_changed", "Günlük seviyesi "+LevelName(l)+" yapıldı.") // #187
	return nil
}
