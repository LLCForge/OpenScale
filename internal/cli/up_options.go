package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
)

// Connection options of "openscale up" that map to node.Config (F-002,
// F-012, F-018, F-024, F-069, F-084) and its local diagnostics API.

type upNetFlags struct {
	staticEndpoints *listFlag
	skipIfaces      *listFlag
	hideLocal       *bool
	disableOffload  *bool
	magicAll        *bool
	noCaptive       *bool
	tcpTimeout      *time.Duration
	udpTimeout      *time.Duration
	icmpTimeout     *time.Duration
	otherTimeout    *time.Duration
	maxFlows        *int
	maxFragments    *int
	localAPI        *bool
}

func addUpNetFlags(fs *flag.FlagSet) upNetFlags {
	f := upNetFlags{staticEndpoints: &listFlag{}, skipIfaces: &listFlag{}}
	fs.Var(f.staticEndpoints, "static-endpoint", "bu cihaza ulaşılabilen sabit adres, IP:port veya dinamik DNS için ad:port (port yönlendirme, sabit IP); tekrarlanabilir veya virgülle")
	fs.Var(f.skipIfaces, "candidate-skip-interfaces", "adresleri koordinatöre hiç bildirilmeyecek arayüz önekleri, virgülle (ör. docker,veth)")
	f.hideLocal = fs.Bool("hide-local-candidates", false, "yerel ağ ve IPv6 arayüz adreslerini koordinatöre bildirme (yalnızca statik ve koordinatörün gördüğü adres)")
	f.disableOffload = fs.Bool("disable-udp-offload", false, "Linux'ta UDP GSO/GRO ve TUN offload'u kapat (sorunlu sürücü, konteyner veya paket yakalama için)")
	f.magicAll = fs.Bool("magicdns-all-devices", false, "MagicDNS bütün cihaz adlarını yanıtlasın (varsayılan: yalnızca tünel kurulanlar)")
	f.noCaptive = fs.Bool("disable-captive-check", false, "giriş sayfası (captive portal) denetimini kapat")
	f.tcpTimeout = fs.Duration("conntrack-tcp-timeout", 0, "bağlantı takibi: TCP zaman aşımı (0: varsayılan; 30s-24h)")
	f.udpTimeout = fs.Duration("conntrack-udp-timeout", 0, "bağlantı takibi: UDP zaman aşımı (0: varsayılan; 10s-1h)")
	f.icmpTimeout = fs.Duration("conntrack-icmp-timeout", 0, "bağlantı takibi: ICMP zaman aşımı (0: varsayılan; 5s-10m)")
	f.otherTimeout = fs.Duration("conntrack-other-timeout", 0, "bağlantı takibi: diğer protokoller (0: varsayılan; 10s-1h)")
	f.maxFlows = fs.Int("conntrack-max-flows", 0, "bağlantı takibi: en fazla akış (0: varsayılan; 1024-1048576)")
	f.maxFragments = fs.Int("conntrack-max-fragments", 0, "bağlantı takibi: en fazla bekleyen parça (0: varsayılan; 64-65536)")
	f.localAPI = fs.Bool("local-api", true, "status/ping/netcheck gibi komutlar için yalnızca bu kullanıcıya açık yerel API (127.0.0.1)")
	return f
}

// upNetOptions are the checked values.
type upNetOptions struct {
	staticEndpoints []netip.AddrPort
	staticNames     []string
	skipIfaces      []string
	hideLocal       bool
	disableOffload  bool
	magicAll        bool
	noCaptive       bool
	connTrack       filter.Limits
	localAPI        bool
}

func (f upNetFlags) resolve() (upNetOptions, error) {
	o := upNetOptions{hideLocal: *f.hideLocal, disableOffload: *f.disableOffload, magicAll: *f.magicAll,
		noCaptive: *f.noCaptive, localAPI: *f.localAPI, skipIfaces: f.skipIfaces.vals}
	eps, names, err := service.SplitStaticEndpoints(f.staticEndpoints.vals) // #387
	if err != nil {
		return o, usageError("--static-endpoint: %v", err)
	}
	o.staticEndpoints, o.staticNames = eps, names
	if err := service.ValidSkipInterfaces(o.skipIfaces); err != nil {
		return o, usageError("--candidate-skip-interfaces: %v", err)
	}
	o.connTrack = filter.Limits{TCPTimeout: *f.tcpTimeout, UDPTimeout: *f.udpTimeout, ICMPTimeout: *f.icmpTimeout,
		OtherTimeout: *f.otherTimeout, MaxFlows: *f.maxFlows, MaxFragments: *f.maxFragments}
	if err := service.ValidConnTrack(o.connTrack); err != nil {
		return o, usageError("bağlantı takibi: %v", err)
	}
	return o, nil
}

func (o upNetOptions) apply(cfg node.Config) node.Config {
	cfg.StaticEndpoints = o.staticEndpoints
	cfg.StaticEndpointNames = o.staticNames
	cfg.CandidateSkipInterfaces = o.skipIfaces
	cfg.HideLocalCandidates = o.hideLocal
	cfg.DisableUDPOffload = o.disableOffload
	cfg.MagicDNSAllDevices = o.magicAll
	cfg.DisableCaptiveCheck = o.noCaptive
	cfg.ConnTrack = o.connTrack
	// "openscale up" installs no kill switch; captive portal checks then
	// run only while an exit node is in use.
	cfg.KillSwitchActive = func() bool { return false }
	return cfg
}

// newLeveledLogger is newLogger with a level "openscale log level" can
// change while the tunnel runs.
func newLeveledLogger(env *Env, debug bool) (*slog.Logger, *slog.LevelVar) {
	level := new(slog.LevelVar)
	if debug {
		level.Set(slog.LevelDebug)
	}
	return maskedJSONLogger(env.Stderr, level), level
}

// upDiag is the diagnostics API of a foreground tunnel.
type upDiag struct {
	*service.EngineDiag
	engine *node.Engine
	level  *slog.LevelVar
	events *service.EventLog
	// obs is the observability of ADR-0105 (up_observe.go).
	obs *service.Observer
}

var _ panel.Diagnostics = (*upDiag)(nil)

func (u *upDiag) DiagStatus() (panel.DiagStatus, error) {
	st, err := u.BaseStatus()
	if err != nil {
		return st, err
	}
	st.Mode, st.Connected = panel.ModeMember, true
	return st, nil
}

func (u *upDiag) DiagDNS() (panel.DNSStatus, error) {
	doc := u.engine.Document()
	out := panel.DNSStatus{Schema: panel.DiagSchema, Domain: doc.DNSDomain, Resolver: doc.DNSResolverIPv4().String(),
		NetworkDNSAccepted: true, Nameservers: []string{}, Split: []panel.SplitDNSInfo{}}
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

func (u *upDiag) DiagEvents() []panel.DiagEvent { return u.events.List() }

func (u *upDiag) DiagPacketTrace(req panel.TraceRequest) (panel.TraceResult, error) {
	self, err := u.engine.Self()
	if err != nil {
		return panel.TraceResult{}, err
	}
	return service.TracePacket(u.engine.Document(), self.Name, false, req)
}

func (u *upDiag) DiagHealth() panel.HealthReport {
	h := panel.HealthReport{Schema: panel.DiagSchema, Live: true, Ready: true, Reasons: []string{}, Alerts: []panel.HealthAlert{}}
	st := u.engine.Status()
	switch {
	case st.LastSyncError != "":
		h.Ready = false
		h.Reasons = append(h.Reasons, "koordinatöre ulaşılamıyor")
	case st.LastSync.IsZero():
		h.Ready = false
		h.Reasons = append(h.Reasons, "koordinatörle henüz eşitlenilmedi")
	}
	if cp := u.engine.CaptivePortal(); cp.Detected {
		h.Alerts = append(h.Alerts, panel.HealthAlert{Code: panel.HealthCaptivePortal, Level: panel.LevelWarning,
			Message: "Bu ağ bir giriş sayfası (captive portal) bekliyor."})
	}
	return h
}

func (u *upDiag) DiagLogLevel() string { return service.LevelName(u.level.Level()) }

func (u *upDiag) DiagSetLogLevel(level string) error {
	l, err := service.ParseLogLevel(level)
	if err != nil {
		return err
	}
	u.level.Set(l)
	return nil
}

func (u *upDiag) DiagPrefs() ([]panel.Pref, error) { return nil, panel.ErrNeedsService }

func (u *upDiag) DiagSetPrefs(map[string]string) ([]panel.Pref, error) {
	return nil, errors.New("ön planda çalışan tünelin ayarları bayraklarla verilir (openscale up -h); kalıcı ayarlar yalnızca OpenScale servisinde var")
}

// localTokenBytes is the size of the local API token.
const localTokenBytes = 32

// startUpLocalAPI serves the diagnostics API of a foreground tunnel and
// writes where it is to the state directory (readable only by this user).
// The returned function stops it and removes the file.
func startUpLocalAPI(env *Env, dir string, engine *node.Engine, iface string, level *slog.LevelVar, logger *slog.Logger) (func(), error) {
	b := make([]byte, localTokenBytes)
	if _, err := io.ReadFull(env.Random, b); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	ln, err := panel.Listen(0)
	if err != nil {
		return nil, err
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("local API listener is not TCP")
	}
	data, err := json.Marshal(localAPIInfo{Port: tcp.Port, Token: token})
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	path := filepath.Join(dir, localAPIFile)
	if err := securefile.Replace(path, data); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("yerel API dosyası yazılamadı: %w", err)
	}
	events := service.NewEventLog(service.MaxEvents)
	obs := service.NewObserver(service.ObserverConfig{Dir: dir, Engine: func() *node.Engine { return engine },
		Now: env.Now, Logger: logger, Interface: func() string { return iface }})
	events.SetOnAdd(obs.PublishDiag)
	d := &upDiag{
		EngineDiag: &service.EngineDiag{Engine: func() *node.Engine { return engine }, Interface: func() string { return iface }, Now: env.Now},
		engine:     engine, level: level, events: events, obs: obs,
	}
	ctx, cancel := context.WithCancel(envContext(env))
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Root, this user and the openscale group (ADR-0050).
		check := peercred.Policy{Admins: true, SameUser: true, Group: operatorGroup}.Check
		if err := panel.ServeLocalAPI(ctx, ln, panel.LocalAPIConfig{Diag: d, Token: token, Logger: logger, PeerCheck: check}); err != nil {
			logger.Warn("local API stopped", "error", err.Error())
		}
	}()
	go obs.Run(ctx)
	go func() {
		w := &service.EventWatcher{Log: events, Now: env.Now}
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			w.Observe(engine)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
		_ = os.Remove(path)
	}, nil
}
