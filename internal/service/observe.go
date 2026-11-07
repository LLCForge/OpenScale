package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// Local observability of a running tunnel (ADR-0105): the refused
// connection log, Prometheus text metrics, the event stream, the hash
// chained security audit log, the diagnostics bundle, packet capture and
// profiling. Everything is served on loopback only and nothing is sent
// anywhere (ADR-0008).

const (
	// observeFile keeps the switches that survive a restart.
	observeFile    = "observe.json"
	maxObserveFile = 4 << 10
	// profilingFor is how long profiling stays on.
	profilingFor = time.Hour
	// observeEvery is how often the security watcher looks.
	observeEvery = 5 * time.Second
)

// ObserverConfig configures an Observer.
type ObserverConfig struct {
	// Dir holds the audit log and the saved switches.
	Dir string
	// Engine returns the running engine, nil while the tunnel is down.
	Engine func() *node.Engine
	Now    func() time.Time
	Logger *slog.Logger
	// Status, when set, is the service status (kill switch, health).
	Status func() panel.AppStatus
	// Shields reports whether this device's shields are on.
	Shields func() bool
	// BundleExtra adds files to the diagnostics bundle (settings, logs).
	BundleExtra func(ctx context.Context) []panel.BundleFile
	// Interface returns the tunnel interface name.
	Interface func() string
}

// observeSaved is observeFile.
type observeSaved struct {
	Metrics bool `json:"metrics"`
	// Notifications is a pointer so a missing value means "on".
	Notifications *bool `json:"notifications,omitempty"`
}

// Observer implements panel.Observability for one tunnel.
type Observer struct {
	cfg   ObserverConfig
	bus   *EventBus
	start time.Time

	auditMu  sync.Mutex
	auditLog *audit.Log
	auditErr string

	mu        sync.Mutex
	saved     observeSaved
	profUntil time.Time
	capturing bool

	// hist is the traffic and resource history (#505, #516,
	// observe_history.go).
	hist historyState
}

var _ panel.Observability = (*Observer)(nil)

// NewObserver opens the audit log and the saved switches. A broken audit
// log does not stop the tunnel; the error is shown instead.
func NewObserver(cfg ObserverConfig) *Observer {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Engine == nil {
		cfg.Engine = func() *node.Engine { return nil }
	}
	o := &Observer{cfg: cfg, bus: NewEventBus(), start: cfg.Now()}
	if cfg.Dir != "" {
		if data, err := securefile.ReadPrivate(filepath.Join(cfg.Dir, observeFile), maxObserveFile); err == nil {
			_ = json.Unmarshal(data, &o.saved)
		} else if !errors.Is(err, fs.ErrNotExist) {
			cfg.Logger.Warn("observability switches unreadable", "error", err.Error())
		}
		l, err := audit.Open(cfg.Dir, cfg.Now)
		if err != nil {
			o.auditErr = err.Error()
			cfg.Logger.Warn("audit log unavailable", "error", err.Error())
		} else {
			o.auditLog = l
		}
	} else {
		o.auditErr = "denetim kaydı için durum klasörü yok"
	}
	return o
}

// Bus returns the event stream.
func (o *Observer) Bus() *EventBus { return o.bus }

func (o *Observer) notificationsOn() bool {
	return o.saved.Notifications == nil || *o.saved.Notifications
}

// PublishDiag forwards a connection event of the event list (F-017).
func (o *Observer) PublishDiag(ev panel.DiagEvent) {
	sev := audit.SeverityInfo
	switch ev.Kind {
	case panel.EventTunnelDown, panel.EventSyncLost, panel.EventCaptive:
		sev = audit.SeverityWarning
	}
	o.bus.Publish(panel.StreamEvent{At: ev.At, Kind: ev.Kind, Category: panel.CategoryConnection, Severity: sev, Peer: ev.Peer, Message: ev.Message})
}

// Security records a security event in the audit log and publishes it.
// notify marks it for a desktop notification.
func (o *Observer) Security(kind, severity, category, peer, message string, notify bool) {
	msg := audit.Clean(message)
	o.auditMu.Lock()
	l := o.auditLog
	o.auditMu.Unlock()
	if l != nil {
		if err := l.Append(kind, severity, msg); err != nil {
			o.cfg.Logger.Warn("audit record not written", "kind", kind, "error", err.Error())
		}
	}
	o.bus.Publish(panel.StreamEvent{At: o.cfg.Now(), Kind: kind, Category: category, Severity: severity, Peer: peer, Message: msg, Notify: notify})
}

// EventsSince implements panel.Observability.
func (o *Observer) EventsSince(ctx context.Context, since uint64, wait time.Duration) panel.EventStreamReply {
	evs, next := o.bus.Since(ctx, since, wait)
	o.mu.Lock()
	on := o.notificationsOn()
	o.mu.Unlock()
	return panel.EventStreamReply{Schema: panel.DiagSchema, Events: evs, Next: next, Notifications: on}
}

// AuditTail implements panel.Observability.
func (o *Observer) AuditTail(n int) (panel.AuditReply, error) {
	rep := panel.AuditReply{Schema: panel.DiagSchema, Records: []audit.Record{}}
	if o.cfg.Dir == "" {
		return rep, errors.New(o.auditErr)
	}
	recs, err := audit.Tail(o.cfg.Dir, n)
	if err != nil {
		return rep, err
	}
	if recs != nil {
		rep.Records = recs
	}
	rep.Verify, err = o.AuditVerify()
	return rep, err
}

// AuditVerify implements panel.Observability.
func (o *Observer) AuditVerify() (audit.Report, error) {
	if o.cfg.Dir == "" {
		return audit.Report{}, errors.New(o.auditErr)
	}
	rep, err := audit.Verify(o.cfg.Dir)
	if err == nil && o.auditErr != "" {
		rep.OK = false
		rep.Problems = append(rep.Problems, "denetim kaydı açılamadı: "+o.auditErr)
	}
	return rep, err
}

// ObservePrefs implements panel.Observability.
func (o *Observer) ObservePrefs() panel.ObservePrefs {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.prefsLocked()
}

func (o *Observer) prefsLocked() panel.ObservePrefs {
	p := panel.ObservePrefs{Schema: panel.DiagSchema, Metrics: o.saved.Metrics, Notifications: o.notificationsOn()}
	if until := o.profUntil; o.cfg.Now().Before(until) {
		p.Profiling = true
		p.ProfilingUntil = &until
	}
	return p
}

// SetObservePrefs implements panel.Observability.
func (o *Observer) SetObservePrefs(c panel.ObservePrefsChange) (panel.ObservePrefs, error) {
	o.mu.Lock()
	saved := o.saved
	if c.Metrics != nil {
		saved.Metrics = *c.Metrics
	}
	if c.Notifications != nil {
		on := *c.Notifications
		saved.Notifications = &on
	}
	if c.Metrics != nil || c.Notifications != nil {
		if o.cfg.Dir != "" {
			data, err := json.Marshal(saved)
			if err == nil {
				err = securefile.Replace(filepath.Join(o.cfg.Dir, observeFile), data)
			}
			if err != nil {
				o.mu.Unlock()
				return panel.ObservePrefs{}, err
			}
		}
	}
	metricsChanged := c.Metrics != nil && *c.Metrics != o.saved.Metrics
	o.saved = saved
	profChanged := false
	if c.Profiling != nil {
		wasOn := o.cfg.Now().Before(o.profUntil)
		if *c.Profiling {
			o.profUntil = o.cfg.Now().Add(profilingFor)
		} else {
			o.profUntil = time.Time{}
		}
		profChanged = wasOn != *c.Profiling
	}
	p := o.prefsLocked()
	o.mu.Unlock()
	if metricsChanged {
		state := "kapatıldı"
		if p.Metrics {
			state = "açıldı"
		}
		o.Security("metrics_endpoint", audit.SeverityInfo, panel.CategorySecurity, "", "Yerel metrik uç noktası "+state+".", false)
	}
	if profChanged {
		state := "kapatıldı"
		if p.Profiling {
			state = "bir saatliğine açıldı"
		}
		o.Security("profiling", audit.SeverityWarning, panel.CategorySecurity, "", "Profilleme "+state+".", false)
	}
	return p, nil
}

func (o *Observer) metricsOn() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.saved.Metrics
}

func (o *Observer) profilingOn() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cfg.Now().Before(o.profUntil)
}

// Run watches the tunnel for security events until ctx ends.
func (o *Observer) Run(ctx context.Context) {
	w := &securityWatch{o: o}
	t := time.NewTicker(observeEvery)
	defer t.Stop()
	// The history is saved once more on the way out (#505).
	defer func() { o.saveHistory(o.cfg.Now(), true) }()
	for {
		if ctx.Err() != nil {
			return
		}
		w.look()
		o.sampleHistories(o.cfg.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// writeTo is a small helper so the capture and profile code can fail
// before the first byte without sending a partial response.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
