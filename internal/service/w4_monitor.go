package service

// Monitoring wired into the desktop service (ADR-0215, ADR-0216, W4):
// service probes, watched devices, joined/left devices, disk and battery,
// link quality history, notification channels with the weekly report,
// the speed test button, wake and network drives, the unknown LAN device
// alarm (#730) and the open port audit (#731). Events go to the service's
// event list (the panel's "Olaylar") and to the owner's notification
// channels. Nothing here stores addresses in events; MAC addresses never
// leave netwatch except as keyed digests.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/healthmon"
	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/netdrive"
	"github.com/openscale/openscale/internal/netwatch"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/notify"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

// Monitoring files in the data directory.
const (
	MonitorFile     = "monitor.json"
	qualityFile     = "quality-history.json"
	weeklyStampFile = "weekly-report.json"
	lanWatchFile    = "lan-devices.json"
	auditStateFile  = "port-audit.json"
)

// Monitoring cadence.
const (
	w4Step           = 30 * time.Second
	w4QualitySave    = 15 * time.Minute
	w4LANEvery       = 5 * time.Minute
	w4AuditEvery     = 24 * time.Hour
	w4BlocklistEvery = 24 * time.Hour
	w4MaxDrives      = 32
)

// Event kinds the monitor adds to the event list beside healthmon's.
const (
	EventLANDevice  = "lan_device_new"
	EventPortOpen   = "port_open"
	EventPortClosed = "port_closed"
	EventIDSAlert   = "ids_alert"
)

// MonitorConfig is monitor.json: what the owner chose to watch.
type MonitorConfig struct {
	// Services are the owner's HTTP and TCP probes.
	Services []healthmon.Target `json:"services,omitempty"`
	// ExtraPrefixes are private networks behind a subnet router that
	// probes may reach besides the tunnel.
	ExtraPrefixes []netip.Prefix `json:"extra_prefixes,omitempty"`
	// Watched are the devices whose going offline is reported.
	Watched []string `json:"watched,omitempty"`
	// Drives are the owner's network drives.
	Drives []netdrive.Mount `json:"drives,omitempty"`
	// LANWatch turns on the unknown LAN device alarm on this computer.
	LANWatch bool `json:"lan_watch,omitempty"`
	// AuditPorts are the owner-approved ports of the open port audit,
	// run by an exit node against its devices' public addresses.
	AuditPorts []uint16 `json:"audit_ports,omitempty"`
}

// Validate checks the configuration (without the document's scope).
func (c MonitorConfig) Validate() error {
	if len(c.Watched) > 1024 {
		return errors.New("en fazla 1024 cihaz izlenebilir")
	}
	if len(c.Drives) > w4MaxDrives {
		return fmt.Errorf("en fazla %d ağ sürücüsü olabilir", w4MaxDrives)
	}
	seen := map[string]bool{}
	for _, d := range c.Drives {
		if d.Name == "" || seen[d.Name] {
			return fmt.Errorf("sürücü adı boş veya tekrarlı: %q", d.Name)
		}
		seen[d.Name] = true
	}
	if len(c.AuditPorts) > 0 {
		if err := (netwatch.AuditConfig{Ports: c.AuditPorts}).Validate(); err != nil {
			return err
		}
	}
	return nil
}

// monitorSnapshot is what one tick sees of the tunnel.
type monitorSnapshot struct {
	doc      *trust.Document
	self     trust.Device
	lastSeen map[string]time.Time
	rtt      map[string]time.Duration
}

// w4Monitor is the monitoring state. Its inputs are functions so the
// whole loop runs in tests without a tunnel.
type w4Monitor struct {
	dir       string
	now       func() time.Time
	snapshot  func() (monitorSnapshot, bool)
	inventory func() map[string]sysinfo.Info
	event     func(panel.DiagEvent)
	wake      func(ctx context.Context, device string) error
	// deliver shows desktop notifications; nil leaves desktop channels
	// to the computer the service runs on.
	deliver func(ctx context.Context, device string, m notify.Message) error
	// mapDrive and unmapDrive are netdrive.MapDrive/UnmapDrive (tests
	// replace them so no drive is ever mounted).
	mapDrive   func(ctx context.Context, doc *trust.Document, m netdrive.Mount) error
	unmapDrive func(ctx context.Context, doc *trust.Document, m netdrive.Mount) error
	// neighbors reads the LAN neighbour table.
	neighbors func() []netwatch.Neighbor
	// audit runs the port audit (tests point it at loopback).
	audit func(ctx context.Context, cfg netwatch.AuditConfig, t []netwatch.AuditTarget) ([]netwatch.AuditFinding, error)
	// updateLists refreshes an exit node's block lists.
	updateLists func(ctx context.Context, doc *trust.Document) error

	mu          sync.Mutex
	cfg         MonitorConfig
	cfgStamp    time.Time
	notifyCfg   notify.Config
	notifyStamp time.Time
	dispatcher  *notify.Dispatcher
	presence    *healthmon.Presence
	services    *healthmon.Monitor
	servicesKey string
	resources   *healthmon.ResourceWatcher
	quality     *healthmon.Quality
	speed       *healthmon.SpeedButton
	lastDoc     *trust.Document
	lastSeen    map[string]time.Time
	incidents   map[string]int
	lastReport  time.Time
	qualitySave time.Time
	lan         *netwatch.LANWatch
	lanAt       time.Time
	auditAt     time.Time
	auditPrev   []netwatch.AuditFinding
	listsAt     time.Time
	ids         *netwatch.Detector
	shortKey    string
}

func newW4Monitor(dir string, now func() time.Time) *w4Monitor {
	m := &w4Monitor{
		dir: dir, now: now,
		mapDrive: netdrive.MapDrive, unmapDrive: netdrive.UnmapDrive,
		neighbors: netwatch.Neighbors, audit: netwatch.Audit,
		quality: healthmon.NewQuality(), speed: healthmon.NewSpeedButton(),
		incidents: map[string]int{}, lastSeen: map[string]time.Time{},
		ids: netwatch.NewDetector(netwatch.IDSConfig{}),
	}
	m.speed.Now = now
	m.resources, _ = healthmon.NewResourceWatcher(healthmon.DefaultThresholds)
	m.presence = healthmon.NewPresence(nil, 0)
	if data, err := securefile.ReadLimited(m.path(qualityFile), 32<<20); err == nil {
		if q, err := healthmon.DecodeQuality(data); err == nil {
			m.quality = q
		}
	}
	var stamp struct {
		Last time.Time `json:"last"`
	}
	if loadJSON(m.path(weeklyStampFile), &stamp) == nil {
		m.lastReport = stamp.Last
	}
	return m
}

func (m *w4Monitor) path(name string) string { return m.dir + string(os.PathSeparator) + name }

// LoadMonitorConfig reads monitor.json; a missing file is an empty
// configuration.
func LoadMonitorConfig(dir string) (MonitorConfig, error) {
	var c MonitorConfig
	if err := loadJSON(dir+string(os.PathSeparator)+MonitorFile, &c); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return MonitorConfig{}, nil
		}
		return MonitorConfig{}, fmt.Errorf("izleme yapılandırması okunamadı: %w", err)
	}
	return c, c.Validate()
}

// SaveMonitorConfig writes monitor.json as a private file.
func SaveMonitorConfig(dir string, c MonitorConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return saveJSON(dir+string(os.PathSeparator)+MonitorFile, c)
}

func modTime(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// reload re-reads monitor.json and notify.json when they changed.
// Called with m.mu held.
func (m *w4Monitor) reloadLocked(doc *trust.Document) {
	if t := modTime(m.path(MonitorFile)); !t.Equal(m.cfgStamp) || m.presence == nil {
		m.cfgStamp = t
		if c, err := LoadMonitorConfig(m.dir); err == nil {
			m.cfg = c
		} else {
			m.emitLocked(panel.DiagEvent{Kind: healthmon.KindServiceDown, Message: err.Error()})
		}
		m.presence = healthmon.NewPresence(m.cfg.Watched, 0)
		m.servicesKey = ""
	}
	if t := modTime(m.path(notify.ConfigFile)); !t.Equal(m.notifyStamp) {
		m.notifyStamp = t
		m.dispatcher = nil
		c, err := notify.Load(m.path(notify.ConfigFile))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				m.emitLocked(panel.DiagEvent{Kind: "notify_error", Message: "Bildirim ayarları okunamadı."})
			}
			c = notify.Config{Schema: 1}
		}
		m.notifyCfg = c
		if d, err := c.Build(m.desktopDeliver); err == nil {
			m.dispatcher = d
		}
	}
	// Short names (#762): shortnames.json → MagicDNS, checked against
	// the signed document so a name never shadows a device.
	if sk := fmt.Sprintf("%d|%v", docVersion(doc), modTime(m.path(netdrive.ShortNamesFile))); doc != nil && sk != m.shortKey {
		m.shortKey = sk
		table := map[string]string{}
		if t, err := netdrive.LoadShortNames(m.path(netdrive.ShortNamesFile)); err == nil && t.Validate(doc) == nil {
			for _, e := range t.Entries {
				table[e.Name] = e.Device
			}
		}
		magicdns.SetShortNames(table)
	}
	key := fmt.Sprintf("%d|%v", docVersion(doc), m.cfgStamp)
	if doc != nil && key != m.servicesKey {
		m.servicesKey = key
		m.services = nil
		if len(m.cfg.Services) > 0 {
			scope, err := healthmon.ScopeFromDocument(doc, m.cfg.ExtraPrefixes)
			if err == nil {
				targets := make([]healthmon.Target, 0, len(m.cfg.Services))
				for _, t := range m.cfg.Services {
					if t.Validate(scope) == nil {
						targets = append(targets, t)
					}
				}
				m.services, _ = healthmon.NewMonitor(&healthmon.Prober{Scope: scope}, targets)
			}
		}
	}
}

func docVersion(doc *trust.Document) uint64 {
	if doc == nil {
		return 0
	}
	return doc.Version
}

func (m *w4Monitor) desktopDeliver(ctx context.Context, device string, msg notify.Message) error {
	if m.deliver != nil {
		return m.deliver(ctx, device, msg)
	}
	return notify.ShowLocal(ctx, msg)
}

// emitLocked records one event; m.mu is held.
func (m *w4Monitor) emitLocked(ev panel.DiagEvent) {
	if ev.At.IsZero() {
		ev.At = m.now()
	}
	if m.event != nil {
		m.event(ev)
	}
}

// health turns healthmon events into the event list and notifications.
func (m *w4Monitor) health(ctx context.Context, evs []healthmon.Event) {
	if len(evs) == 0 {
		return
	}
	m.mu.Lock()
	d := m.dispatcher
	for _, ev := range evs {
		m.incidents[ev.Kind]++
		m.emitLocked(panel.DiagEvent{At: ev.At, Kind: ev.Kind, Peer: ev.Subject, Message: ev.Title})
	}
	m.mu.Unlock()
	if d == nil {
		return
	}
	for _, ev := range evs {
		d.Notify(ctx, ev.Message())
	}
}

// alert reports a netwatch finding (no addresses in the event).
func (m *w4Monitor) alert(ctx context.Context, kind, subject, title string, p notify.Priority) {
	now := m.now()
	m.mu.Lock()
	m.incidents[kind]++
	m.emitLocked(panel.DiagEvent{At: now, Kind: kind, Peer: subject, Message: title})
	d := m.dispatcher
	m.mu.Unlock()
	if d != nil {
		d.Notify(ctx, notify.Message{Kind: kind, Subject: subject, Title: title, Priority: p, At: now})
	}
}

// tick runs one round of every watcher.
func (m *w4Monitor) tick(ctx context.Context) {
	now := m.now()
	snap, ok := m.snapshot()
	m.mu.Lock()
	var doc *trust.Document
	if ok {
		doc = snap.doc
	}
	m.reloadLocked(doc)
	presence, services, quality, d := m.presence, m.services, m.quality, m.dispatcher
	prev := m.lastDoc
	if ok {
		m.lastDoc = snap.doc
		for n, t := range snap.lastSeen {
			m.lastSeen[n] = t
		}
	}
	m.mu.Unlock()

	var evs []healthmon.Event
	if ok {
		if prev != nil && prev.Version != snap.doc.Version {
			evs = append(evs, healthmon.MemberChanges(prev, snap.doc, now)...)
		}
		evs = append(evs, presence.Observe(snap.lastSeen, now)...)
		for name, rtt := range snap.rtt {
			quality.Add(name, now, rtt, false)
		}
		for name, seen := range snap.lastSeen {
			if _, has := snap.rtt[name]; !has && now.Sub(seen) > onlineWindow && presence.Watched(name) {
				quality.Add(name, now, 0, true)
			}
		}
	}
	if services != nil {
		evs = append(evs, services.Tick(ctx, now)...)
	}
	if m.inventory != nil && m.resources != nil {
		inv := m.inventory()
		names := make([]string, 0, len(inv))
		for n := range inv {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if det := inv[n].Detail; det != nil {
				evs = append(evs, m.resources.Update(n, det, now)...)
			}
		}
	}
	m.health(ctx, evs)
	if d != nil {
		d.Flush(ctx, now)
	}
	m.weekly(ctx, now)
	m.saveQuality(now, false)
	if ok {
		m.lanWatch(ctx, now)
		m.portAudit(ctx, now, snap)
		m.blocklists(ctx, now, snap)
	}
}

func (m *w4Monitor) saveQuality(now time.Time, force bool) {
	m.mu.Lock()
	due := force || now.Sub(m.qualitySave) >= w4QualitySave
	if due {
		m.qualitySave = now
	}
	q := m.quality
	m.mu.Unlock()
	if !due || len(q.Devices()) == 0 {
		return
	}
	if data, err := q.Encode(); err == nil {
		_ = os.MkdirAll(m.dir, 0o700)
		_ = securefile.Replace(m.path(qualityFile), data)
	}
}

// weekly sends the weekly report when it is due.
func (m *w4Monitor) weekly(ctx context.Context, now time.Time) {
	m.mu.Lock()
	cfg, last, d := m.notifyCfg, m.lastReport, m.dispatcher
	m.mu.Unlock()
	if d == nil || !cfg.ReportDue(now, last) {
		return
	}
	w := m.buildWeekly(now)
	msg, err := w.Message()
	if err != nil {
		return
	}
	// The owner asked for the report: it must pass a channel's default
	// "normal and above" filter.
	if msg.Priority < notify.PriorityNormal {
		msg.Priority = notify.PriorityNormal
	}
	d.Notify(ctx, msg)
	m.mu.Lock()
	m.lastReport = now
	m.incidents = map[string]int{}
	m.mu.Unlock()
	if m.services != nil {
		m.services.Downtime(true)
	}
	_ = saveJSON(m.path(weeklyStampFile), struct {
		Last time.Time `json:"last"`
	}{now})
}

func (m *w4Monitor) buildWeekly(now time.Time) notify.Weekly {
	m.mu.Lock()
	in := notify.WeeklyInput{From: now.Add(-7 * 24 * time.Hour), To: now, Incidents: map[string]int{}}
	for k, v := range m.incidents {
		in.Incidents[k] = v
	}
	doc, services := m.lastDoc, m.services
	seen := make(map[string]time.Time, len(m.lastSeen))
	for k, v := range m.lastSeen {
		seen[k] = v
	}
	m.mu.Unlock()
	if services != nil {
		in.ServiceDowntime = services.Downtime(false)
	}
	if st := node.ExitExtensions(); st.Adblock != nil {
		in.Blocked = st.Adblock.Blocked
	}
	var inv map[string]sysinfo.Info
	if m.inventory != nil {
		inv = m.inventory()
	}
	if doc != nil {
		in.Network = doc.DNSDomain
		for _, dev := range doc.Devices {
			dw := notify.DeviceWeek{Name: dev.Name}
			if t, ok := seen[dev.Name]; ok {
				dw.Online = now.Sub(t) < onlineWindow
				if !dw.Online {
					dw.OfflineFor = now.Sub(t)
				}
			}
			if info, ok := inv[dev.Name]; ok {
				dw.Version, dw.Latest = info.Version, version.Version
			}
			in.Devices = append(in.Devices, dw)
		}
	}
	return notify.BuildWeekly(in, now)
}

// lanWatch runs the unknown LAN device alarm when the owner turned it on.
func (m *w4Monitor) lanWatch(ctx context.Context, now time.Time) {
	m.mu.Lock()
	on := m.cfg.LANWatch && now.Sub(m.lanAt) >= w4LANEvery
	if on {
		m.lanAt = now
	}
	m.mu.Unlock()
	if !on || m.neighbors == nil {
		return
	}
	m.mu.Lock()
	if m.lan == nil {
		w, err := netwatch.LoadLANWatch(m.path(lanWatchFile))
		if err != nil {
			w, err = netwatch.NewLANWatch()
		}
		if err != nil {
			m.mu.Unlock()
			return
		}
		m.lan = w
	}
	w := m.lan
	m.mu.Unlock()
	// An empty read (unsupported system, no LAN) must not end the
	// learning phase: the next real read would then alarm on everything.
	ns := m.neighbors()
	if len(ns) == 0 {
		return
	}
	for _, n := range w.Observe(ns, now) {
		m.alert(ctx, EventLANDevice, n.OUI, n.Message(), notify.PriorityNormal)
	}
	_ = w.Save(m.path(lanWatchFile))
}

// portAudit runs on an exit node: the devices' reported public addresses
// on the owner-approved ports, at most once a day.
func (m *w4Monitor) portAudit(ctx context.Context, now time.Time, snap monitorSnapshot) {
	m.mu.Lock()
	ports := slices.Clone(m.cfg.AuditPorts)
	if m.auditAt.IsZero() {
		var st struct {
			At       time.Time               `json:"at"`
			Findings []netwatch.AuditFinding `json:"findings"`
		}
		if loadJSON(m.path(auditStateFile), &st) == nil {
			m.auditAt, m.auditPrev = st.At, st.Findings
		}
	}
	due := len(ports) > 0 && snap.self.HasRole(trust.RoleExitNode) && netwatch.AuditDue(m.auditAt, now, w4AuditEvery)
	if due {
		m.auditAt = now
	}
	prev := m.auditPrev
	m.mu.Unlock()
	if !due || m.inventory == nil || m.audit == nil {
		return
	}
	public := map[string]string{}
	for n, info := range m.inventory() {
		if info.PublicIP != "" {
			public[n] = info.PublicIP
		}
	}
	found, err := m.audit(ctx, netwatch.AuditConfig{Ports: ports}, netwatch.TargetsFromReports(snap.doc, public))
	if err != nil {
		return
	}
	opened, closed := netwatch.AuditDiff(prev, found)
	for _, f := range opened {
		m.alert(ctx, EventPortOpen, f.Device, fmt.Sprintf("%s cihazının genel adresinde %d numaralı port internete açık.", f.Device, f.Port), notify.PriorityHigh)
	}
	for _, f := range closed {
		m.alert(ctx, EventPortClosed, f.Device, fmt.Sprintf("%s cihazında %d numaralı port artık kapalı.", f.Device, f.Port), notify.PriorityLow)
	}
	m.mu.Lock()
	m.auditPrev = found
	m.mu.Unlock()
	_ = saveJSON(m.path(auditStateFile), struct {
		At       time.Time               `json:"at"`
		Findings []netwatch.AuditFinding `json:"findings"`
	}{now, found})
}

// blocklists refreshes an exit node's signed block lists once a day
// (until now this happened only from the command line).
func (m *w4Monitor) blocklists(ctx context.Context, now time.Time, snap monitorSnapshot) {
	if m.updateLists == nil || !snap.self.HasRole(trust.RoleExitNode) || snap.doc.Blocking == nil || len(snap.doc.Blocking.Subscriptions) == 0 {
		return
	}
	m.mu.Lock()
	due := now.Sub(m.listsAt) >= w4BlocklistEvery
	if due {
		m.listsAt = now
	}
	m.mu.Unlock()
	if due {
		if err := m.updateLists(ctx, snap.doc); err != nil {
			m.alert(ctx, "blocklist_error", "", "Engel listeleri güncellenemedi: "+err.Error(), notify.PriorityLow)
		}
	}
}

// ObserveFlow feeds the light intrusion detector (#729). The packet
// filter of the tunnel calls it for new connections; alerts become
// events and notifications.
func (m *w4Monitor) ObserveFlow(ctx context.Context, f netwatch.Flow) {
	for _, a := range m.ids.Observe(f) {
		subject := "tünel içi kaynak"
		m.mu.Lock()
		if m.lastDoc != nil {
			if dev, ok := m.lastDoc.DeviceByAddr(a.Src); ok {
				subject = dev.Name
			}
		}
		m.mu.Unlock()
		m.alert(ctx, EventIDSAlert, subject, a.Message, notify.PriorityHigh)
	}
}

// --- panel.MonitorApp ---

var _ panel.MonitorApp = (*w4Monitor)(nil)

// MonitorServices implements panel.MonitorApp.
func (m *w4Monitor) MonitorServices() []healthmon.ServiceStatus {
	m.mu.Lock()
	s := m.services
	m.mu.Unlock()
	if s == nil {
		return []healthmon.ServiceStatus{}
	}
	return s.Status()
}

// MonitorDevices implements panel.MonitorApp.
func (m *w4Monitor) MonitorDevices() []panel.MonitorDevice {
	now := m.now()
	m.mu.Lock()
	doc, presence := m.lastDoc, m.presence
	seen := make(map[string]time.Time, len(m.lastSeen))
	for k, v := range m.lastSeen {
		seen[k] = v
	}
	m.mu.Unlock()
	out := []panel.MonitorDevice{}
	if doc == nil {
		return out
	}
	var inv map[string]sysinfo.Info
	if m.inventory != nil {
		inv = m.inventory()
	}
	for _, dev := range doc.Devices {
		row := panel.MonitorDevice{Name: dev.Name, Watched: presence.Watched(dev.Name), Warnings: []string{}}
		if t, ok := seen[dev.Name]; ok {
			row.LastSeen = t
			row.Online = now.Sub(t) < onlineWindow
		}
		if info, ok := inv[dev.Name]; ok && info.Detail != nil {
			for _, f := range healthmon.CheckResources(dev.Name, info.Detail, healthmon.DefaultThresholds) {
				row.Warnings = append(row.Warnings, f.Title)
			}
		}
		out = append(out, row)
	}
	return out
}

// MonitorQuality implements panel.MonitorApp.
func (m *w4Monitor) MonitorQuality(device string, coarse bool) ([]healthmon.Point, error) {
	res := healthmon.Fine
	if coarse {
		res = healthmon.Coarse
	}
	return m.quality.Series(device, res, m.now())
}

// NotifyConfig implements panel.MonitorApp.
func (m *w4Monitor) NotifyConfig() (notify.Config, error) {
	c, err := notify.Load(m.path(notify.ConfigFile))
	if errors.Is(err, fs.ErrNotExist) {
		return notify.Config{Schema: 1, Channels: []notify.ChannelConfig{}}, nil
	}
	return c, err
}

// SetNotifyConfig implements panel.MonitorApp.
func (m *w4Monitor) SetNotifyConfig(c notify.Config) error {
	if _, err := c.Build(m.desktopDeliver); err != nil {
		return err
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	if err := notify.Save(m.path(notify.ConfigFile), c); err != nil {
		return err
	}
	m.mu.Lock()
	m.notifyStamp = time.Time{}
	m.reloadLocked(m.lastDoc)
	m.mu.Unlock()
	return nil
}

// NotifyTest implements panel.MonitorApp: one test message to the
// channel with label (all channels when label is empty).
func (m *w4Monitor) NotifyTest(label string) error {
	c, err := m.NotifyConfig()
	if err != nil {
		return err
	}
	if label != "" {
		var keep []notify.ChannelConfig
		for _, ch := range c.Channels {
			if ch.Label == label {
				keep = append(keep, ch)
			}
		}
		if len(keep) == 0 {
			return errors.New("bu adla bir bildirim kanalı yok")
		}
		c.Channels = keep
	}
	c.QuietStart, c.QuietEnd = "", ""
	d, err := c.Build(m.desktopDeliver)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := d.Notify(ctx, notify.Message{Kind: "test", Subject: "test", Key: fmt.Sprintf("test|%d", m.now().UnixNano()),
		Title: "OpenScale deneme bildirimi", Body: "Bu kanal çalışıyor.", Priority: notify.PriorityHigh, At: m.now()})
	if len(res) == 0 {
		return notify.ErrNoChannels
	}
	for _, r := range res {
		if r.Err != nil {
			return fmt.Errorf("%s: %w", r.Channel, r.Err)
		}
	}
	return nil
}

// WeeklyPreview implements panel.MonitorApp.
func (m *w4Monitor) WeeklyPreview() (string, string, error) {
	w := m.buildWeekly(m.now())
	return w.Subject(), w.Text(), nil
}

// SpeedTest implements panel.MonitorApp through the speed test button.
func (m *w4Monitor) SpeedTest(target string) (healthmon.SpeedResult, error) {
	snap, ok := m.snapshot()
	if !ok {
		return healthmon.SpeedResult{}, errors.New("tünel kapalı")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return m.speed.Measure(ctx, snap.doc, snap.self.Name, target)
}

// SpeedHistory implements panel.MonitorApp.
func (m *w4Monitor) SpeedHistory(target string) []healthmon.SpeedResult {
	out := []healthmon.SpeedResult{}
	for _, r := range m.speed.History() {
		if target == "" || r.Target == target {
			out = append(out, r)
		}
	}
	return out
}

// Wake implements panel.MonitorApp through the service's wake flow.
func (m *w4Monitor) Wake(device string) error {
	if m.wake == nil {
		return errors.New("uyandırma bu süreçte kullanılamıyor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return m.wake(ctx, device)
}

func (m *w4Monitor) drive(name string) (netdrive.Mount, *trust.Document, error) {
	m.mu.Lock()
	doc := m.lastDoc
	cfg := m.cfg
	m.mu.Unlock()
	if doc == nil {
		return netdrive.Mount{}, nil, errors.New("tünel kapalı")
	}
	for _, d := range cfg.Drives {
		if d.Name == name {
			return d, doc, nil
		}
	}
	return netdrive.Mount{}, nil, errors.New("bu adla bir ağ sürücüsü tanımlı değil")
}

// MapDrive implements panel.MonitorApp.
func (m *w4Monitor) MapDrive(name string) error {
	d, doc, err := m.drive(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return m.mapDrive(ctx, doc, d)
}

// UnmapDrive implements panel.MonitorApp.
func (m *w4Monitor) UnmapDrive(name string) error {
	d, doc, err := m.drive(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return m.unmapDrive(ctx, doc, d)
}

// --- Runtime wiring ---

// w4Runtime holds the monitor of one Runtime.
type w4Runtime struct {
	mu  sync.Mutex
	mon *w4Monitor
}

// monitor returns the Runtime's monitor, creating it on first use.
func (r *Runtime) monitor() *w4Monitor {
	r.w4.mu.Lock()
	defer r.w4.mu.Unlock()
	if r.w4.mon != nil {
		return r.w4.mon
	}
	m := newW4Monitor(r.cfg.DataDir, r.cfg.Now)
	m.snapshot = r.monitorSnapshot
	m.inventory = r.inventoryReports
	m.event = func(ev panel.DiagEvent) { r.eventLog().Add(ev) }
	m.wake = func(ctx context.Context, device string) error {
		_, err := r.Wake(ctx, device)
		return err
	}
	m.updateLists = func(ctx context.Context, doc *trust.Document) error {
		_, err := node.UpdateExitBlocklists(ctx, r.path(DeviceDir), doc, true)
		return err
	}
	r.w4.mon = m
	return m
}

// MonitorApp gives the panel the monitoring screen (panel.MonitorApp's
// Wake and SpeedTest differ from panel.RemoteApps', so the Runtime hands
// out the monitor instead of implementing both).
func (r *Runtime) MonitorApp() panel.MonitorApp { return r.monitor() }

func (r *Runtime) monitorSnapshot() (monitorSnapshot, bool) {
	e := r.currentEngine()
	if e == nil {
		return monitorSnapshot{}, false
	}
	self, err := e.Self()
	if err != nil {
		return monitorSnapshot{}, false
	}
	doc := e.Document()
	snap := monitorSnapshot{doc: doc, self: self, lastSeen: map[string]time.Time{}, rtt: map[string]time.Duration{}}
	// This device runs the engine, so it is online; without this the
	// panel listed the own device as offline (no handshake with itself).
	snap.lastSeen[self.Name] = r.cfg.Now()
	stats, _ := e.PeerStats()
	for _, d := range doc.TunnelPeersOf(self.Name) {
		if s, ok := stats[d.WireGuardKey]; ok && s.LastHandshakeUnix > 0 {
			snap.lastSeen[d.Name] = time.Unix(s.LastHandshakeUnix, 0)
		}
	}
	paths, _ := e.PeerPaths()
	for _, p := range paths {
		if p.ProbeRTT > 0 {
			snap.rtt[p.Name] = p.ProbeRTT
		}
	}
	return snap, true
}

// monitorLoop runs the watchers until ctx ends.
func (r *Runtime) monitorLoop(ctx context.Context) {
	m := r.monitor()
	every := w4Step
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < every {
		every = r.cfg.PollInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		m.tick(ctx)
		select {
		case <-ctx.Done():
			m.saveQuality(m.now(), true)
			return
		case <-t.C:
		}
	}
}
