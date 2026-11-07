package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/syncdir"
	"github.com/openscale/openscale/internal/trust"
)

// Sync guard, pause and backup probe (P07, ADR-0159; #452, #453).
//
// Scheduled pulls, backups and probes are held while any pause reason is
// active: the owner's pause (apps/sync-pause.json, optionally until a
// time), the game or metered device mode of P11 (read from edge.json, so
// a mode set before a restart still holds) and any reason registered with
// Runtime.HoldSync. Manual "sync now" and "back up now" still run: the
// owner asked for them. The ransomware guard works per folder inside
// syncdir and is not lifted by anything but the owner's ClearSyncAlarm.

const (
	syncPauseFn    = "sync-pause.json"
	syncGuardFn    = "sync-guard.json"
	backupProbeFn  = "backup-probe.json"
	probeMinHours  = 24
	probeTimeoutSv = 2 * time.Hour
)

type syncPauseFile struct {
	Since time.Time `json:"since"`
	// Until is zero for a pause without end.
	Until time.Time `json:"until,omitempty"`
}

type syncGuardFile struct {
	// Off lists folders whose guard the owner turned off.
	Off []string `json:"off,omitempty"`
}

// p07State is the in-memory part, kept beside Apps.
type p07State struct {
	mu     sync.Mutex
	hold   syncdir.Pauser
	probe  *panel.BackupProbeStatus
	loaded bool
	notify func(kind, severity, message string)
}

var p07States sync.Map // *Apps -> *p07State

func (a *Apps) p07() *p07State {
	if v, ok := p07States.Load(a); ok {
		return v.(*p07State)
	}
	v, _ := p07States.LoadOrStore(a, &p07State{})
	return v.(*p07State)
}

// guardConfig is the syncdir guard of folder id.
func (a *Apps) guardConfig(id string) syncdir.GuardConfig {
	var g syncGuardFile
	_ = loadJSON(a.syncPath(syncGuardFn), &g)
	return syncdir.GuardConfig{Off: slices.Contains(g.Off, id)}
}

// onSyncAlarm is called by syncdir when the guard suspends a folder.
func (a *Apps) onSyncAlarm(id string, al syncdir.Alarm) {
	a.log.Warn("ransomware suspicion: folder suspended", "folder", id, "source", al.Source,
		"modified", al.Modified, "deleted", al.Deleted, "ext_changed", al.ExtChanged, "high_entropy", al.HighEntropy, "bad_magic", al.BadMagic)
	st := a.p07()
	st.mu.Lock()
	notify := st.notify
	st.mu.Unlock()
	if notify != nil {
		notify("sync_ransomware_suspected", audit.SeverityCritical,
			"Eşitlenen klasörde fidye yazılımı belirtisi: "+id+". Eşitleme ve yedek durduruldu; dosyaları denetleyip panelden onaylayın. "+al.Reason)
	}
}

// syncPauseReasons returns the active pause reasons.
func (a *Apps) syncPauseReasons(now time.Time) []panel.SyncPauseView {
	var out []panel.SyncPauseView
	var p syncPauseFile
	if err := loadJSON(a.syncPath(syncPauseFn), &p); err == nil {
		if p.Until.IsZero() || now.Before(p.Until) {
			v := panel.SyncPauseView{Reason: panel.SyncPauseOwner, Label: "Sahip duraklattı"}
			since := p.Since
			v.Since = &since
			if !p.Until.IsZero() {
				until := p.Until
				v.Until = &until
			}
			out = append(out, v)
		} else {
			_ = os.Remove(a.syncPath(syncPauseFn))
		}
	}
	if st, err := loadEdge(a.cfg.Dir); err == nil && st.Mode != nil {
		since := st.Mode.Since
		switch st.Mode.Name {
		case panel.EdgeModeGame:
			out = append(out, panel.SyncPauseView{Reason: panel.SyncPauseGame, Label: "Oyun kipi açık", Since: &since})
		case panel.EdgeModeMetered:
			out = append(out, panel.SyncPauseView{Reason: panel.SyncPauseMetered, Label: "Ölçülü bağlantı kipi açık", Since: &since})
		}
	}
	h := &a.p07().hold
	for _, r := range h.Reasons() {
		v := panel.SyncPauseView{Reason: r, Label: "Duraklatıldı: " + r}
		if t, ok := h.Since(r); ok {
			v.Since = &t
		}
		out = append(out, v)
	}
	return out
}

// syncHeld reports whether scheduled work waits; syncDue calls it first.
func (a *Apps) syncHeld(now time.Time) bool {
	return len(a.syncPauseReasons(now)) > 0
}

// --- probe (#452) ---

func (a *Apps) probeHours(c syncConfig) int {
	h := c.Backup.IntervalHours
	if h <= 0 {
		h = defaultBackupHours
	}
	return max(h, probeMinHours)
}

func (a *Apps) loadProbe() *panel.BackupProbeStatus {
	st := a.p07()
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.loaded {
		st.loaded = true
		var p panel.BackupProbeStatus
		if err := loadJSON(a.syncPath(backupProbeFn), &p); err == nil && !p.At.IsZero() {
			st.probe = &p
		}
	}
	if st.probe == nil {
		return nil
	}
	cp := *st.probe
	cp.Folders = slices.Clone(st.probe.Folders)
	return &cp
}

// probeDue runs a scheduled probe after syncDue's pulls and backups.
func (a *Apps) probeDue(now time.Time) {
	c, err := a.loadSyncConfig()
	if err != nil || !c.Backup.Enabled || len(c.Backup.Folders) == 0 {
		return
	}
	if last := a.loadProbe(); last != nil && now.Sub(last.At) < time.Duration(a.probeHours(c))*time.Hour {
		return
	}
	ctx, cancel := context.WithTimeout(a.runContext(), probeTimeoutSv)
	defer cancel()
	if _, err := a.runProbe(ctx, c); err != nil {
		a.log.Warn("backup probe failed", "error", err.Error())
	}
}

// runProbe checks every backed up folder on the target and keeps the
// result.
func (a *Apps) runProbe(ctx context.Context, c syncConfig) (*panel.BackupProbeStatus, error) {
	s := &a.ext().sync
	s.work.Lock()
	defer s.work.Unlock()
	res := &panel.BackupProbeStatus{At: a.cfg.Now().UTC(), Target: c.Backup.Target, Folders: []panel.BackupProbeFolder{}}
	err := a.probeRound(ctx, c, res)
	if err != nil {
		res.Error = err.Error()
	}
	res.OK = err == nil && len(res.Folders) > 0
	for _, f := range res.Folders {
		if !f.OK {
			res.OK = false
		}
	}
	st := a.p07()
	st.mu.Lock()
	st.probe, st.loaded = res, true
	notify := st.notify
	st.mu.Unlock()
	if serr := saveJSON(a.syncPath(backupProbeFn), res); serr != nil {
		a.log.Warn("backup probe result not saved", "error", serr.Error())
	}
	if !res.OK && err == nil && notify != nil {
		notify("backup_probe_failed", audit.SeverityWarning, "Yedek bütünlüğü yoklaması sorun buldu; yedeğin bir kısmı geri yüklenemeyebilir.")
	}
	return res, err
}

func (a *Apps) probeRound(ctx context.Context, c syncConfig, res *panel.BackupProbeStatus) error {
	key, _, err := a.backupKey()
	if err != nil {
		return err
	}
	doc, self, ok := a.current()
	if !ok {
		return errNoTunnel()
	}
	target, ok := doc.DeviceByName(c.Backup.Target)
	if !ok || !doc.AllowsBackup(self.Name, target.Name) {
		return errors.New("yedek hedefi seçilmemiş veya kural izin vermiyor")
	}
	cl, err := syncdir.Dial(ctx, netip.AddrPortFrom(target.IPv4, trust.SyncPort))
	if err != nil {
		return errors.New("yedek hedefine ulaşılamadı; sonraki turda yeniden denenecek")
	}
	defer cl.Close()
	for _, id := range c.Backup.Folders {
		if err := ctx.Err(); err != nil {
			return err
		}
		pf := panel.BackupProbeFolder{Folder: id}
		r, err := syncdir.Probe(ctx, key, cl.Store(id), syncdir.ProbeOptions{})
		switch {
		case errors.Is(err, syncdir.ErrNoSnapshot):
			pf.Error = "hedefte bu klasörün yedeği yok"
		case err != nil:
			pf.Error = err.Error()
			res.Folders = append(res.Folders, pf)
			return fmt.Errorf("%s: %w", id, err)
		default:
			pf.OK, pf.Snapshot, pf.Snapshots, pf.Files, pf.Checked, pf.Bytes, pf.Missing = r.OK, r.Snapshot, r.Snapshots, r.Files, r.Checked, r.Bytes, r.Missing
			if !r.SnapshotTime.IsZero() {
				t := r.SnapshotTime
				pf.SnapshotTime = &t
			}
			for _, p := range r.Problems {
				pf.Problems = append(pf.Problems, panel.BackupProbeProblem{Path: p.Path, Reason: p.Reason})
			}
		}
		res.Folders = append(res.Folders, pf)
		a.log.Info("backup probe", "folder", id, "ok", pf.OK, "checked", pf.Checked, "missing", pf.Missing)
	}
	return nil
}

// --- panel.SyncGuardControl (through Runtime) ---

func (a *Apps) syncGuardStatus() (panel.SyncGuardStatus, error) {
	now := a.cfg.Now()
	out := panel.SyncGuardStatus{Pauses: a.syncPauseReasons(now), Folders: []panel.SyncGuardFolder{}}
	out.Paused = len(out.Pauses) > 0
	c, err := a.loadSyncConfig()
	if err != nil {
		return out, err
	}
	out.ProbeHours = a.probeHours(c)
	out.Probe = a.loadProbe()
	var g syncGuardFile
	_ = loadJSON(a.syncPath(syncGuardFn), &g)
	for _, fc := range c.Folders {
		v := panel.SyncGuardFolder{ID: fc.ID, GuardOff: slices.Contains(g.Off, fc.ID)}
		if err := fc.validate(a.cfg.Dir); err != nil {
			v.Error = err.Error()
		} else if f, err := a.openFolder(fc); err != nil {
			v.Error = err.Error()
		} else if al := f.Alarm(); al != nil {
			v.Alarm = &panel.SyncAlarmView{Since: al.Since, Source: al.Source, Reason: al.Reason, Files: al.Files, Modified: al.Modified,
				Deleted: al.Deleted, Added: al.Added, ExtChanged: al.ExtChanged, Sampled: al.Sampled, HighEntropy: al.HighEntropy,
				BadMagic: al.BadMagic, Examples: al.Examples}
		}
		out.Folders = append(out.Folders, v)
	}
	return out, nil
}

func (a *Apps) setSyncPause(req panel.SyncPauseRequest) error {
	if !req.Paused {
		if err := os.Remove(a.syncPath(syncPauseFn)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		a.log.Info("sync resumed by owner")
		return nil
	}
	if req.Hours < 0 || req.Hours > maxBackupHours {
		return fmt.Errorf("duraklatma süresi 0 ile %d saat arasında olmalı", maxBackupHours)
	}
	now := a.cfg.Now().UTC()
	p := syncPauseFile{Since: now}
	if req.Hours > 0 {
		p.Until = now.Add(time.Duration(req.Hours) * time.Hour)
	}
	if err := saveJSON(a.syncPath(syncPauseFn), p); err != nil {
		return err
	}
	a.log.Info("sync paused by owner", "hours", req.Hours)
	return nil
}

func (a *Apps) setSyncGuard(req panel.SyncGuardRequest) error {
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	if _, ok := c.folder(req.ID); !ok {
		return errors.New("böyle bir klasör yok")
	}
	s := &a.ext().sync
	s.work.Lock()
	defer s.work.Unlock()
	var g syncGuardFile
	if err := loadJSON(a.syncPath(syncGuardFn), &g); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	g.Off = slices.DeleteFunc(g.Off, func(id string) bool { return id == req.ID })
	if req.Off {
		g.Off = append(g.Off, req.ID)
	}
	slices.Sort(g.Off)
	if err := saveJSON(a.syncPath(syncGuardFn), g); err != nil {
		return err
	}
	a.closeFolder(req.ID)
	a.log.Info("sync guard changed", "folder", req.ID, "off", req.Off)
	return nil
}

func (a *Apps) clearSyncAlarm(id string) error {
	f, err := a.configuredFolder(id)
	if err != nil {
		return err
	}
	if f.Alarm() == nil {
		return errors.New("bu klasörde etkin bir fidye yazılımı uyarısı yok")
	}
	s := &a.ext().sync
	s.work.Lock()
	defer s.work.Unlock()
	if err := f.ClearAlarm(); err != nil {
		return err
	}
	a.log.Warn("ransomware alarm cleared by owner", "folder", id)
	return nil
}

func (a *Apps) probeBackupNow(ctx context.Context) error {
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	if !validDeviceName(c.Backup.Target) || len(c.Backup.Folders) == 0 {
		return errors.New("yedek hedefi ve klasörleri seçilmemiş")
	}
	_, err = a.runProbe(ctx, c)
	return err
}

// --- Runtime ---

var _ panel.SyncGuardControl = (*Runtime)(nil)

// wireP07 connects the guard's alerts to the security event stream and
// starts the dynamic DNS check and updater (ddns_p07.go).
func (r *Runtime) wireP07(ctx context.Context, a *Apps) {
	r.spawn(func() { r.p07Loop(ctx) })
	st := a.p07()
	st.mu.Lock()
	st.notify = func(kind, severity, message string) {
		r.observer().Security(kind, severity, panel.CategorySecurity, "", message, true)
	}
	st.mu.Unlock()
}

// HoldSync adds or removes a reason that holds scheduled synchronization,
// backups and probes (the pause hook of #385 and #447 for code that does
// not go through edge.json).
func (r *Runtime) HoldSync(reason string, on bool) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	if reason == "" || len(reason) > 64 {
		return errors.New("duraklatma nedeni geçersiz")
	}
	a.p07().hold.Set(reason, on, a.cfg.Now())
	return nil
}

func (r *Runtime) guardResult(err error) (panel.SyncGuardStatus, error) {
	if err != nil {
		return panel.SyncGuardStatus{}, err
	}
	return r.SyncGuardStatus()
}

// SyncGuardStatus implements panel.SyncGuardControl.
func (r *Runtime) SyncGuardStatus() (panel.SyncGuardStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SyncGuardStatus{}, err
	}
	return a.syncGuardStatus()
}

// SetSyncPause implements panel.SyncGuardControl.
func (r *Runtime) SetSyncPause(req panel.SyncPauseRequest) (panel.SyncGuardStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SyncGuardStatus{}, err
	}
	err = a.setSyncPause(req)
	if err == nil {
		if req.Paused {
			r.auditLocal("sync_paused", "Eşitleme ve yedek sahip tarafından duraklatıldı")
		} else {
			r.auditLocal("sync_resumed", "Eşitleme ve yedek yeniden başladı")
		}
	}
	return r.guardResult(err)
}

// SetSyncGuard implements panel.SyncGuardControl.
func (r *Runtime) SetSyncGuard(req panel.SyncGuardRequest) (panel.SyncGuardStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SyncGuardStatus{}, err
	}
	err = a.setSyncGuard(req)
	if err == nil && req.Off {
		r.auditLocal("sync_guard_off", "Fidye yazılımı koruması kapatıldı: "+req.ID)
	}
	return r.guardResult(err)
}

// ClearSyncAlarm implements panel.SyncGuardControl.
func (r *Runtime) ClearSyncAlarm(id string) (panel.SyncGuardStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SyncGuardStatus{}, err
	}
	err = a.clearSyncAlarm(id)
	if err == nil {
		r.auditLocal("sync_alarm_cleared", "Fidye yazılımı uyarısı sahip tarafından kapatıldı: "+id)
	}
	return r.guardResult(err)
}

// ProbeBackup implements panel.SyncGuardControl.
func (r *Runtime) ProbeBackup(ctx context.Context) (panel.SyncGuardStatus, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SyncGuardStatus{}, err
	}
	return r.guardResult(a.probeBackupNow(ctx))
}
