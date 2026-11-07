package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/syncdir"
	"github.com/openscale/openscale/internal/trust"
)

// Folder sync, encrypted backup and the offline outbox (ADR-0104,
// ADR-0110). Sync is pull only: this device serves its shared folders read
// only to the devices the sync rules name and pulls its own folders from
// the peers the owner listed, on a timer. Backups run only after the owner
// exported the backup key (a lost key makes every backup unreadable).
// Files for offline recipients wait in a queue on this device; nothing is
// stored at the coordinator or another device.

const (
	syncConfigFn        = "sync.json"
	backupKeyFn         = "backup.key"
	backupExportFn      = "backup-key-export.json"
	syncBackupsDir      = "backups"
	queueDir            = "queue"
	outboxFn            = "outbox.json"
	defaultSyncInterval = 5 * time.Minute
	minSyncInterval     = time.Minute
	maxSyncInterval     = 24 * time.Hour
	defaultBackupHours  = 24
	maxBackupHours      = 24 * 30
	maxSyncFolders      = 64
	maxSyncPeers        = 32
	maxSyncPath         = 1024
	outboxEvery         = 30 * time.Second
	syncPullTimeout     = 30 * time.Minute
	backupTimeout       = 6 * time.Hour
)

// syncFolderConfig is one folder in apps/sync.json.
type syncFolderConfig struct {
	ID               string   `json:"id"`
	Path             string   `json:"path"`
	Mode             string   `json:"mode"`
	Peers            []string `json:"peers,omitempty"`
	PropagateDeletes bool     `json:"propagate_deletes,omitempty"`
	Versions         int      `json:"versions,omitempty"`
}

type syncBackupConfig struct {
	Enabled       bool     `json:"enabled,omitempty"`
	Target        string   `json:"target,omitempty"`
	Folders       []string `json:"folders,omitempty"`
	IntervalHours int      `json:"interval_hours,omitempty"`
}

// syncConfig is apps/sync.json.
type syncConfig struct {
	Folders     []syncFolderConfig `json:"folders,omitempty"`
	IntervalSec int                `json:"interval_sec,omitempty"`
	Backup      syncBackupConfig   `json:"backup"`
}

type backupExport struct {
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

func (c syncConfig) interval() time.Duration {
	d := time.Duration(c.IntervalSec) * time.Second
	if d < minSyncInterval || d > maxSyncInterval {
		return defaultSyncInterval
	}
	return d
}

func (c syncConfig) folder(id string) (syncFolderConfig, bool) {
	i := slices.IndexFunc(c.Folders, func(f syncFolderConfig) bool { return f.ID == id })
	if i < 0 {
		return syncFolderConfig{}, false
	}
	return c.Folders[i], true
}

// validSyncPath refuses relative paths, drive or file system roots and
// the data directory (which holds the keys) or anything inside or above it.
func validSyncPath(dataDir, p string) error {
	if p == "" || len(p) > maxSyncPath || !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n") {
		return errors.New("klasör yolu mutlak ve geçerli olmalı")
	}
	clean := filepath.Clean(p)
	if filepath.Dir(clean) == clean {
		return errors.New("sürücü veya dosya sistemi kökü paylaşılamaz")
	}
	if dataDir != "" {
		data := filepath.Clean(dataDir)
		if within(clean, data) || within(data, clean) {
			return errors.New("OpenScale veri klasörü (anahtarlar) eşitlenemez")
		}
	}
	info, err := os.Stat(clean)
	if err != nil || !info.IsDir() {
		return errors.New("klasör bulunamadı")
	}
	return nil
}

// within reports whether p is base or below it (case-insensitive on
// Windows-style paths).
func within(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func (c syncFolderConfig) validate(dataDir string) error {
	if !syncdir.ValidID(c.ID) {
		return errors.New("klasör kimliği küçük harf, rakam ve tire olmalı (en çok 63)")
	}
	if !syncdir.FolderMode(c.Mode).Valid() {
		return errors.New("kip sendreceive, sendonly veya receiveonly olmalı")
	}
	if len(c.Peers) > maxSyncPeers {
		return fmt.Errorf("en çok %d eş listelenebilir", maxSyncPeers)
	}
	for _, p := range c.Peers {
		if !validDeviceName(p) {
			return fmt.Errorf("geçersiz cihaz adı %q", p)
		}
	}
	if c.Mode == string(syncdir.SendOnly) && len(c.Peers) > 0 {
		return errors.New("yalnızca gönderen (sendonly) klasör eşlerden çekmez; eş listesini boş bırakın")
	}
	if c.Versions < -1 || c.Versions > 100 {
		return errors.New("saklanacak sürüm sayısı -1 ile 100 arasında olmalı")
	}
	return validSyncPath(dataDir, c.Path)
}

func validDeviceName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// syncRun is what the last pull of a folder did.
type syncRun struct {
	at                                  time.Time
	err                                 string
	fetched, deleted, conflicts, failed int
}

// syncState is the sync part of Apps.
type syncState struct {
	mu       sync.Mutex
	folders  map[string]*syncdir.Folder
	opened   map[string]syncFolderConfig
	runs     map[string]syncRun
	lastPull time.Time
	backup   syncRun
	lastSnap string
	lastBack time.Time
	outbox   *filesend.Outbox
	outErr   string
	work     sync.Mutex // one pull or backup round at a time
}

func (a *Apps) syncPath(parts ...string) string { return a.appsPath(parts...) }

func (a *Apps) loadSyncConfig() (syncConfig, error) {
	var c syncConfig
	err := loadJSON(a.syncPath(syncConfigFn), &c)
	if errors.Is(err, fs.ErrNotExist) {
		return syncConfig{}, nil
	}
	return c, err
}

func (a *Apps) saveSyncConfig(c syncConfig) error {
	if err := os.MkdirAll(a.appsPath(), 0o700); err != nil {
		return err
	}
	return saveJSON(a.syncPath(syncConfigFn), c)
}

// openFolder returns the open folder for cfg, reopening it when the
// configuration changed.
func (a *Apps) openFolder(cfg syncFolderConfig) (*syncdir.Folder, error) {
	s := &a.ext().sync
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.folders[cfg.ID]; ok {
		if old := s.opened[cfg.ID]; old.Path == cfg.Path && old.Mode == cfg.Mode && old.PropagateDeletes == cfg.PropagateDeletes && old.Versions == cfg.Versions {
			return f, nil
		}
		_ = f.Close()
		delete(s.folders, cfg.ID)
	}
	versions := cfg.Versions
	if versions == 0 {
		versions = syncdir.DefaultVersions
	}
	f, err := syncdir.OpenFolder(syncdir.FolderConfig{ID: cfg.ID, Path: cfg.Path, Mode: syncdir.FolderMode(cfg.Mode),
		PropagateDeletes: cfg.PropagateDeletes, Versions: versions, Guard: a.guardConfig(cfg.ID), OnAlarm: a.onSyncAlarm})
	if err != nil {
		return nil, err
	}
	if s.folders == nil {
		s.folders, s.opened = map[string]*syncdir.Folder{}, map[string]syncFolderConfig{}
	}
	s.folders[cfg.ID], s.opened[cfg.ID] = f, cfg
	return f, nil
}

func (a *Apps) closeFolder(id string) {
	s := &a.ext().sync
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.folders[id]; ok {
		_ = f.Close()
		delete(s.folders, id)
		delete(s.opened, id)
	}
}

func (a *Apps) closeFolders() {
	s := &a.ext().sync
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, f := range s.folders {
		_ = f.Close()
		delete(s.folders, id)
	}
}

// servedFolder is syncdir.ServerConfig.Folder: only folders the owner
// shares (sendreceive or sendonly) are served.
func (a *Apps) servedFolder(id string) *syncdir.Folder {
	c, err := a.loadSyncConfig()
	if err != nil {
		return nil
	}
	fc, ok := c.folder(id)
	if !ok || fc.Mode == string(syncdir.ReceiveOnly) || fc.validate(a.cfg.Dir) != nil {
		return nil
	}
	f, err := a.openFolder(fc)
	if err != nil {
		a.log.Warn("shared folder could not be opened", "folder", id, "error", err.Error())
		return nil
	}
	return f
}

// syncAccess is syncdir.ServerConfig.Authorize, asked for every request.
func (a *Apps) syncAccess(remote netip.Addr) syncdir.Access {
	doc, self, dev, ok := a.peer(remote)
	if !ok {
		return syncdir.Access{}
	}
	g := doc.SyncAccess(dev.Name, self.Name)
	return syncdir.Access{Peer: dev.Name, Folders: g.Folders, Backup: g.Backup, Quota: g.Quota, AllowPrune: g.AllowPrune}
}

// startSync runs the sync server on the tunnel listener.
func (a *Apps) startSync(ctx context.Context, ln net.Listener, addr netip.AddrPort) (func() error, error) {
	backups := a.appsPath(syncBackupsDir)
	if err := os.MkdirAll(backups, 0o700); err != nil {
		return nil, err
	}
	srv, err := syncdir.NewServer(syncdir.ServerConfig{
		ListenAddr: addr,
		Authorize:  a.syncAccess,
		Folder:     a.servedFolder,
		BackupDir:  backups,
		Logger:     a.log.With("service", "sync"),
	})
	if err != nil {
		return nil, err
	}
	return func() error { return srv.Serve(ctx, ln) }, nil
}

// --- scheduled pulls and backups ---

func (a *Apps) syncDue(now time.Time) {
	if a.syncHeld(now) { // P07: owner pause, game or metered mode (sync_p07.go)
		return
	}
	c, err := a.loadSyncConfig()
	if err != nil {
		a.log.Warn("sync settings unreadable", "error", err.Error())
		return
	}
	s := &a.ext().sync
	s.mu.Lock()
	pullDue := len(c.Folders) > 0 && now.Sub(s.lastPull) >= c.interval()
	hours := c.Backup.IntervalHours
	if hours <= 0 {
		hours = defaultBackupHours
	}
	backupDue := c.Backup.Enabled && now.Sub(s.lastBack) >= time.Duration(hours)*time.Hour
	s.mu.Unlock()
	if pullDue {
		ctx, cancel := context.WithTimeout(a.runContext(), syncPullTimeout)
		_ = a.pullAll(ctx, c)
		cancel()
	}
	if backupDue {
		ctx, cancel := context.WithTimeout(a.runContext(), backupTimeout)
		if err := a.backupAll(ctx, c); err != nil {
			a.log.Warn("scheduled backup failed", "error", err.Error())
		}
		cancel()
	}
	a.probeDue(now) // #452
}

func (a *Apps) runContext() context.Context {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runCtx
}

// pullAll pulls every folder from every listed peer that allows it. An
// offline peer is simply tried again at the next round.
func (a *Apps) pullAll(ctx context.Context, c syncConfig) error {
	s := &a.ext().sync
	s.work.Lock()
	defer s.work.Unlock()
	s.mu.Lock()
	s.lastPull = a.cfg.Now()
	s.mu.Unlock()
	doc, self, ok := a.current()
	if !ok {
		return errNoTunnel()
	}
	var errs []error
	for _, fc := range c.Folders {
		if fc.Mode == string(syncdir.SendOnly) || len(fc.Peers) == 0 {
			continue
		}
		run := syncRun{at: a.cfg.Now().UTC()}
		if err := fc.validate(a.cfg.Dir); err != nil {
			run.err = err.Error()
			a.setSyncRun(fc.ID, run)
			continue
		}
		f, err := a.openFolder(fc)
		if err != nil {
			run.err = err.Error()
			a.setSyncRun(fc.ID, run)
			errs = append(errs, err)
			continue
		}
		var msgs []string
		for _, peer := range fc.Peers {
			dev, ok := doc.DeviceByName(peer)
			if !ok || !doc.AllowsSyncFolder(self.Name, dev.Name, fc.ID) {
				msgs = append(msgs, peer+": kural bu klasörü okumaya izin vermiyor")
				continue
			}
			res, err := a.pullFrom(ctx, f, dev, fc.ID)
			if err != nil {
				msgs = append(msgs, peer+": "+err.Error())
				continue
			}
			run.fetched += res.Fetched
			run.deleted += res.Deleted
			run.conflicts += res.Conflicts
			run.failed += len(res.Failed)
		}
		run.err = strings.Join(msgs, "; ")
		a.setSyncRun(fc.ID, run)
		if run.fetched+run.deleted > 0 {
			a.log.Info("folder synchronized", "folder", fc.ID, "fetched", run.fetched, "deleted", run.deleted, "conflicts", run.conflicts)
		}
	}
	return errors.Join(errs...)
}

func (a *Apps) pullFrom(ctx context.Context, f *syncdir.Folder, dev trust.Device, id string) (syncdir.PullResult, error) {
	cl, err := syncdir.Dial(ctx, netip.AddrPortFrom(dev.IPv4, trust.SyncPort))
	if err != nil {
		return syncdir.PullResult{}, errors.New("cihaza ulaşılamadı; sonraki turda yeniden denenecek")
	}
	defer cl.Close()
	res, err := f.Pull(ctx, dev.Name, cl.Folder(id))
	if errors.Is(err, syncdir.ErrDenied) {
		return res, errors.New("cihaz bu klasörü paylaşmıyor")
	}
	return res, err
}

func (a *Apps) setSyncRun(id string, run syncRun) {
	s := &a.ext().sync
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs == nil {
		s.runs = map[string]syncRun{}
	}
	s.runs[id] = run
}

// backupKey loads the key and reports whether the owner exported it.
func (a *Apps) backupKey() (*syncdir.BackupKey, bool, error) {
	if err := os.MkdirAll(a.appsPath(), 0o700); err != nil {
		return nil, false, err
	}
	k, _, err := syncdir.LoadOrCreateBackupKey(a.syncPath(backupKeyFn))
	if err != nil {
		return nil, false, err
	}
	var exp backupExport
	if err := loadJSON(a.syncPath(backupExportFn), &exp); err != nil {
		return k, false, nil
	}
	return k, exp.Fingerprint == k.Fingerprint(), nil
}

// backupAll takes one snapshot of every chosen folder on the target.
func (a *Apps) backupAll(ctx context.Context, c syncConfig) error {
	s := &a.ext().sync
	s.work.Lock()
	defer s.work.Unlock()
	now := a.cfg.Now().UTC()
	s.mu.Lock()
	s.lastBack = now
	s.mu.Unlock()
	run := syncRun{at: now}
	err := a.backupRound(ctx, c, &run)
	if err != nil {
		run.err = err.Error()
	}
	s.mu.Lock()
	s.backup = run
	s.mu.Unlock()
	return err
}

func (a *Apps) backupRound(ctx context.Context, c syncConfig, run *syncRun) error {
	key, exported, err := a.backupKey()
	if err != nil {
		return err
	}
	if !exported {
		// SECURITY: a backup whose key was never saved elsewhere is lost
		// with this device; refuse until the owner exported it.
		return errors.New("yedek anahtarı dışa aktarılmadan yedek alınmaz")
	}
	doc, self, ok := a.current()
	if !ok {
		return errNoTunnel()
	}
	target, ok := doc.DeviceByName(c.Backup.Target)
	if !ok || !doc.AllowsBackup(self.Name, target.Name) {
		return errors.New("yedek hedefi kuralı bu cihazdan yedek kabul etmiyor")
	}
	cl, err := syncdir.Dial(ctx, netip.AddrPortFrom(target.IPv4, trust.SyncPort))
	if err != nil {
		return errors.New("yedek hedefine ulaşılamadı; sonraki turda yeniden denenecek")
	}
	defer cl.Close()
	var errs []error
	for _, id := range c.Backup.Folders {
		fc, ok := c.folder(id)
		if !ok {
			continue
		}
		f, err := a.openFolder(fc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		res, err := syncdir.Snapshot(ctx, f, key, cl.Store(id), "")
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		run.fetched += res.Uploaded
		a.ext().sync.mu.Lock()
		a.ext().sync.lastSnap = res.Name
		a.ext().sync.mu.Unlock()
		a.log.Info("backup snapshot taken", "folder", id, "files", res.Files, "uploaded", res.Uploaded, "reused", res.Reused)
	}
	return errors.Join(errs...)
}

// --- outbox (#140) ---

func (a *Apps) outbox() (*filesend.Outbox, error) {
	s := &a.ext().sync
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outbox != nil {
		return s.outbox, nil
	}
	if err := os.MkdirAll(a.appsPath(), 0o700); err != nil {
		return nil, err
	}
	o, err := filesend.OpenOutbox(filesend.OutboxConfig{
		File:    a.syncPath(outboxFn),
		Resolve: a.outboxResolve,
		OnDone:  a.outboxDone,
		Now:     a.cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	s.outbox = o
	return o, nil
}

// outboxResolve returns the recipient's file service while the tunnel runs
// and a rule allows sending; otherwise the item keeps waiting.
func (a *Apps) outboxResolve(peer string) (netip.AddrPort, bool) {
	doc, self, ok := a.current()
	if !ok {
		return netip.AddrPort{}, false
	}
	dev, ok := doc.DeviceByName(peer)
	if !ok || !doc.AllowsFileSend(self.Name, dev.Name) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(dev.IPv4, trust.FilesPort), true
}

func (a *Apps) outboxDone(it filesend.OutboxItem, _ filesend.SendResult, err error) {
	if within(it.Path, a.appsPath(queueDir)) {
		removeSoon(it.Path)
	}
	if err != nil {
		a.log.Warn("queued file dropped", "device", it.Peer, "error", err.Error())
		return
	}
	a.log.Info("queued file sent", "device", it.Peer, "size", it.Size)
}

func (a *Apps) runOutbox(ctx context.Context) {
	o, err := a.outbox()
	if err != nil {
		s := &a.ext().sync
		s.mu.Lock()
		s.outErr = err.Error()
		s.mu.Unlock()
		return
	}
	o.RunOnce(ctx)
}

func stripMode(s string) (filesend.MetadataMode, error) {
	switch s {
	case "":
		return filesend.MetadataKeep, nil
	case "location", "konum":
		return filesend.MetadataLocation, nil
	case "all", "hepsi":
		return filesend.MetadataAll, nil
	}
	return 0, errors.New("üst veri seçeneği konum (location) veya hepsi (all) olmalı")
}

func stripName(m filesend.MetadataMode) string {
	switch m {
	case filesend.MetadataLocation:
		return "location"
	case filesend.MetadataAll:
		return "all"
	}
	return ""
}

// QueueFile implements panel.SyncControl.
func (a *Apps) QueueFile(device, name string, body io.Reader, size int64, strip string) (string, error) {
	mode, err := stripMode(strip)
	if err != nil {
		return "", err
	}
	doc, self, ok := a.current()
	if !ok {
		return "", errNoTunnel()
	}
	target, ok := doc.DeviceByName(normalizeDevice(device))
	if !ok {
		return "", errors.New("böyle bir cihaz yok")
	}
	if !doc.AllowsFileSend(self.Name, target.Name) {
		return "", errors.New("bu cihaza dosya göndermeye izin veren bir kural yok")
	}
	clean, err := filesend.SanitizeName(name)
	if err != nil {
		return "", errors.New("dosya adı güvenli değil")
	}
	if size <= 0 || size > maxPanelUpload {
		return "", fmt.Errorf("dosya 1 bayt ile %d GiB arasında olmalı", maxPanelUpload>>30)
	}
	o, err := a.outbox()
	if err != nil {
		return "", err
	}
	dir := a.appsPath(queueDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, newID()+".bin")
	if err := writeUpload(path, body, size); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	it, err := o.Enqueue(target.Name, path, clean, mode)
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if !a.ext().noKick {
		go a.runOutbox(a.runContext())
	}
	return it.ID, nil
}

// RemoveOutbox implements panel.SyncControl.
func (a *Apps) RemoveOutbox(id string) error {
	o, err := a.outbox()
	if err != nil {
		return err
	}
	var path string
	for _, it := range o.Items() {
		if it.ID == id {
			path = it.Path
		}
	}
	found, err := o.Remove(id)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("kuyrukta böyle bir dosya yok")
	}
	if path != "" && within(path, a.appsPath(queueDir)) {
		removeSoon(path)
	}
	return nil
}

// removeSoon deletes a queued copy; on Windows a send still reading it
// keeps it open, so the removal is retried for a while.
func removeSoon(path string) {
	if err := os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
		return
	}
	go func() {
		for range 120 {
			time.Sleep(time.Second)
			if err := os.Remove(path); err == nil || errors.Is(err, fs.ErrNotExist) {
				return
			}
		}
	}()
}

// --- panel.SyncControl ---

// SyncStatus implements panel.SyncControl.
func (a *Apps) SyncStatus() panel.SyncStatus {
	out := panel.SyncStatus{Folders: []panel.SyncFolderView{}, BackupTargets: []string{}, Outbox: []panel.OutboxView{}}
	c, err := a.loadSyncConfig()
	if err != nil {
		out.Error = "eşitleme ayarları okunamadı: " + err.Error()
	}
	out.IntervalSec = int(c.interval() / time.Second)
	doc, self, ok := a.current()
	if ok {
		out.Hosted = doc.HostsService(self.Name, trust.ServiceSync)
	}
	a.mu.Lock()
	if r := a.runners[trust.ServiceSync]; r != nil {
		out.Running = r.running
		if r.err != "" {
			out.Error = r.err
		}
	}
	a.mu.Unlock()
	s := &a.ext().sync
	s.mu.Lock()
	runs := make(map[string]syncRun, len(s.runs))
	for k, v := range s.runs {
		runs[k] = v
	}
	backup, lastSnap, outErr := s.backup, s.lastSnap, s.outErr
	s.mu.Unlock()
	for _, fc := range c.Folders {
		v := panel.SyncFolderView{ID: fc.ID, Path: fc.Path, Mode: fc.Mode, Peers: append([]string{}, fc.Peers...),
			PropagateDeletes: fc.PropagateDeletes, Versions: fc.Versions, ServedTo: []string{}, Readable: []string{}}
		if ok {
			for _, d := range doc.Devices {
				if d.Name != self.Name && fc.Mode != string(syncdir.ReceiveOnly) && doc.AllowsSyncFolder(d.Name, self.Name, fc.ID) {
					v.ServedTo = append(v.ServedTo, d.Name)
				}
			}
			for _, p := range fc.Peers {
				if doc.AllowsSyncFolder(self.Name, p, fc.ID) {
					v.Readable = append(v.Readable, p)
				}
			}
		}
		if r, ok := runs[fc.ID]; ok {
			t := r.at
			v.LastPull, v.LastError = &t, r.err
			v.Fetched, v.Deleted, v.Conflicts, v.Failed = r.fetched, r.deleted, r.conflicts, r.failed
		}
		out.Folders = append(out.Folders, v)
	}
	if ok {
		for _, d := range doc.Devices {
			if d.Name != self.Name && doc.AllowsBackup(self.Name, d.Name) {
				out.BackupTargets = append(out.BackupTargets, d.Name)
			}
		}
	}
	b := panel.SyncBackupView{Enabled: c.Backup.Enabled, Target: c.Backup.Target, Folders: append([]string{}, c.Backup.Folders...),
		IntervalHours: c.Backup.IntervalHours, LastSnapshot: lastSnap}
	if b.IntervalHours == 0 {
		b.IntervalHours = defaultBackupHours
	}
	if !backup.at.IsZero() {
		t := backup.at
		b.LastRun, b.LastError = &t, backup.err
	}
	if k, exported, err := a.peekBackupKey(); err == nil && k != nil {
		b.KeyFingerprint, b.KeyExported = k.Fingerprint(), exported.Fingerprint == k.Fingerprint()
		if b.KeyExported {
			t := exported.At
			b.KeyExportedAt = &t
		}
	}
	out.Backup = b
	if o, err := a.outbox(); err == nil {
		for _, it := range o.Items() {
			out.Outbox = append(out.Outbox, panel.OutboxView{ID: it.ID, Peer: it.Peer, Name: it.Name, Size: it.Size, Strip: stripName(it.Metadata),
				Queued: it.Queued, Attempts: it.Attempts, NextTry: it.NextTry, LastError: it.LastError})
		}
	} else if outErr == "" {
		out.Error = "gönderim kuyruğu açılamadı: " + err.Error()
	}
	return out
}

// peekBackupKey reads the key without creating it.
func (a *Apps) peekBackupKey() (*syncdir.BackupKey, backupExport, error) {
	var exp backupExport
	k, err := syncdir.LoadBackupKey(a.syncPath(backupKeyFn))
	if err != nil {
		return nil, exp, err
	}
	_ = loadJSON(a.syncPath(backupExportFn), &exp)
	return k, exp, nil
}

// SetSyncFolder implements panel.SyncControl.
func (a *Apps) SetSyncFolder(ch panel.SyncFolderChange) error {
	fc := syncFolderConfig{ID: strings.TrimSpace(ch.ID), Path: strings.TrimSpace(ch.Path), Mode: strings.TrimSpace(ch.Mode),
		PropagateDeletes: ch.PropagateDeletes, Versions: ch.Versions}
	for _, p := range ch.Peers {
		if p = normalizeDevice(p); p != "" && !slices.Contains(fc.Peers, p) {
			fc.Peers = append(fc.Peers, p)
		}
	}
	if fc.Mode == "" {
		fc.Mode = string(syncdir.SendReceive)
	}
	if err := fc.validate(a.cfg.Dir); err != nil {
		return err
	}
	a.ext().sync.work.Lock()
	defer a.ext().sync.work.Unlock()
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(c.Folders, func(f syncFolderConfig) bool { return f.ID == fc.ID }); i >= 0 {
		c.Folders[i] = fc
	} else {
		if len(c.Folders) >= maxSyncFolders {
			return fmt.Errorf("en çok %d klasör eşitlenebilir", maxSyncFolders)
		}
		for _, f := range c.Folders {
			if filepath.Clean(f.Path) == filepath.Clean(fc.Path) {
				return errors.New("bu klasör başka bir kimlikle zaten eşitleniyor")
			}
		}
		c.Folders = append(c.Folders, fc)
	}
	if err := a.saveSyncConfig(c); err != nil {
		return err
	}
	a.closeFolder(fc.ID)
	a.log.Info("sync folder saved", "folder", fc.ID, "mode", fc.Mode, "peers", len(fc.Peers))
	return nil
}

// RemoveSyncFolder implements panel.SyncControl. Files stay where they are.
func (a *Apps) RemoveSyncFolder(id string) error {
	a.ext().sync.work.Lock()
	defer a.ext().sync.work.Unlock()
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(c.Folders, func(f syncFolderConfig) bool { return f.ID == id })
	if i < 0 {
		return errors.New("böyle bir klasör yok")
	}
	c.Folders = slices.Delete(c.Folders, i, i+1)
	c.Backup.Folders = slices.DeleteFunc(c.Backup.Folders, func(f string) bool { return f == id })
	if err := a.saveSyncConfig(c); err != nil {
		return err
	}
	a.closeFolder(id)
	return nil
}

// SyncNow implements panel.SyncControl.
func (a *Apps) SyncNow(ctx context.Context) error {
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	return a.pullAll(ctx, c)
}

// SyncVersions implements panel.SyncControl.
func (a *Apps) SyncVersions(id string) ([]panel.SyncVersionView, error) {
	f, err := a.configuredFolder(id)
	if err != nil {
		return nil, err
	}
	vs, err := f.Versions()
	if err != nil {
		return nil, err
	}
	out := make([]panel.SyncVersionView, 0, len(vs))
	for _, v := range vs {
		out = append(out, panel.SyncVersionView{Path: v.Path, Stored: v.Stored, Time: v.Time, Size: v.Size})
	}
	return out, nil
}

func (a *Apps) configuredFolder(id string) (*syncdir.Folder, error) {
	c, err := a.loadSyncConfig()
	if err != nil {
		return nil, err
	}
	fc, ok := c.folder(id)
	if !ok {
		return nil, errors.New("böyle bir klasör yok")
	}
	return a.openFolder(fc)
}

// RestoreSyncVersion implements panel.SyncControl.
func (a *Apps) RestoreSyncVersion(id, stored string) error {
	f, err := a.configuredFolder(id)
	if err != nil {
		return err
	}
	vs, err := f.Versions()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(vs, func(v syncdir.Version) bool { return v.Stored == stored })
	if i < 0 {
		return errors.New("böyle bir sürüm yok")
	}
	return f.Restore(vs[i])
}

// SetSyncBackup implements panel.SyncControl.
func (a *Apps) SetSyncBackup(ch panel.SyncBackupChange) error {
	if ch.IntervalHours < 0 || ch.IntervalHours > maxBackupHours {
		return fmt.Errorf("yedek aralığı 1 ile %d saat arasında olmalı", maxBackupHours)
	}
	a.ext().sync.work.Lock()
	defer a.ext().sync.work.Unlock()
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	b := syncBackupConfig{Enabled: ch.Enabled, Target: normalizeDevice(ch.Target), IntervalHours: ch.IntervalHours}
	for _, id := range ch.Folders {
		if _, ok := c.folder(id); !ok {
			return fmt.Errorf("klasör %q eşitleme listesinde yok", id)
		}
		if !slices.Contains(b.Folders, id) {
			b.Folders = append(b.Folders, id)
		}
	}
	if b.Enabled {
		if !validDeviceName(b.Target) || len(b.Folders) == 0 {
			return errors.New("yedek için hedef cihaz ve en az bir klasör seçilmeli")
		}
		if _, exported, err := a.backupKey(); err != nil {
			return err
		} else if !exported {
			return errors.New("önce yedek anahtarını parolayla dışa aktarıp saklayın; anahtar olmadan yedekler açılamaz")
		}
		if doc, self, ok := a.current(); ok && !doc.AllowsBackup(self.Name, b.Target) {
			return errors.New("seçilen cihazın kuralı bu cihazdan yedek kabul etmiyor")
		}
	}
	c.Backup = b
	return a.saveSyncConfig(c)
}

// ExportBackupKey implements panel.SyncControl.
func (a *Apps) ExportBackupKey(passphrase []byte) (string, error) {
	k, _, err := a.backupKey()
	if err != nil {
		return "", err
	}
	text, err := k.Export(passphrase)
	if err != nil {
		return "", err
	}
	exp := backupExport{Fingerprint: k.Fingerprint(), At: a.cfg.Now().UTC()}
	if err := saveJSON(a.syncPath(backupExportFn), exp); err != nil {
		return "", err
	}
	a.log.Info("backup key exported", "fingerprint", exp.Fingerprint)
	return text, nil
}

// BackupNow implements panel.SyncControl.
func (a *Apps) BackupNow(ctx context.Context) error {
	c, err := a.loadSyncConfig()
	if err != nil {
		return err
	}
	if !validDeviceName(c.Backup.Target) || len(c.Backup.Folders) == 0 {
		return errors.New("yedek hedefi ve klasörleri seçilmemiş")
	}
	return a.backupAll(ctx, c)
}

// BackupSnapshots implements panel.SyncControl.
func (a *Apps) BackupSnapshots(ctx context.Context) ([]panel.SyncSnapshotView, error) {
	c, err := a.loadSyncConfig()
	if err != nil {
		return nil, err
	}
	doc, self, ok := a.current()
	if !ok {
		return nil, errNoTunnel()
	}
	target, ok := doc.DeviceByName(c.Backup.Target)
	if !ok || !doc.AllowsBackup(self.Name, target.Name) {
		return nil, errors.New("yedek hedefi seçilmemiş veya kural izin vermiyor")
	}
	cl, err := syncdir.Dial(ctx, netip.AddrPortFrom(target.IPv4, trust.SyncPort))
	if err != nil {
		return nil, errors.New("yedek hedefine ulaşılamadı")
	}
	defer cl.Close()
	out := []panel.SyncSnapshotView{}
	for _, id := range c.Backup.Folders {
		names, err := syncdir.Snapshots(ctx, cl.Store(id))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			t, _ := syncdir.SnapshotTime(n)
			out = append(out, panel.SyncSnapshotView{Folder: id, Name: n, Time: t})
		}
	}
	return out, nil
}
