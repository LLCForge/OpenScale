package syncdir

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	indexFileName = "index.json"
	versionsDir   = MetaDir + "/versions"
	tmpDir        = MetaDir + "/tmp"
	maxStateFile  = 512 << 20

	// DefaultVersions is how many earlier versions of a file are kept.
	DefaultVersions = 5
	// DefaultVersionMaxAge removes older versions.
	DefaultVersionMaxAge = 30 * 24 * time.Hour

	versionStamp = "20060102T150405.000000000Z"
)

// FolderConfig configures one synchronized folder.
type FolderConfig struct {
	// ID names the folder between devices (lower case letters, digits
	// and dashes).
	ID string
	// Path is the local directory; it must exist.
	Path string
	Mode FolderMode
	// PropagateDeletes deletes files the peer deleted (they go to the
	// version store). Off by default.
	PropagateDeletes bool
	// Versions keeps this many earlier versions of each file replaced or
	// deleted by a pull (default 5; negative keeps none).
	Versions int
	// VersionMaxAge removes versions older than this (default 30 days).
	VersionMaxAge time.Duration
	// MaxFileSize skips larger files (default 64 GiB).
	MaxFileSize int64
	// Guard tunes the ransomware guard (#453, guard.go); on by default.
	Guard GuardConfig
	// OnAlarm, when set, is called (in its own goroutine) when the guard
	// suspends the folder.
	OnAlarm func(id string, a Alarm)
}

// Folder is an open synchronized folder. All file access goes through
// os.Root, so symbolic links and ".." never lead outside it.
type Folder struct {
	cfg  FolderConfig
	root *os.Root

	mu    sync.Mutex // guards cache, alarm and the state files
	cache Index
	alarm *Alarm // the guard suspended the folder (guard.go)

	pull sync.Mutex // one pull at a time
}

// OpenFolder opens cfg.Path and its state directory.
func OpenFolder(cfg FolderConfig) (*Folder, error) {
	if !ValidID(cfg.ID) {
		return nil, fmt.Errorf("syncdir: geçersiz klasör kimliği %q", cfg.ID)
	}
	if cfg.Mode == "" {
		cfg.Mode = SendReceive
	}
	if !cfg.Mode.Valid() {
		return nil, fmt.Errorf("syncdir: geçersiz klasör kipi %q", cfg.Mode)
	}
	if cfg.Versions == 0 {
		cfg.Versions = DefaultVersions
	}
	if cfg.VersionMaxAge <= 0 {
		cfg.VersionMaxAge = DefaultVersionMaxAge
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = DefaultMaxFileSize
	}
	root, err := os.OpenRoot(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("syncdir: klasör açılamadı: %w", err)
	}
	for _, d := range []string{MetaDir, versionsDir, tmpDir} {
		if err := root.MkdirAll(d, 0o700); err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("syncdir: durum klasörü oluşturulamadı: %w", err)
		}
	}
	f := &Folder{cfg: cfg, root: root}
	if data, err := root.ReadFile(MetaDir + "/" + indexFileName); err == nil {
		if ix, err := unmarshalIndex(data); err == nil {
			f.cache = ix
		}
	}
	f.loadGuard()
	f.cleanTmp()
	return f, nil
}

// Config returns the folder's configuration.
func (f *Folder) Config() FolderConfig { return f.cfg }

// Close releases the folder.
func (f *Folder) Close() error { return f.root.Close() }

func (f *Folder) cleanTmp() {
	entries, err := fs.ReadDir(f.root.FS(), tmpDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = f.root.Remove(tmpDir + "/" + e.Name())
	}
}

// Scan walks the folder and returns its index. Files whose size and
// modification time did not change since the last scan keep their hash;
// others are hashed. Symbolic links, devices and names that cannot be
// synchronized safely are skipped. While the guard suspends the folder,
// and when this scan looks like ransomware at work, it returns
// ErrSuspended (guard.go).
func (f *Folder) Scan() (Index, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scanLocked(true)
}

func (f *Folder) scanLocked(judge bool) (Index, error) {
	if f.alarm != nil {
		return nil, ErrSuspended
	}
	prev := f.cache
	ix := Index{}
	fsys := f.root.FS()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == "." {
				return err
			}
			return nil // unreadable entries are skipped
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if strings.EqualFold(p, MetaDir) || ValidatePath(p) != nil {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || ValidatePath(p) != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > f.cfg.MaxFileSize {
			return nil
		}
		e := Entry{Size: info.Size(), MTime: mtimeOf(info)}
		if old, ok := prev[p]; ok && old.Size == e.Size && old.MTime == e.MTime {
			e.Hash = old.Hash
		} else {
			h, err := f.hashFile(p)
			if err != nil {
				return nil
			}
			e.Hash = h
		}
		if len(ix) >= MaxEntries {
			return fmt.Errorf("syncdir: klasörde %d dosyadan fazlası var", MaxEntries)
		}
		ix[p] = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	if judge && len(prev) > 0 {
		if a := Assess(f.cfg.Guard, prev, ix, f.sampleFile); a != nil {
			// The previous index stays the baseline; nothing of this scan
			// is served, pulled over or backed up.
			f.setAlarmLocked(a, time.Now())
			return nil, ErrSuspended
		}
	}
	f.cache = ix
	if data, err := marshalIndex(ix); err == nil {
		_ = f.writeState(indexFileName, data)
	}
	return ix, nil
}

func (f *Folder) hashFile(p string) (string, error) {
	r, err := f.root.Open(p)
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeState atomically replaces a state file inside MetaDir.
func (f *Folder) writeState(name string, data []byte) error {
	tmp := tmpDir + "/" + randomName() + ".state"
	w, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		_ = f.root.Remove(tmp)
		return err
	}
	if err := w.Sync(); err != nil {
		_ = w.Close()
		_ = f.root.Remove(tmp)
		return err
	}
	if err := w.Close(); err != nil {
		_ = f.root.Remove(tmp)
		return err
	}
	if err := f.root.Rename(tmp, MetaDir+"/"+name); err != nil {
		_ = f.root.Remove(tmp)
		return err
	}
	return nil
}

func randomName() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func baseName(peer string) string {
	h := sha256.Sum256([]byte(peer))
	return "base-" + hex.EncodeToString(h[:8]) + ".json"
}

func (f *Folder) loadBase(peer string) Index {
	data, err := f.root.ReadFile(MetaDir + "/" + baseName(peer))
	if err != nil || len(data) > maxStateFile {
		return Index{}
	}
	ix, err := unmarshalIndex(data)
	if err != nil {
		return Index{}
	}
	return ix
}

// Source is where a pull reads the peer's folder from.
type Source interface {
	// Index returns the peer's current index.
	Index(ctx context.Context) (Index, error)
	// Fetch writes the file at p, which must have the given hash and
	// size, to w.
	Fetch(ctx context.Context, p string, e Entry, w io.Writer) error
}

// PullResult reports what a pull did.
type PullResult struct {
	Fetched   int
	Deleted   int
	Conflicts int
	Skipped   []Skipped
	// Failed lists paths whose action failed; they are retried next time.
	Failed []Skipped
}

// Pull brings the folder up to date with the peer's copy (#134). peer
// names the device; the state both last agreed on is kept per peer.
func (f *Folder) Pull(ctx context.Context, peer string, src Source) (PullResult, error) {
	if f.cfg.Mode == SendOnly {
		return PullResult{}, ErrSendOnly
	}
	f.pull.Lock()
	defer f.pull.Unlock()
	local, err := f.Scan()
	if err != nil {
		return PullResult{}, err
	}
	remote, err := src.Index(ctx)
	if err != nil {
		return PullResult{}, err
	}
	for p, e := range remote {
		// The source is the peer; its names are checked here as well.
		if ValidatePath(p) != nil || !e.valid(1<<62) {
			return PullResult{}, fmt.Errorf("%w: geçersiz dizin girdisi", ErrProtocol)
		}
	}
	base := f.loadBase(peer)
	if a := AssessIndexes(f.cfg.Guard, base, remote); a != nil {
		a.Source = "peer:" + peer
		f.mu.Lock()
		f.setAlarmLocked(a, time.Now())
		f.mu.Unlock()
		return PullResult{}, ErrSuspended
	}
	acts, skipped := Plan(f.cfg.Mode, local, remote, base, PlanOptions{PropagateDeletes: f.cfg.PropagateDeletes, MaxFileSize: f.cfg.MaxFileSize})
	res := PullResult{Skipped: skipped}
	now := time.Now()
	for _, a := range acts {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := f.apply(ctx, src, a, now); err != nil {
			res.Failed = append(res.Failed, Skipped{a.Path, err.Error()})
			continue
		}
		switch a.Kind {
		case ActFetch:
			res.Fetched++
		case ActDelete:
			res.Deleted++
		default:
			res.Conflicts++
		}
	}
	// The agreed state: paths where both sides now hold the same content.
	// Everything else keeps its old base entry, so an unfinished action or
	// a change the peer has not pulled yet is compared correctly next time.
	// The files this pull placed are verified downloads, not local
	// changes, so this scan is not judged by the guard.
	f.mu.Lock()
	after, err := f.scanLocked(false)
	f.mu.Unlock()
	if err != nil {
		return res, err
	}
	nb := Index{}
	for p, b := range base {
		if _, inL := after[p]; !inL {
			if _, inR := remote[p]; !inR {
				continue
			}
		}
		nb[p] = b
	}
	for p, l := range after {
		if r, ok := remote[p]; ok && r.Hash == l.Hash {
			nb[p] = l
		}
	}
	data, err := marshalIndex(nb)
	if err != nil {
		return res, err
	}
	if err := f.writeState(baseName(peer), data); err != nil {
		return res, fmt.Errorf("syncdir: eşitleme durumu yazılamadı: %w", err)
	}
	f.pruneVersions(now)
	return res, nil
}

var errChangedLocally = errors.New("dosya eşitleme sırasında burada değişti; sonraki eşitlemede yeniden denenecek")

// unchanged checks that p still matches what the plan saw (absent when
// want is nil).
func (f *Folder) unchanged(p string, want *Entry) error {
	info, err := f.root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		if want == nil {
			return nil
		}
		return errChangedLocally
	}
	if err != nil {
		return err
	}
	if want == nil || !info.Mode().IsRegular() || info.Size() != want.Size {
		return errChangedLocally
	}
	if mtimeOf(info) != want.MTime {
		if h, err := f.hashFile(p); err != nil || h != want.Hash {
			return errChangedLocally
		}
	}
	return nil
}

func (f *Folder) apply(ctx context.Context, src Source, a Action, now time.Time) error {
	switch a.Kind {
	case ActDelete:
		if err := f.unchanged(a.Path, a.Local); err != nil {
			return err
		}
		return f.archive(a.Path, now)
	case ActFetch:
		tmp, err := f.download(ctx, src, a.Path, a.Remote)
		if err != nil {
			return err
		}
		defer f.root.Remove(tmp)
		if err := f.unchanged(a.Path, a.Local); err != nil {
			return err
		}
		if a.Local != nil {
			if err := f.archive(a.Path, now); err != nil {
				return err
			}
		}
		return f.place(tmp, a.Path)
	case ActConflictKeepLocal:
		if _, err := f.root.Lstat(a.ConflictPath); err == nil {
			return nil // already there from an earlier pull
		}
		tmp, err := f.download(ctx, src, a.Path, a.Remote)
		if err != nil {
			return err
		}
		defer f.root.Remove(tmp)
		return f.place(tmp, a.ConflictPath)
	case ActConflictTakeRemote:
		tmp, err := f.download(ctx, src, a.Path, a.Remote)
		if err != nil {
			return err
		}
		defer f.root.Remove(tmp)
		if err := f.unchanged(a.Path, a.Local); err != nil {
			return err
		}
		if _, err := f.root.Lstat(a.ConflictPath); err == nil {
			// The loser is already kept; keep this copy as a version.
			if err := f.archive(a.Path, now); err != nil {
				return err
			}
		} else if err := f.root.Rename(a.Path, a.ConflictPath); err != nil {
			return err
		}
		return f.place(tmp, a.Path)
	}
	return fmt.Errorf("syncdir: bilinmeyen işlem %d", a.Kind)
}

// download fetches e into a temporary file, checking size and hash, and
// sets its modification time to the peer's.
func (f *Folder) download(ctx context.Context, src Source, p string, e Entry) (string, error) {
	tmp := tmpDir + "/" + randomName() + ".part"
	w, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	lw := &limitWriter{w: io.MultiWriter(w, h), left: e.Size}
	ferr := src.Fetch(ctx, p, e, lw)
	cerr := w.Close()
	if ferr == nil {
		ferr = cerr
	}
	if ferr == nil && (lw.left != 0 || hex.EncodeToString(h.Sum(nil)) != e.Hash) {
		ferr = errors.New("indirilen dosya doğrulanamadı")
	}
	if ferr != nil {
		_ = f.root.Remove(tmp)
		return "", ferr
	}
	mt := time.Unix(0, e.MTime)
	_ = f.root.Chtimes(tmp, mt, mt)
	return tmp, nil
}

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > l.left {
		return 0, errors.New("eş beklenenden fazla veri gönderdi")
	}
	n, err := l.w.Write(b)
	l.left -= int64(n)
	return n, err
}

// place moves a verified temporary file to p, creating parent folders.
// p must be absent.
func (f *Folder) place(tmp, p string) error {
	if dir := path.Dir(p); dir != "." {
		if err := f.root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if _, err := f.root.Lstat(p); err == nil {
		return errChangedLocally
	}
	return f.root.Rename(tmp, p)
}

// archive moves p into the version store (#136), or deletes it when the
// folder keeps no versions.
func (f *Folder) archive(p string, now time.Time) error {
	if f.cfg.Versions < 0 {
		return f.root.Remove(p)
	}
	dir, file := path.Split(p)
	ext := path.Ext(file)
	if ext == file || len(ext) > 16 {
		ext = ""
	}
	name := strings.TrimSuffix(file, ext) + "~" + now.UTC().Format(versionStamp) + ext
	dst := versionsDir + "/" + dir + name
	if err := f.root.MkdirAll(path.Dir(dst), 0o700); err != nil {
		return err
	}
	return f.root.Rename(p, dst)
}

// Version is one kept earlier version of a file.
type Version struct {
	// Path is the original folder-relative path.
	Path string
	// Stored is the version's path relative to the folder.
	Stored string
	Time   time.Time
	Size   int64
}

// splitVersion parses "stem~STAMP.ext".
func splitVersion(name string) (string, time.Time, bool) {
	i := strings.LastIndexByte(name, '~')
	if i < 0 || i+1+len(versionStamp) > len(name) {
		return "", time.Time{}, false
	}
	t, err := time.Parse(versionStamp, name[i+1:i+1+len(versionStamp)])
	if err != nil {
		return "", time.Time{}, false
	}
	return name[:i] + name[i+1+len(versionStamp):], t, true
}

// Versions lists the kept versions, newest first per path.
func (f *Folder) Versions() ([]Version, error) {
	var out []Version
	err := fs.WalkDir(f.root.FS(), versionsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		dir, name := path.Split(strings.TrimPrefix(p, versionsDir+"/"))
		orig, t, ok := splitVersion(name)
		if !ok {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, Version{Path: dir + orig, Stored: p, Time: t, Size: info.Size()})
		return nil
	})
	slices.SortFunc(out, func(a, b Version) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return b.Time.Compare(a.Time)
	})
	return out, err
}

// Restore copies a kept version back to its path. The current file, if
// any, becomes a version itself.
func (f *Folder) Restore(v Version) error {
	if ValidatePath(v.Path) != nil || !strings.HasPrefix(v.Stored, versionsDir+"/") {
		return ErrBadPath
	}
	f.pull.Lock()
	defer f.pull.Unlock()
	now := time.Now()
	if _, err := f.root.Lstat(v.Path); err == nil {
		if err := f.archive(v.Path, now); err != nil {
			return err
		}
	}
	if dir := path.Dir(v.Path); dir != "." {
		if err := f.root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return f.root.Rename(v.Stored, v.Path)
}

// pruneVersions keeps the newest Versions per path and drops those older
// than VersionMaxAge.
func (f *Folder) pruneVersions(now time.Time) {
	vs, err := f.Versions()
	if err != nil {
		return
	}
	count := map[string]int{}
	for _, v := range vs {
		count[v.Path]++
		if count[v.Path] > max(f.cfg.Versions, 0) || now.Sub(v.Time) > f.cfg.VersionMaxAge {
			_ = f.root.Remove(v.Stored)
		}
	}
}

// mtimeOf rounds modification times to milliseconds, which every
// supported file system keeps, so a time set on one device compares equal
// on another.
func mtimeOf(info fs.FileInfo) int64 { return info.ModTime().Truncate(time.Millisecond).UnixNano() }
