package autoupdate

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/rollout"
	"github.com/openscale/openscale/internal/updater"
)

// Defaults of the schedule.
const (
	// DefaultMaxJitter spreads the installs of a network over half an hour.
	DefaultMaxJitter  = 30 * time.Minute
	DefaultFirstCheck = 5 * time.Minute
	DefaultEvery      = 6 * time.Hour
	// DefaultRate stays below the coordinator's per-device control limit
	// (coordinator.DefaultControlRate, 200 per second).
	DefaultRate     = 120
	DefaultParallel = 8

	retryRejected  = 24 * time.Hour
	retryOffline   = 30 * time.Minute
	recheckInstall = 10 * time.Minute
	requestStale   = 15 * time.Minute
	takenStale     = 2 * time.Hour
	spaceReserve   = 64 << 20
)

// WaitingKeyAction tells the owner what to do while no release root key is
// installed (docs/otomatik-guncelleme.md).
const WaitingKeyAction = "Sahip: sürüm anahtarlarını kurup imzalı sürüm derleyin (docs/otomatik-guncelleme.md: releasesign root-keygen, signing-keygen, certify, sonra scripts klasöründeki sürüm betiği); ardından bu cihaza imzalı sürümü bir kez elle kurun: openscale update apply <imzalı sürüm klasörü>"

// Config configures a Runner.
type Config struct {
	Paths   Paths
	Fetcher Fetcher
	// Installed is this program's version.
	Installed string
	// GOOS and GOARCH default to this program's.
	GOOS, GOARCH string
	// LoadRoot returns the release root key; nil uses updater.LoadRootKey("").
	LoadRoot func() (release.PublicKey, error)
	// Trigger starts the privileged installer once the request is written;
	// nil leaves it to the system (the systemd path unit on Linux).
	Trigger func(ctx context.Context) error
	Now     func() time.Time
	// Jitter returns a random delay in [0, max); nil uses crypto/rand.
	Jitter                       func(max time.Duration) time.Duration
	MaxJitter, FirstCheck, Every time.Duration
	// Parallel and Rate bound the download (requests in flight, per second).
	Parallel, Rate int
	Logger         *slog.Logger
	// Rings returns this device's ring and the ring sizes from its own
	// signed document (ADR-0235); nil puts it in the main ring of a
	// network without rings.
	Rings func() RingInfo
	// Healthy reports the service's health for the rollout report; nil
	// reports healthy (the report itself crossed the tunnel).
	Healthy func() bool
}

type rejection struct {
	at      time.Time
	version string
	msg     string
}

type verifiedRelease struct {
	digest      string
	name        string
	manifest    *release.Manifest
	manifestRaw []byte
	revocations []byte
}

// Runner checks the coordinator and hands applicable releases to the
// installer.
type Runner struct {
	cfg  Config
	wake chan struct{}

	mu     sync.Mutex
	status Status
	sched  struct {
		digest string
		at     time.Time
	}
	rejected map[string]rejection
	verified *verifiedRelease
}

// New creates a runner; it reads the last saved status for the history.
func New(cfg Config) *Runner {
	if cfg.GOOS == "" {
		cfg.GOOS, cfg.GOARCH = runtime.GOOS, runtime.GOARCH
	}
	if cfg.LoadRoot == nil {
		cfg.LoadRoot = func() (release.PublicKey, error) {
			k, _, err := updater.LoadRootKey("")
			return k, err
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Jitter == nil {
		cfg.Jitter = randomJitter
	}
	if cfg.MaxJitter <= 0 {
		cfg.MaxJitter = DefaultMaxJitter
	}
	if cfg.FirstCheck <= 0 {
		cfg.FirstCheck = DefaultFirstCheck
	}
	if cfg.Every <= 0 {
		cfg.Every = DefaultEvery
	}
	if cfg.Parallel <= 0 {
		cfg.Parallel = DefaultParallel
	}
	if cfg.Rate == 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	r := &Runner{cfg: cfg, wake: make(chan struct{}, 1), rejected: map[string]rejection{}}
	if prev, err := ReadStatus(cfg.Paths.Work); err == nil {
		r.status.LastAttempt = prev.LastAttempt
	}
	st, root := r.local(r.cfg.Now())
	switch {
	case st.State != "":
	case root.IsZero():
		st.State, st.Message, st.Action = StateWaitingKey, "Sürüm imzalama anahtarı kurulmadığı için otomatik güncelleme bekliyor; imzasız sürüm kurulmaz.", WaitingKeyAction
	default:
		st.State, st.Message = StatePending, "İlk denetim bekleniyor."
	}
	st.LastAttempt = r.status.LastAttempt
	r.status = st
	return r
}

func randomJitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return limit / 2
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(limit))
}

// Status returns the last status.
func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// SetEnabled saves the switch and checks again soon.
func (r *Runner) SetEnabled(on bool) (Status, error) {
	if !r.cfg.Paths.Supported {
		return r.Status(), errors.New(r.cfg.Paths.Reason)
	}
	if err := WriteSettings(r.cfg.Paths.Settings, on); err != nil {
		return r.Status(), err
	}
	st, _ := r.local(r.cfg.Now())
	if st.State == "" {
		st.State, st.Message = StatePending, "Denetim başlıyor."
	}
	r.mu.Lock()
	st.LastAttempt, st.Latest, st.LastCheck = r.status.LastAttempt, r.status.Latest, r.status.LastCheck
	r.status = st
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return st, nil
}

// Run checks after FirstCheck (plus a random part of it), then every Every.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTimer(r.cfg.FirstCheck + r.cfg.Jitter(r.cfg.FirstCheck))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.wake:
		}
		_, next := r.Check(ctx)
		t.Reset(next)
	}
}

// local fills what this device knows without the coordinator. A non-empty
// State ends the check.
func (r *Runner) local(now time.Time) (Status, release.PublicKey) {
	p := r.cfg.Paths
	st := Status{Current: r.cfg.Installed, Mode: p.Mode, Channel: updater.ChannelStable}
	if !p.Supported {
		st.State, st.Message = StateUnsupported, p.Reason
		return st, release.PublicKey{}
	}
	set, err := ReadSettings(p.Settings)
	st.Enabled = set.Enabled
	if err != nil {
		st.State, st.Message, st.Action = StateOff, "Otomatik güncelleme ayarı okunamadı ("+err.Error()+"); kapalı sayılıyor.", "openscale update auto on"
		return st, release.PublicKey{}
	}
	if ch, err := updater.ReadChannel(p.UpdaterState); err == nil {
		st.Channel = ch
	}
	if !set.Enabled {
		st.State, st.Message, st.Action = StateOff, "Otomatik güncelleme kapalı.", "openscale update auto on"
		return st, release.PublicKey{}
	}
	if j, err := updater.ReadJournal(p.UpdaterState); err == nil && j != nil {
		st.State, st.Message, st.Action = StatePending, fmt.Sprintf("Yarım kalan bir güncelleme var (%s -> %s); otomatik güncelleme bekliyor.", j.From, j.To), "openscale update status"
		return st, release.PublicKey{}
	}
	root, err := r.cfg.LoadRoot()
	if err != nil || root.IsZero() {
		return st, release.PublicKey{}
	}
	return st, root
}

func (r *Runner) finish(st Status, next time.Duration) (Status, time.Duration) {
	now := r.cfg.Now()
	if st.LastCheck.IsZero() {
		st.LastCheck = now
	}
	if r.ringInfo().Ring != rollout.RingMain {
		next = min(next, ringReportEvery)
	}
	st.NextCheck = now.Add(next)
	r.mu.Lock()
	if st.LastAttempt == nil {
		st.LastAttempt = r.status.LastAttempt
	}
	r.status = st
	r.mu.Unlock()
	if r.cfg.Paths.Supported && r.cfg.Paths.Work != "" {
		if err := writeStatus(r.cfg.Paths.Work, st); err != nil {
			r.cfg.Logger.Warn("auto update status not saved", "error", err.Error())
		}
	}
	return st, next
}

// Check runs one round and returns the status and when to check again.
func (r *Runner) Check(ctx context.Context) (Status, time.Duration) {
	now := r.cfg.Now()
	r.absorbResult()
	st, root := r.local(now)
	st.LastCheck = now
	if st.State != "" {
		return r.finish(st, r.cfg.Every)
	}
	p := r.cfg.Paths
	if r.cfg.Fetcher == nil {
		st.State, st.Message = StateUnreachable, "Tünel yok; koordinatöre ulaşılamıyor."
		return r.finish(st, retryOffline)
	}
	ann, err := announce(ctx, r.cfg.Fetcher, r.report())
	st.Source, st.SourceChecked = ann.Source, ann.Checked
	st.Ring = r.ringInfo().Ring
	if ann.Rollout != nil {
		// The progress also on devices that wait for nothing (ringGate
		// adds this device's own floor).
		st.Rollout = rolloutStatus(ann.Rollout, time.Time{}, rollout.Decision{})
	}
	switch {
	case errors.Is(err, ErrNotServed):
		st.State, st.Message = StateNoRelease, "Koordinatör sürüm dağıtmıyor (eski koordinatör sürümü)."
		return r.finish(st, r.cfg.Every)
	case err != nil:
		st.State, st.Message = StateUnreachable, "Koordinatöre ulaşılamadı: "+err.Error()
		return r.finish(st, retryOffline)
	case ann.Version == "":
		st.State, st.Message, st.Action = StateNoRelease, "Koordinatörde yayımlanmış bir sürüm yok.", "Sahip, koordinatör sunucusunda: openscale update publish --dir <imzalı sürüm klasörü>"
		return r.finish(st, r.cfg.Every)
	}
	st.Latest = ann.Version
	if c, err := release.CompareVersions(r.cfg.Installed, ann.Version); err == nil && c >= 0 {
		st.State, st.Message = StateUpToDate, "Bu cihaz güncel."
		return r.finish(st, r.cfg.Every)
	}
	if root.IsZero() {
		st.State = StateWaitingKey
		st.Message = "Sürüm imzalama anahtarı kurulmadığı için otomatik güncelleme bekliyor; imzasız sürüm kurulmaz. Koordinatörün ilan ettiği " + ann.Version + " doğrulanamadı."
		st.Action = WaitingKeyAction
		return r.finish(st, r.cfg.Every)
	}
	r.mu.Lock()
	rej, rejected := r.rejected[ann.Digest]
	r.mu.Unlock()
	if rejected && now.Sub(rej.at) < retryRejected {
		st.State, st.Message = StateRejected, rej.msg
		return r.finish(st, r.cfg.Every)
	}
	if st2, wait, busy := r.pendingInstall(st, now); busy {
		return r.finish(st2, wait)
	}
	v, err := r.verify(ctx, root, ann)
	if err != nil {
		if errors.Is(err, updater.ErrAlreadyLatest) {
			st.State, st.Message = StateUpToDate, "Bu cihaz güncel."
			return r.finish(st, r.cfg.Every)
		}
		if errors.Is(err, ErrReleaseChanged) || isNetErr(err) {
			st.State, st.Message = StateUnreachable, "İndirme yarıda kaldı: "+err.Error()
			return r.finish(st, retryOffline)
		}
		msg := "Koordinatördeki " + ann.Version + " reddedildi: " + err.Error()
		r.reject(ann.Digest, ann.Version, msg)
		st.State, st.Message = StateRejected, msg
		return r.finish(st, r.cfg.Every)
	}
	st.Latest, st.LatestVerified = v.manifest.Version, true
	// Rings before the random delay: the delay starts once the ring opens,
	// so a ring's devices do not all install the moment it does.
	if next, ok := r.ringGate(&st, ann, now); !ok {
		return r.finish(st, next)
	}
	r.mu.Lock()
	if r.sched.digest != ann.Digest {
		r.sched.digest, r.sched.at = ann.Digest, now.Add(r.cfg.Jitter(r.cfg.MaxJitter))
	}
	at := r.sched.at
	r.mu.Unlock()
	if now.Before(at) {
		st.State, st.ScheduledAt = StateScheduled, at
		st.Message = "İmzalı " + v.manifest.Version + " doğrulandı; ağdaki cihazlar aynı anda yeniden başlamasın diye kurulum rastgele bir gecikmeyle yapılacak."
		return r.finish(st, min(at.Sub(now), r.cfg.Every))
	}
	req, err := r.fetchPayload(ctx, v)
	if err != nil {
		if errors.Is(err, ErrReleaseChanged) || isNetErr(err) {
			st.State, st.Message = StateUnreachable, "İndirme yarıda kaldı: "+err.Error()
			return r.finish(st, retryOffline)
		}
		msg := "Koordinatördeki " + v.manifest.Version + " kurulmadı: " + err.Error()
		r.reject(ann.Digest, v.manifest.Version, msg)
		st.State, st.Message = StateRejected, msg
		return r.finish(st, r.cfg.Every)
	}
	if err := writeJSON(filepath.Join(p.Work, RequestFile), req); err != nil {
		st.State, st.Message = StateFailed, "Kurulum isteği yazılamadı: "+err.Error()
		return r.finish(st, retryOffline)
	}
	r.cfg.Logger.Info("auto update handed to the installer", "release", req.Version)
	if r.cfg.Trigger != nil {
		if err := r.cfg.Trigger(ctx); err != nil {
			_ = os.Remove(filepath.Join(p.Work, RequestFile))
			st.State, st.Message = StateFailed, "Kurulum yardımcısı başlatılamadı: "+err.Error()
			return r.finish(st, retryOffline)
		}
	}
	st.State, st.Message = StateInstalling, "İmzalı "+req.Version+" indirildi ve doğrulandı; kuruluyor. Servis kısa süre yeniden başlayacak."
	return r.finish(st, recheckInstall)
}

// isNetErr: the tunnel or the coordinator failed, not the release. The text
// is node.ErrNoReply's (this package does not import node).
func isNetErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || err.Error() == "coordinator did not reply"
}

func (r *Runner) reject(digest, version, msg string) {
	r.mu.Lock()
	r.rejected[digest] = rejection{at: r.cfg.Now(), version: version, msg: msg}
	r.verified = nil
	r.mu.Unlock()
	r.cfg.Logger.Warn("auto update refused a release", "release", version, "reason", msg)
}

// pendingInstall reports a request the installer has not finished.
func (r *Runner) pendingInstall(st Status, now time.Time) (Status, time.Duration, bool) {
	work := r.cfg.Paths.Work
	if info, err := os.Stat(filepath.Join(work, TakenFile)); err == nil {
		if now.Sub(info.ModTime()) < takenStale {
			st.State, st.Message = StateInstalling, "Kurulum sürüyor."
			return st, recheckInstall, true
		}
		_ = os.Remove(filepath.Join(work, TakenFile))
	}
	info, err := os.Stat(filepath.Join(work, RequestFile))
	if err != nil {
		return st, 0, false
	}
	st.State = StateInstalling
	if now.Sub(info.ModTime()) < requestStale {
		st.Message = "Kurulum yardımcısı bekleniyor."
		return st, recheckInstall, true
	}
	st.Message = "Kurulum yardımcısı isteği almadı."
	if runtime.GOOS == "linux" {
		st.Action = "sudo systemctl enable --now openscale-autoupdate.path"
	} else {
		st.Action = "openscale update auto install (yönetici olarak)"
	}
	return st, r.cfg.Every, true
}

// absorbResult takes the installer's report and clears its work files.
func (r *Runner) absorbResult() {
	work := r.cfg.Paths.Work
	if work == "" {
		return
	}
	res, err := readResult(work)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	_ = os.Remove(filepath.Join(work, ResultFile))
	_ = os.Remove(filepath.Join(work, TakenFile))
	_ = os.Remove(filepath.Join(work, RequestFile))
	_ = os.RemoveAll(filepath.Join(work, CacheDir))
	if err != nil {
		return
	}
	a := &Attempt{Version: res.Version, At: res.At, OK: res.OK, RolledBack: res.RolledBack, Message: res.Message}
	r.mu.Lock()
	r.status.LastAttempt = a
	r.verified = nil
	if !res.OK {
		r.rejected[res.Digest] = rejection{at: res.At, version: res.Version, msg: "Son kurulum denemesi başarısız: " + res.Message}
	}
	r.mu.Unlock()
}

// verify fetches the manifest and the revocation list and judges them as
// the installer will; nothing on this device changes.
func (r *Runner) verify(ctx context.Context, root release.PublicKey, ann announcement) (*verifiedRelease, error) {
	r.mu.Lock()
	if r.verified != nil && r.verified.digest == ann.Digest {
		v := r.verified
		r.mu.Unlock()
		return v, nil
	}
	r.mu.Unlock()
	if ann.Size > release.MaxSignedReleaseSize {
		return nil, errors.New("imzalı sürüm dosyası çok büyük")
	}
	cache := filepath.Join(r.cfg.Paths.Work, CacheDir)
	if err := os.RemoveAll(cache); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, err
	}
	raw, err := r.fetchSmall(ctx, ann.Digest, ann.Manifest, release.MaxSignedReleaseSize, int64(ann.Size))
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != ann.Digest {
		return nil, ErrReleaseChanged
	}
	revs, err := r.fetchSmall(ctx, ann.Digest, updater.RevocationsFile, release.MaxRevocationsSize, 0)
	if errors.Is(err, ErrFileMissing) {
		revs, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	artifact, _, _, err := ArtifactFor(r.cfg.Paths.Mode, r.cfg.GOOS, r.cfg.GOARCH, ann.Version)
	if err != nil {
		return nil, err
	}
	opts := updater.Options{Root: root, Artifact: artifact, StateDir: r.cfg.Paths.UpdaterState, Now: r.cfg.Now}
	vr, err := updater.VerifySource(opts, updater.Source{Manifest: raw, Revocations: revs})
	if err != nil {
		return nil, err
	}
	m := &vr.Manifest
	if m.Version != ann.Version {
		return nil, fmt.Errorf("koordinatör %s ilan etti ama imzalı sürüm %s", ann.Version, m.Version)
	}
	if err := updater.CheckChannel(m.Version, channelBeta(r.cfg.Paths.UpdaterState)); err != nil {
		return nil, err
	}
	if err := release.CheckUpgrade(r.cfg.Installed, m.Version, false); err != nil {
		return nil, fmt.Errorf("geri alma koruması: kurulu %s, aday %s: %w", r.cfg.Installed, m.Version, err)
	}
	if c, err := release.CompareVersions(r.cfg.Installed, m.Version); err == nil && c == 0 {
		return nil, updater.ErrAlreadyLatest
	}
	if err := os.WriteFile(filepath.Join(cache, ann.Manifest), raw, 0o600); err != nil {
		return nil, err
	}
	if revs != nil {
		if err := os.WriteFile(filepath.Join(cache, updater.RevocationsFile), revs, 0o600); err != nil {
			return nil, err
		}
	}
	v := &verifiedRelease{digest: ann.Digest, name: ann.Manifest, manifest: m, manifestRaw: raw, revocations: revs}
	r.mu.Lock()
	r.verified = v
	r.mu.Unlock()
	return v, nil
}

func channelBeta(stateDir string) bool {
	ch, err := updater.ReadChannel(stateDir)
	return err == nil && ch == updater.ChannelBeta
}

// fetchSmall downloads a file of at most limit bytes into memory through a
// temporary file in the cache.
func (r *Runner) fetchSmall(ctx context.Context, digest, name string, limit, exact int64) ([]byte, error) {
	path := filepath.Join(r.cfg.Paths.Work, CacheDir, ".part-"+name)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)
	defer f.Close()
	n, err := download(ctx, r.cfg.Fetcher, digest, name, limit, exact, r.cfg.Parallel, r.cfg.Rate, f)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, n))
}

// fetchPayload downloads the program or package and checks it against the
// verified manifest before anything is handed to the installer.
func (r *Runner) fetchPayload(ctx context.Context, v *verifiedRelease) (Request, error) {
	p := r.cfg.Paths
	m := v.manifest
	artifact, mirror, compressed, err := ArtifactFor(p.Mode, r.cfg.GOOS, r.cfg.GOARCH, m.Version)
	if err != nil {
		return Request{}, err
	}
	art, ok := m.Lookup(artifact)
	if !ok {
		return Request{}, fmt.Errorf("%s bu sürümde yok", artifact)
	}
	if free, err := diskguard.Free(p.Work); err == nil && free < uint64(art.Size)*3+spaceReserve {
		return Request{}, fmt.Errorf("diskte yeterli boş alan yok (%d MB)", free>>20)
	}
	limit, exact := art.Size, art.Size
	if compressed {
		// gzip adds a few bytes per 32 KiB block, even to random data.
		limit, exact = art.Size+art.Size/64+(1<<20), 0
	}
	cache := filepath.Join(p.Work, CacheDir)
	part := filepath.Join(cache, ".part-"+mirror)
	f, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Request{}, err
	}
	defer os.Remove(part)
	r.mu.Lock()
	r.status.State, r.status.Message = StateDownloading, "İmzalı "+m.Version+" koordinatörden tünel içinden indiriliyor."
	r.mu.Unlock()
	if _, err := download(ctx, r.cfg.Fetcher, v.digest, mirror, limit, exact, r.cfg.Parallel, r.cfg.Rate, f); err != nil {
		f.Close()
		return Request{}, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return Request{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return Request{}, err
	}
	var in io.Reader = f
	if compressed {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return Request{}, fmt.Errorf("sıkıştırılmış program bozuk: %w", err)
		}
		in = gz
	}
	err = m.CheckFile(artifact, in)
	f.Close()
	if err != nil {
		return Request{}, err
	}
	if err := os.Rename(part, filepath.Join(cache, mirror)); err != nil {
		return Request{}, err
	}
	req := Request{
		Format: requestFormat, Version: m.Version, Digest: v.digest, Mode: p.Mode,
		Manifest: v.name, Payload: mirror, Artifact: artifact, Compressed: compressed, Created: r.cfg.Now().UTC(),
	}
	if v.revocations != nil {
		req.Revocations = updater.RevocationsFile
	}
	if _, err := os.Stat(filepath.Join(cache, req.Manifest)); err != nil {
		return Request{}, errors.New("doğrulanan manifesto önbellekte yok")
	}
	return req, nil
}
