// Package updater installs a signed OpenScale release over the installed
// program and rolls it back when the new version does not start (#203,
// #204, ADR-0095). There is no update server: the release comes from a
// file or from the owner's own HTTPS server, and nothing is trusted before
// release.Verify accepts the signed manifest (ADR-0022).
//
// Order of an update, chosen so that the tunnel is down only between the
// service stop and start:
//  1. verify the signed manifest, the rollback rule and the free space;
//  2. stage the program next to the installed one and check its size and
//     SHA-256 against the manifest (the staged copy is what runs, so the
//     file cannot change between check and use);
//  3. run "<staged> version --json" and require the manifest's version;
//  4. write the journal, stop the services, rename the installed program
//     to <exe>.prev (a running image can be renamed on Windows too) and
//     the staged one into its place;
//  5. start the services and wait until each runs with one stable process
//     (and, where the service reports it, with the new version);
//  6. on failure stop them, put <exe>.prev back and start them again.
//
// The kill switch (ADR-0023) stays in place while the service is stopped,
// so the gap blocks traffic instead of leaking it; tunnels come back with
// the cached endpoints (F-005) within seconds of the start.
package updater

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/privsep"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

const (
	// JournalFile records an update between the swap and its outcome.
	JournalFile = "update-journal.json"
	// InstalledManifestFile is the signed manifest of the installed
	// release, kept for the start-up integrity check (#172).
	InstalledManifestFile = "installed.release.json"
	// InstalledArtifactFile names the installed program in that manifest.
	InstalledArtifactFile = "installed.artifact"
	// MarkerFile is written by a service that started (service package).
	MarkerFile = "running.json"

	// PrevSuffix is the previous program kept for rollback.
	PrevSuffix = ".prev"
	// FailedSuffix is a program that did not start, kept for diagnosis.
	FailedSuffix = ".failed"

	journalFormat   = "openscale-update-journal-v1"
	maxJournal      = 16 << 10
	maxMarker       = 4 << 10
	spaceMargin     = 16 << 20
	defaultHealth   = 90 * time.Second
	defaultStable   = 10 * time.Second
	defaultPoll     = 500 * time.Millisecond
	rollbackHealth  = 60 * time.Second
	maxArtifactName = 128
)

// Journal states.
const (
	StateStaged         = "staged"
	StateSwapped        = "swapped"
	StateRollbackFailed = "rollback-failed"
)

// Errors.
var (
	ErrPending       = errors.New("önceki bir güncelleme yarım kalmış; önce 'openscale update status' ve gerekirse 'openscale update rollback'")
	ErrNoSpace       = errors.New("güncelleme için diskte yeterli boş alan yok")
	ErrVersionDiffer = errors.New("indirilen programın bildirdiği sürüm manifestodaki sürümle aynı değil")
	ErrUnhealthy     = errors.New("yeni sürümle servis kararlı biçimde başlamadı")
	ErrNoPrevious    = errors.New("geri dönülecek önceki program yok")
	ErrAlreadyLatest = errors.New("bu sürüm zaten kurulu")
)

// Service is one service the update stops and starts.
type Service interface {
	Name() string
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
	Status(ctx context.Context) (ServiceState, error)
}

// ServiceState is what the health check needs to know.
type ServiceState struct {
	Installed bool
	Running   bool
	// PID is the service process; 0 when the platform does not tell.
	PID int
}

// Marker is what a started service writes (MarkerFile).
type Marker struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
}

// Options configure Apply and Rollback.
type Options struct {
	// Exe is the installed program that is replaced.
	Exe string
	// Artifact is the program's name in the manifest for this platform.
	Artifact string
	// Installed overrides the installed version; empty asks Exe.
	Installed string
	// Root verifies the manifest; RootFingerprint, when set, must match.
	Root            release.PublicKey
	RootFingerprint string
	Revocations     *release.Revocations
	AllowDowngrade  bool
	// AllowPrerelease installs a beta for this run; otherwise only the
	// saved beta channel allows one (channel.go, ADR-0193).
	AllowPrerelease bool
	// Reinstall allows installing the same version again.
	Reinstall bool
	// StateDir holds the journal and the installed manifest.
	StateDir string
	// Services are stopped before the swap and, if they were running,
	// started and health-checked after it.
	Services []Service
	// ProgramVersion runs a program and returns the version it reports;
	// nil uses RunVersion.
	ProgramVersion func(ctx context.Context, exe string) (string, error)
	// ReadMarker returns what the service wrote after starting; nil skips
	// the marker check (the Linux units do not write one).
	ReadMarker func() (Marker, error)
	// KeyFiles lists the key files whose storage scheme (DPAPI or plain)
	// is compared before and after, for the rollback warning.
	KeyFiles func() []string

	HealthTimeout time.Duration
	StableFor     time.Duration
	PollEvery     time.Duration
	Now           func() time.Time
	// Logf reports progress (Turkish); nil discards it.
	Logf func(format string, args ...any)
}

func (o *Options) defaults() {
	if o.ProgramVersion == nil {
		o.ProgramVersion = RunVersion
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = defaultHealth
	}
	if o.StableFor <= 0 {
		o.StableFor = defaultStable
	}
	if o.PollEvery <= 0 {
		o.PollEvery = defaultPoll
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.KeyFiles == nil {
		o.KeyFiles = func() []string { return nil }
	}
}

// Source is a release to install: the signed manifest and the program.
type Source struct {
	Manifest []byte
	// Revocations is the signed revocation list published next to the
	// manifest, if any (RevocationsFile).
	Revocations []byte
	// Open returns the program's bytes; it is called once, after the
	// manifest was verified.
	Open func(ctx context.Context) (io.ReadCloser, error)
	// Where describes the source for messages.
	Where string
}

// Result describes a finished Apply or Rollback.
type Result struct {
	From, To string
	// Downtime is the time between the service stop and a healthy start.
	Downtime time.Duration
	// Restarted is false when no service was running (the new program is
	// used at the next start).
	Restarted  bool
	RolledBack bool
	Warnings   []string
}

// Journal is the persisted progress of an update.
type Journal struct {
	Format  string    `json:"format"`
	State   string    `json:"state"`
	Exe     string    `json:"exe"`
	Staged  string    `json:"staged,omitempty"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Started time.Time `json:"started"`
	// Running lists the services that were running before the stop.
	Running []string `json:"running,omitempty"`
	// PlainKeys lists key files that were not DPAPI-protected before.
	PlainKeys []string `json:"plain_keys,omitempty"`
}

// ReadJournal returns the pending journal in stateDir, or nil.
func ReadJournal(stateDir string) (*Journal, error) {
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, JournalFile), maxJournal)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(data, &j); err != nil || j.Format != journalFormat {
		return nil, fmt.Errorf("güncelleme günlüğü bozuk: %s", filepath.Join(stateDir, JournalFile))
	}
	return &j, nil
}

func writeJournal(stateDir string, j *Journal) error {
	j.Format = journalFormat
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return diskguard.WriteCritical(stateDir, func() error {
		return securefile.Replace(filepath.Join(stateDir, JournalFile), data)
	})
}

func removeJournal(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, JournalFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// ReadMarkerFile reads a MarkerFile.
func ReadMarkerFile(path string) (Marker, error) {
	data, err := securefile.ReadPrivate(path, maxMarker)
	if err != nil {
		return Marker{}, err
	}
	var m Marker
	if err := json.Unmarshal(data, &m); err != nil {
		return Marker{}, fmt.Errorf("servis işareti bozuk: %w", err)
	}
	return m, nil
}

// WriteMarkerFile writes what a started service reports.
func WriteMarkerFile(stateDir string, m Marker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(stateDir, MarkerFile), data)
}

// ArtifactName is the release file name of the program for goos/goarch,
// as scripts/release.sh names it.
func ArtifactName(goos, goarch string) (string, error) {
	switch {
	case goos == "windows" && goarch == "amd64":
		return "openscale-windows-amd64.exe", nil
	case goos == "linux" && (goarch == "amd64" || goarch == "arm64"):
		return "openscale-linux-" + goarch, nil
	case goos == "linux" && goarch == "arm":
		return "openscale-linux-armv7", nil
	}
	return "", fmt.Errorf("%s/%s için yayımlanan bir sürüm yok", goos, goarch)
}

// CurrentArtifact is ArtifactName for this program.
func CurrentArtifact() (string, error) { return ArtifactName(runtime.GOOS, runtime.GOARCH) }

// Verify checks the signed manifest against the options and returns it.
func Verify(opts Options, manifest []byte) (*release.Verified, error) {
	if err := checkRoot(opts); err != nil {
		return nil, err
	}
	// The newest known list is always enforced; it is not the caller's
	// choice (revocations.go).
	revocations, err := effectiveRevocations(opts)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	// The manifest came from a mirror or a file: it is parsed in the
	// unprivileged helper first when the process has one (ADR-0233).
	if err := privsep.CheckReleaseDefault(context.Background(), manifest); err != nil {
		return nil, fmt.Errorf("imzalı sürüm ayrıştırılamadı: %w", err)
	}
	v, err := release.Verify(opts.Root, manifest, release.VerifyOptions{Now: now(), Revocations: revocations})
	if err != nil {
		return nil, fmt.Errorf("imzalı sürüm doğrulanamadı: %w", err)
	}
	if len(opts.Artifact) == 0 || len(opts.Artifact) > maxArtifactName {
		return nil, errors.New("program adı geçersiz")
	}
	if _, ok := v.Manifest.Lookup(opts.Artifact); !ok {
		return nil, fmt.Errorf("%s bu sürümde yok: %w", opts.Artifact, release.ErrNotInManifest)
	}
	return v, nil
}

func checkRoot(opts Options) error {
	if opts.Root.IsZero() {
		return errors.New("sürüm kök açık anahtarı yok; --root-key ile verin (ADR-0022)")
	}
	if opts.RootFingerprint != "" && release.NormalizeFingerprint(opts.RootFingerprint) != release.NormalizeFingerprint(opts.Root.Fingerprint()) {
		return fmt.Errorf("sürüm kök anahtarının parmak izi beklenenle eşleşmiyor: %s", opts.Root.Fingerprint())
	}
	return nil
}

// Apply installs src over opts.Exe.
func Apply(ctx context.Context, opts Options, src Source) (*Result, error) {
	opts.defaults()
	if j, err := ReadJournal(opts.StateDir); err != nil {
		return nil, err
	} else if j != nil {
		return nil, ErrPending
	}
	if err := checkRoot(opts); err != nil {
		return nil, err
	}
	// Remember the newest list first: it stays in force even when this
	// release is refused.
	if err := adoptRevocations(&opts, src); err != nil {
		return nil, err
	}
	v, err := Verify(opts, src.Manifest)
	if err != nil {
		return nil, err
	}
	m := &v.Manifest
	art, _ := m.Lookup(opts.Artifact)
	if err := CheckChannel(m.Version, prereleaseAllowed(opts)); err != nil {
		return nil, err
	}

	installed := opts.Installed
	if installed == "" {
		if installed, err = opts.ProgramVersion(ctx, opts.Exe); err != nil {
			return nil, fmt.Errorf("kurulu sürüm okunamadı (%s): %w; bilerek devam etmek için --installed-version verin", opts.Exe, err)
		}
	}
	if err := release.CheckUpgrade(installed, m.Version, opts.AllowDowngrade); err != nil {
		return nil, fmt.Errorf("geri alma koruması: kurulu %s, aday %s: %w (bilerek eski sürüm için --allow-downgrade)", installed, m.Version, err)
	}
	if c, err := release.CompareVersions(installed, m.Version); err == nil && c == 0 && !opts.Reinstall {
		return nil, fmt.Errorf("%w (%s); yeniden kurmak için --reinstall", ErrAlreadyLatest, m.Version)
	}
	dir := filepath.Dir(opts.Exe)
	if free, err := diskguard.Free(dir); err == nil && free < uint64(art.Size)*2+spaceMargin {
		return nil, fmt.Errorf("%w: %s klasöründe %d MB boş, en az %d MB gerekir", ErrNoSpace, dir, free>>20, (uint64(art.Size)*2+spaceMargin)>>20)
	}

	opts.Logf("Sürüm doğrulandı: %s %s (imza %s); kurulu sürüm %s.", m.Product, m.Version, m.Created.Format(time.RFC3339), installed)
	staged, err := stage(ctx, opts, m, src)
	if err != nil {
		return nil, err
	}
	keepStaged := false
	defer func() {
		if !keepStaged {
			_ = removeBusy(staged)
		}
	}()
	got, err := opts.ProgramVersion(ctx, staged)
	if err != nil {
		return nil, fmt.Errorf("yeni program çalıştırılamadı: %w", err)
	}
	if c, err := release.CompareVersions(got, m.Version); err != nil || c != 0 {
		return nil, fmt.Errorf("%w: program %q, manifesto %q", ErrVersionDiffer, got, m.Version)
	}
	opts.Logf("Yeni program denendi: sürüm %s.", got)

	j := &Journal{State: StateStaged, Exe: opts.Exe, Staged: staged, From: installed, To: m.Version, Started: opts.Now().UTC(), PlainKeys: plainKeys(opts.KeyFiles())}
	running, err := runningServices(ctx, opts.Services)
	if err != nil {
		return nil, err
	}
	for _, s := range running {
		j.Running = append(j.Running, s.Name())
	}
	if err := writeJournal(opts.StateDir, j); err != nil {
		return nil, fmt.Errorf("güncelleme günlüğü yazılamadı: %w", err)
	}
	keepStaged = true

	// The stopping service learns that this is an update (restarthint.go).
	defer writeRestartHint(opts.StateDir, m.Version, opts.Now())()
	stopAt := opts.Now()
	if err := stopAll(ctx, opts, running); err != nil {
		startAll(ctx, opts, running)
		_ = removeBusy(staged)
		_ = removeJournal(opts.StateDir)
		return nil, fmt.Errorf("servis durdurulamadı, hiçbir şey değişmedi: %w", err)
	}
	if err := swap(opts.Exe, staged); err != nil {
		startAll(ctx, opts, running)
		_ = removeBusy(staged)
		_ = removeJournal(opts.StateDir)
		return nil, fmt.Errorf("program değiştirilemedi, eski sürüm yerinde: %w", err)
	}
	j.State, j.Staged = StateSwapped, ""
	if err := writeJournal(opts.StateDir, j); err != nil {
		opts.Logf("UYARI: güncelleme günlüğü yazılamadı: %v", err)
	}
	opts.Logf("Program değiştirildi; önceki sürüm %s olarak saklandı.", opts.Exe+PrevSuffix)

	res := &Result{From: installed, To: m.Version, Restarted: len(running) > 0}
	if err := startAndCheck(ctx, opts, running, m.Version, stopAt, opts.HealthTimeout); err != nil {
		opts.Logf("Yeni sürüm sağlıklı başlamadı (%v); önceki sürüme dönülüyor.", err)
		rerr := rollback(ctx, opts, j, running)
		res.RolledBack = rerr == nil
		res.Warnings = append(res.Warnings, keyWarnings(j.PlainKeys)...)
		if rerr != nil {
			return res, fmt.Errorf("%w: %v; geri dönüş de başarısız: %v", ErrUnhealthy, err, rerr)
		}
		return res, fmt.Errorf("%w: %v; önceki sürüm (%s) geri yüklendi", ErrUnhealthy, err, installed)
	}
	res.Downtime = opts.Now().Sub(stopAt)
	if err := saveInstalled(opts.StateDir, src.Manifest, opts.Artifact); err != nil {
		res.Warnings = append(res.Warnings, "kurulu sürümün manifestosu saklanamadı (açılış bütünlük denetimi atlanır): "+err.Error())
	}
	if err := removeJournal(opts.StateDir); err != nil {
		res.Warnings = append(res.Warnings, "güncelleme günlüğü silinemedi: "+err.Error())
	}
	if !res.Restarted {
		res.Warnings = append(res.Warnings, "servis çalışmıyordu; yeni sürüm servis başlatılınca kullanılacak")
	}
	return res, nil
}

// stage copies the program next to the installed one and checks it.
func stage(ctx context.Context, opts Options, m *release.Manifest, src Source) (string, error) {
	art, _ := m.Lookup(opts.Artifact)
	dir := filepath.Dir(opts.Exe)
	suffix := ".new"
	if runtime.GOOS == "windows" {
		suffix = ".new.exe" // CreateProcess wants an .exe
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	path := filepath.Join(dir, ".openscale-update-"+hex.EncodeToString(rnd[:])+suffix)
	r, err := src.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("yeni program alınamadı (%s): %w", src.Where, err)
	}
	defer r.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return "", fmt.Errorf("geçici dosya oluşturulamadı: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	// One byte past the expected size is enough to notice a longer file.
	n, err := io.Copy(f, io.LimitReader(r, art.Size+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if diskguard.IsDiskFull(err) {
			return "", ErrNoSpace
		}
		return "", fmt.Errorf("yeni program yazılamadı: %w", err)
	}
	if n != art.Size {
		return "", fmt.Errorf("%s: %w (boyut %d, beklenen %d)", opts.Artifact, release.ErrDigestMismatch, n, art.Size)
	}
	// Check what is on disk: that file is what runs.
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	err = m.CheckFile(opts.Artifact, in)
	_ = in.Close()
	if err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

// swap renames exe to exe.prev and staged to exe. Only one previous
// program is kept; one that is still in use is moved aside.
func swap(exe, staged string) error {
	prev := exe + PrevSuffix
	if err := os.Remove(prev); err != nil && !errors.Is(err, fs.ErrNotExist) {
		if rerr := os.Rename(prev, exe+".old-"+randomSuffix()); rerr != nil {
			return fmt.Errorf("önceki yedek kaldırılamadı: %w", err)
		}
	}
	if err := renameBusy(exe, prev); err != nil {
		return err
	}
	if err := renameBusy(staged, exe); err != nil {
		if rerr := renameBusy(prev, exe); rerr != nil {
			return fmt.Errorf("%w; eski program da geri konamadı: %v (elle: %s -> %s)", err, rerr, prev, exe)
		}
		return err
	}
	return nil
}

func randomSuffix() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func runningServices(ctx context.Context, all []Service) ([]Service, error) {
	var out []Service
	for _, s := range all {
		st, err := s.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s durumu okunamadı: %w", s.Name(), err)
		}
		if st.Installed && st.Running {
			out = append(out, s)
		}
	}
	return out, nil
}

func stopAll(ctx context.Context, opts Options, services []Service) error {
	for _, s := range services {
		opts.Logf("Durduruluyor: %s", s.Name())
		if err := s.Stop(ctx); err != nil {
			return fmt.Errorf("%s: %w", s.Name(), err)
		}
	}
	return nil
}

func startAll(ctx context.Context, opts Options, services []Service) {
	for _, s := range services {
		if err := s.Start(ctx); err != nil {
			opts.Logf("UYARI: %s başlatılamadı: %v", s.Name(), err)
		}
	}
}

// startAndCheck starts every service and waits until each is healthy.
func startAndCheck(ctx context.Context, opts Options, services []Service, want string, since time.Time, timeout time.Duration) error {
	for _, s := range services {
		opts.Logf("Başlatılıyor: %s", s.Name())
		if err := s.Start(ctx); err != nil {
			return fmt.Errorf("%s başlatılamadı: %w", s.Name(), err)
		}
	}
	for _, s := range services {
		if err := waitHealthy(ctx, opts, s, want, since, timeout); err != nil {
			return err
		}
	}
	return nil
}

// waitHealthy waits until s has run with the same process for StableFor
// and, when a marker is read, the marker names want and is newer than
// since.
func waitHealthy(ctx context.Context, opts Options, s Service, want string, since time.Time, timeout time.Duration) error {
	deadline := opts.Now().Add(timeout)
	var pid int
	var upSince time.Time
	restarts := 0
	for {
		st, err := s.Status(ctx)
		now := opts.Now()
		switch {
		case err != nil:
			pid, upSince = 0, time.Time{}
		case !st.Running:
			if pid != 0 {
				restarts++
			}
			pid, upSince = 0, time.Time{}
		case pid == 0 || st.PID != pid:
			if pid != 0 {
				restarts++
			}
			pid, upSince = st.PID, now
			if pid == 0 {
				pid = -1 // running, but the platform gives no PID
			}
		}
		if restarts >= 2 {
			return fmt.Errorf("%s yeniden başlayıp duruyor (çöküyor olabilir)", s.Name())
		}
		if !upSince.IsZero() && now.Sub(upSince) >= opts.StableFor && markerOK(opts, want, since) {
			return nil
		}
		if !now.Before(deadline) {
			if err != nil {
				return fmt.Errorf("%s durumu okunamadı: %w", s.Name(), err)
			}
			if upSince.IsZero() {
				return fmt.Errorf("%s çalışmıyor", s.Name())
			}
			return fmt.Errorf("%s başladı ama yeni sürüm hazır olduğunu bildirmedi", s.Name())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(opts.PollEvery):
		}
	}
}

func markerOK(opts Options, want string, since time.Time) bool {
	if opts.ReadMarker == nil || want == "" {
		return true
	}
	m, err := opts.ReadMarker()
	if err != nil || m.Started.Before(since.Add(-time.Second)) {
		return false
	}
	c, err := release.CompareVersions(m.Version, want)
	return err == nil && c == 0
}

// rollback restores exe.prev after a failed update.
func rollback(ctx context.Context, opts Options, j *Journal, services []Service) error {
	_ = stopAll(ctx, opts, services)
	exe, prev := opts.Exe, opts.Exe+PrevSuffix
	if _, err := os.Stat(prev); err != nil {
		j.State = StateRollbackFailed
		_ = writeJournal(opts.StateDir, j)
		return fmt.Errorf("%w: %s", ErrNoPrevious, prev)
	}
	failed := exe + FailedSuffix
	_ = os.Remove(failed)
	if err := renameBusy(exe, failed); err != nil && !errors.Is(err, fs.ErrNotExist) {
		j.State = StateRollbackFailed
		_ = writeJournal(opts.StateDir, j)
		return fmt.Errorf("yeni program kenara alınamadı: %w", err)
	}
	if err := renameBusy(prev, exe); err != nil {
		_ = renameBusy(failed, exe)
		j.State = StateRollbackFailed
		_ = writeJournal(opts.StateDir, j)
		return fmt.Errorf("önceki program geri konamadı: %w", err)
	}
	opts.Logf("Önceki program geri kondu; denenen sürüm %s olarak saklandı.", failed)
	if len(services) == 0 {
		return removeJournal(opts.StateDir)
	}
	if err := startAndCheck(ctx, opts, services, "", time.Time{}, minDuration(opts.HealthTimeout, rollbackHealth)); err != nil {
		j.State = StateRollbackFailed
		_ = writeJournal(opts.StateDir, j)
		return fmt.Errorf("önceki sürümle de servis başlamadı: %w", err)
	}
	return removeJournal(opts.StateDir)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Rollback puts exe.prev back on owner request (also after an interrupted
// update). Services that run are stopped first and started again.
func Rollback(ctx context.Context, opts Options) (*Result, error) {
	opts.defaults()
	j, err := ReadJournal(opts.StateDir)
	if err != nil {
		return nil, err
	}
	if j != nil && j.State == StateStaged {
		// Interrupted before the swap: nothing to undo but the staged file.
		if j.Staged != "" && filepath.Dir(j.Staged) == filepath.Dir(opts.Exe) && strings.HasPrefix(filepath.Base(j.Staged), ".openscale-update-") {
			_ = os.Remove(j.Staged)
		}
		if err := removeJournal(opts.StateDir); err != nil {
			return nil, err
		}
		running, _ := runningServices(ctx, opts.Services)
		if len(running) == 0 && len(j.Running) > 0 {
			opts.Logf("Servis durmuş; yeniden başlatılıyor.")
			startAll(ctx, opts, opts.Services)
		}
		return &Result{From: j.From, To: j.From}, nil
	}
	prev := opts.Exe + PrevSuffix
	if _, err := os.Stat(prev); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoPrevious, prev)
	}
	prevVersion, err := opts.ProgramVersion(ctx, prev)
	if err != nil {
		return nil, fmt.Errorf("önceki program çalıştırılamadı: %w", err)
	}
	current, _ := opts.ProgramVersion(ctx, opts.Exe)
	running, err := runningServices(ctx, opts.Services)
	if err != nil {
		return nil, err
	}
	if j == nil {
		j = &Journal{State: StateSwapped, Exe: opts.Exe, From: current, To: prevVersion, Started: opts.Now().UTC()}
		for _, s := range running {
			j.Running = append(j.Running, s.Name())
		}
		if err := writeJournal(opts.StateDir, j); err != nil {
			return nil, err
		}
	} else if len(running) == 0 {
		// A failed rollback left the services stopped: start those that
		// ran before the update.
		for _, s := range opts.Services {
			for _, name := range j.Running {
				if s.Name() == name {
					running = append(running, s)
				}
			}
		}
	}
	res := &Result{From: current, To: prevVersion, Restarted: len(running) > 0, RolledBack: true}
	if err := rollback(ctx, opts, j, running); err != nil {
		return res, err
	}
	_ = os.Remove(filepath.Join(opts.StateDir, InstalledManifestFile))
	_ = os.Remove(filepath.Join(opts.StateDir, InstalledArtifactFile))
	return res, nil
}

func saveInstalled(stateDir string, manifest []byte, artifact string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := securefile.Replace(filepath.Join(stateDir, InstalledManifestFile), manifest); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(stateDir, InstalledArtifactFile), []byte(artifact))
}

// CheckInstalled verifies exe against the manifest saved by the last
// update (#172). It returns ok=false with no error when no manifest was
// saved (installed by hand or by a package).
func CheckInstalled(stateDir, exe string, root release.PublicKey, now time.Time) (version string, ok bool, err error) {
	manifest, err := securefile.ReadPrivate(filepath.Join(stateDir, InstalledManifestFile), release.MaxSignedReleaseSize)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	name, err := securefile.ReadPrivate(filepath.Join(stateDir, InstalledArtifactFile), maxArtifactName)
	if err != nil {
		return "", false, err
	}
	// StateDir brings in the stored revocation list: a key revoked after this
	// release was installed fails here too (ADR-0195).
	v, err := Verify(Options{Root: root, Artifact: strings.TrimSpace(string(name)), StateDir: stateDir, Now: func() time.Time { return now }}, manifest)
	if err != nil {
		return "", false, err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	if err := v.Manifest.CheckFile(strings.TrimSpace(string(name)), f); err != nil {
		return v.Manifest.Version, false, err
	}
	return v.Manifest.Version, true, nil
}
