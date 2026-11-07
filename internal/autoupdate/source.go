package autoupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/updater"
)

// Upstream source (ADR-0225). The owner may let the coordinator follow the
// project's GitHub releases: "openscale update source set
// https://github.com/<owner>/<repo>". Only the coordinator host connects
// to GitHub (the sync runs there, outside the sandboxed coordinator
// process); devices keep talking only to their coordinator, inside the
// tunnel, so neither their addresses nor their versions reach a third
// party. The sync verifies the signed manifest exactly as devices do
// before anything is published; an unsigned or unverifiable GitHub release
// is never mirrored. No address is built in (ADR-0008): the source is off
// until the owner sets it.

// SourceFile is the owner's source setting in the coordinator's state
// directory.
const SourceFile = "release-source.json"

// Source limits and defaults.
const (
	DefaultSourceEvery = 6 * time.Hour
	MinSourceEvery     = time.Hour
	MaxSourceEvery     = 7 * 24 * time.Hour
	sourceSchema       = 1
	maxListing         = 4 << 20
	listingTimeout     = time.Minute
	assetTimeout       = 30 * time.Minute
	maxReleasesListed  = 30
	// sourceHost is the only host a source may name; the API host is
	// derived from it. It is compared, never dialled unless configured.
	sourceHost = "github.com"
)

var repoPartRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?$`)

// SourceConfig is the content of SourceFile.
type SourceConfig struct {
	Schema int    `json:"schema"`
	Owner  string `json:"owner"`
	Repo   string `json:"repo"`
	// Every is the check interval; Beta includes pre-releases (devices
	// still apply their own channel).
	Every Duration `json:"every"`
	Beta  bool     `json:"beta"`
}

// Duration is a time.Duration written as text ("6h0m0s").
type Duration time.Duration

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Name is the source as devices see it: "github.com/owner/repo".
func (c SourceConfig) Name() string { return sourceHost + "/" + c.Owner + "/" + c.Repo }

// SourceFormat is the accepted form of a source, for messages. It is built
// at run time so no address literal is compiled in (ADR-0008).
func SourceFormat() string {
	return (&url.URL{Scheme: "https", Host: sourceHost, Path: "/<sahip>/<depo>"}).String()
}

// ParseSourceURL accepts exactly https://github.com/<owner>/<repo>.
func ParseSourceURL(s string) (owner, repo string, err error) {
	bad := fmt.Errorf("kaynak %s biçiminde olmalı", SourceFormat())
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, sourceHost) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", bad
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), "/"), "/")
	if len(parts) != 2 || !repoPartRe.MatchString(parts[0]) || !repoPartRe.MatchString(parts[1]) || strings.HasSuffix(parts[1], ".git") {
		return "", "", bad
	}
	return parts[0], parts[1], nil
}

// ReadSource returns the setting, or nil when no source is set.
func ReadSource(stateDir string) (*SourceConfig, error) {
	data, err := securefile.ReadPrivate(filepath.Join(stateDir, SourceFile), maxSmallFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c SourceConfig
	if err := decodeStrict(data, &c); err != nil || c.Schema != sourceSchema || !repoPartRe.MatchString(c.Owner) || !repoPartRe.MatchString(c.Repo) ||
		time.Duration(c.Every) < MinSourceEvery || time.Duration(c.Every) > MaxSourceEvery {
		return nil, fmt.Errorf("%s bozuk", SourceFile)
	}
	return &c, nil
}

// WriteSource saves the setting; nil removes it (source off).
func WriteSource(stateDir string, c *SourceConfig) error {
	path := filepath.Join(stateDir, SourceFile)
	if c == nil {
		err := os.Remove(path)
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		_ = os.Remove(filepath.Join(stateDir, coordinator.ReleaseSourceStatusFile))
		return err
	}
	c.Schema = sourceSchema
	if time.Duration(c.Every) < MinSourceEvery || time.Duration(c.Every) > MaxSourceEvery {
		return fmt.Errorf("kontrol aralığı %s ile %s arasında olmalı", MinSourceEvery, MaxSourceEvery)
	}
	if err := writeJSON(path, c); err != nil {
		return err
	}
	return matchOwner(path, stateDir)
}

// ReadSourceStatus returns the last sync report.
func ReadSourceStatus(stateDir string) (coordinator.SourceStatus, error) {
	var st coordinator.SourceStatus
	data, err := securefile.ReadLimited(filepath.Join(stateDir, coordinator.ReleaseSourceStatusFile), maxSmallFile)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

// SyncOptions configure SyncSource.
type SyncOptions struct {
	StateDir string
	Root     release.PublicKey
	// Force checks now even when the interval has not passed.
	Force bool
	// Client defaults to updater.HTTPClient (HTTPS only, bounded).
	Client *http.Client
	// APIBase and DownloadBase override the derived addresses (tests).
	APIBase, DownloadBase string
	Now                   func() time.Time
	Logf                  func(format string, args ...any)
}

// SyncResult describes one sync.
type SyncResult struct {
	Skipped   bool
	Version   string
	Published bool
}

type ghAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	Tag        string    `json:"tag_name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
}

// SyncSource checks the source and publishes a newer verified release into
// the mirror. Its outcome is written to ReleaseSourceStatusFile.
func SyncSource(ctx context.Context, o SyncOptions) (SyncResult, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	cfg, err := ReadSource(o.StateDir)
	if err != nil {
		return SyncResult{}, err
	}
	if cfg == nil {
		return SyncResult{Skipped: true}, errors.New("yukarı akış kaynağı ayarlı değil (openscale update source set " + SourceFormat() + ")")
	}
	prev, _ := ReadSourceStatus(o.StateDir)
	if !o.Force && prev.Source == cfg.Name() && o.Now().Sub(prev.LastCheck) < time.Duration(cfg.Every) {
		return SyncResult{Skipped: true, Version: prev.Version}, nil
	}
	res, err := syncSource(ctx, o, cfg)
	st := coordinator.SourceStatus{Schema: 1, Source: cfg.Name(), LastCheck: o.Now().UTC(), Version: res.Version}
	if err != nil {
		st.Error = err.Error()
		if len(st.Error) > 300 {
			st.Error = st.Error[:300]
		}
		if st.Version == "" {
			st.Version = prev.Version
		}
	}
	path := filepath.Join(o.StateDir, coordinator.ReleaseSourceStatusFile)
	if werr := writeJSON(path, st); werr == nil {
		_ = matchOwner(path, o.StateDir)
	}
	return res, err
}

func syncSource(ctx context.Context, o SyncOptions, cfg *SourceConfig) (SyncResult, error) {
	if o.Root.IsZero() {
		return SyncResult{}, errors.New("sürüm kök açık anahtarı yok; doğrulanamayan sürüm dağıtılmaz")
	}
	client := o.Client
	if client == nil {
		client = updater.HTTPClient()
	}
	api := o.APIBase
	if api == "" {
		api = (&url.URL{Scheme: "https", Host: "api." + sourceHost}).String()
	}
	dl := o.DownloadBase
	if dl == "" {
		dl = (&url.URL{Scheme: "https", Host: sourceHost}).String()
	}
	lctx, cancel := context.WithTimeout(ctx, listingTimeout)
	defer cancel()
	listURL := api + "/repos/" + url.PathEscape(cfg.Owner) + "/" + url.PathEscape(cfg.Repo) + "/releases?per_page=" + fmt.Sprint(maxReleasesListed)
	body, err := httpGet(lctx, client, listURL, maxListing, "application/vnd.github+json")
	if err != nil {
		return SyncResult{}, fmt.Errorf("sürüm listesi alınamadı: %w", err)
	}
	var list []ghRelease
	if err := json.Unmarshal(body, &list); err != nil {
		return SyncResult{}, errors.New("sürüm listesi okunamadı")
	}
	best, bestVer := pickRelease(list, cfg.Beta)
	if best == nil {
		return SyncResult{}, errors.New("kaynakta imzalı manifestosu (openscale-<sürüm>.release.json) olan bir sürüm yok; imzasız sürüm dağıtılmaz")
	}
	res := SyncResult{Version: bestVer}
	mirror := filepath.Join(o.StateDir, coordinator.ReleaseMirrorDir)
	manifestName := "openscale-" + bestVer + ".release.json"
	base := dl + "/" + url.PathEscape(cfg.Owner) + "/" + url.PathEscape(cfg.Repo) + "/releases/download/" + url.PathEscape(best.Tag) + "/"
	manifest, err := httpGet(ctx, client, base+url.PathEscape(manifestName), release.MaxSignedReleaseSize, "")
	if err != nil {
		return res, fmt.Errorf("manifesto indirilemedi: %w", err)
	}
	if current, err := os.ReadFile(filepath.Join(mirror, manifestName)); err == nil && string(current) == string(manifest) {
		o.Logf("Aynadaki sürüm (%s) kaynaktaki en yeni sürümle aynı.", bestVer)
		return res, nil
	}
	var revs []byte
	if hasAsset(best, updater.RevocationsFile) {
		if revs, err = httpGet(ctx, client, base+updater.RevocationsFile, release.MaxRevocationsSize, ""); err != nil {
			return res, fmt.Errorf("iptal listesi indirilemedi: %w", err)
		}
	}
	// Verify before the large downloads: fail closed and early.
	list2, err := updater.EnforcedRevocations("", o.Root, nil, revs, o.Logf)
	if err != nil {
		return res, err
	}
	v, err := release.Verify(o.Root, manifest, release.VerifyOptions{Now: o.Now(), Revocations: list2})
	if err != nil {
		return res, fmt.Errorf("kaynaktaki sürüm doğrulanamadı, dağıtılmadı: %w", err)
	}
	if v.Manifest.Version != bestVer {
		return res, fmt.Errorf("etiket %s, imzalı sürüm %s", best.Tag, v.Manifest.Version)
	}
	tmp, err := os.MkdirTemp(o.StateDir, ".source-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, manifestName), manifest, 0o600); err != nil {
		return res, err
	}
	if revs != nil {
		if err := os.WriteFile(filepath.Join(tmp, updater.RevocationsFile), revs, 0o600); err != nil {
			return res, err
		}
	}
	for _, a := range v.Manifest.Artifacts {
		if !slices.Contains(mirroredPrograms, a.Name) && !strings.HasSuffix(a.Name, ".deb") {
			continue
		}
		ga, ok := asset(best, a.Name)
		if !ok {
			continue // devices that need it report it missing
		}
		if ga.Size != a.Size {
			return res, fmt.Errorf("%s boyutu kaynakta %d, manifestoda %d", a.Name, ga.Size, a.Size)
		}
		o.Logf("İndiriliyor: %s (%d MB)", a.Name, a.Size>>20)
		actx, cancel := context.WithTimeout(ctx, assetTimeout)
		err := httpSave(actx, client, base+url.PathEscape(a.Name), a.Size, filepath.Join(tmp, a.Name))
		cancel()
		if err != nil {
			return res, fmt.Errorf("%s indirilemedi: %w", a.Name, err)
		}
	}
	// Publish verifies the manifest again and every file against it.
	if _, err := Publish(PublishOptions{Dist: tmp, StateDir: o.StateDir, Root: o.Root, Now: o.Now, Logf: o.Logf}); err != nil {
		return res, err
	}
	res.Published = true
	return res, nil
}

// pickRelease chooses the highest version with a signed manifest asset.
func pickRelease(list []ghRelease, beta bool) (*ghRelease, string) {
	var best *ghRelease
	bestVer := ""
	for i := range list {
		r := &list[i]
		ver := strings.TrimPrefix(r.Tag, "v")
		if r.Draft || len(ver) > 48 || !hasAsset(r, "openscale-"+ver+".release.json") {
			continue
		}
		if _, err := release.ParseVersion(ver); err != nil {
			continue
		}
		if !beta && (r.Prerelease || updater.IsPrerelease(ver)) {
			continue
		}
		if best == nil {
			best, bestVer = r, ver
			continue
		}
		if c, err := release.CompareVersions(ver, bestVer); err == nil && c > 0 {
			best, bestVer = r, ver
		}
	}
	return best, bestVer
}

func asset(r *ghRelease, name string) (ghAsset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return ghAsset{}, false
}

func hasAsset(r *ghRelease, name string) bool { _, ok := asset(r, name); return ok }

func httpGet(ctx context.Context, client *http.Client, u string, limit int64, accept string) ([]byte, error) {
	resp, err := httpOpen(ctx, client, u, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("yanıt çok büyük")
	}
	return data, nil
}

func httpOpen(ctx context.Context, client *http.Client, u, accept string) (*http.Response, error) {
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" {
		// SECURITY FIX: CWE-319 the source is fetched over HTTPS only.
		return nil, errors.New("yalnızca https adresleri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("sunucu %s döndürdü", resp.Status)
	}
	return resp, nil
}

// httpSave writes exactly size bytes to path.
func httpSave(ctx context.Context, client *http.Client, u string, size int64, path string) error {
	resp, err := httpOpen(ctx, client, u, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	tmp := path + ".part-" + hex.EncodeToString(rnd[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != size {
		err = fmt.Errorf("boyut %d, beklenen %d", n, size)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
