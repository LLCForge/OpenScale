package autoupdate

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/updater"
)

// ErrNoRequest: nothing is waiting for the installer.
var ErrNoRequest = errors.New("bekleyen otomatik güncelleme yok")

// InstallOptions configure Install, the privileged half (administrator or
// root): "openscale update auto install", started by the Windows service or
// by openscale-autoupdate.path on Linux.
type InstallOptions struct {
	Paths Paths
	// LoadRoot defaults to updater.LoadRootKey("").
	LoadRoot func() (release.PublicKey, error)
	// Binary returns the updater options of this installation for
	// ModeBinary; nil uses updater.DefaultPlatform.
	Binary func() (updater.Options, error)
	// Package returns them for ModeDeb; nil uses PackagePlatform (Linux).
	Package func() (updater.PackageOptions, error)
	// Apply and ApplyPackage default to the updater's.
	Apply        func(context.Context, updater.Options, updater.Source) (*updater.Result, error)
	ApplyPackage func(context.Context, updater.PackageOptions, updater.Source) (*updater.Result, error)
	GOOS, GOARCH string
	Now          func() time.Time
	Logf         func(format string, args ...any)
}

// Install takes the device's request, verifies the cached release from
// scratch and runs the update with its health check and rollback. It
// always writes a Result for the device unless no request was waiting.
func Install(ctx context.Context, o InstallOptions) (*updater.Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.GOOS == "" {
		o.GOOS, o.GOARCH = runtime.GOOS, runtime.GOARCH
	}
	if o.LoadRoot == nil {
		o.LoadRoot = func() (release.PublicKey, error) {
			k, _, err := updater.LoadRootKey("")
			return k, err
		}
	}
	if o.Apply == nil {
		o.Apply = updater.Apply
	}
	if o.ApplyPackage == nil {
		o.ApplyPackage = updater.ApplyPackage
	}
	work := o.Paths.Work
	reqPath, taken := filepath.Join(work, RequestFile), filepath.Join(work, TakenFile)
	// Claim the request first: the path unit must not start a second run.
	if err := os.Rename(reqPath, taken); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoRequest
		}
		return nil, err
	}
	req, res, err := install(ctx, o, taken)
	r := Result{Format: resultFormat, Version: req.Version, Digest: req.Digest, OK: err == nil, At: o.Now().UTC()}
	if res != nil {
		r.RolledBack = res.RolledBack
	}
	if err != nil {
		r.Message = err.Error()
	} else if res != nil {
		r.Message = fmt.Sprintf("%s -> %s", res.From, res.To)
	}
	if werr := writeJSON(filepath.Join(work, ResultFile), r); werr != nil {
		o.Logf("UYARI: kurulum sonucu yazılamadı: %v", werr)
	}
	_ = os.Remove(taken)
	return res, err
}

func install(ctx context.Context, o InstallOptions, taken string) (Request, *updater.Result, error) {
	var req Request
	data, err := securefile.ReadPrivate(taken, maxSmallFile)
	if err != nil {
		return req, nil, fmt.Errorf("kurulum isteği okunamadı: %w", err)
	}
	if err := decodeStrict(data, &req); err != nil || req.Format != requestFormat {
		return Request{}, nil, errors.New("kurulum isteği bozuk")
	}
	if !o.Paths.Supported || req.Mode != o.Paths.Mode {
		return req, nil, errors.New("kurulum isteği bu kurulumun biçimine uymuyor")
	}
	for _, n := range []string{req.Manifest, req.Payload} {
		if !control.ValidReleaseFileName(n) {
			return req, nil, errors.New("kurulum isteğinde geçersiz dosya adı")
		}
	}
	if req.Revocations != "" && req.Revocations != updater.RevocationsFile {
		return req, nil, errors.New("kurulum isteğinde geçersiz iptal listesi adı")
	}
	// What this installation needs for the requested version; the request
	// cannot name another platform's program or package.
	artifact, mirror, compressed, err := ArtifactFor(o.Paths.Mode, o.GOOS, o.GOARCH, req.Version)
	if err != nil {
		return req, nil, err
	}
	if req.Artifact != artifact || req.Payload != mirror || req.Compressed != compressed {
		return req, nil, errors.New("kurulum isteği bu cihazın programını istemiyor")
	}
	root, err := o.LoadRoot()
	if err != nil || root.IsZero() {
		return req, nil, errors.New("sürüm kök açık anahtarı yok; imzasız sürüm kurulmaz")
	}
	cache, err := os.OpenRoot(filepath.Join(o.Paths.Work, CacheDir))
	if err != nil {
		return req, nil, err
	}
	defer cache.Close()
	manifest, err := readCached(cache, req.Manifest, release.MaxSignedReleaseSize)
	if err != nil {
		return req, nil, err
	}
	if sum := sha256.Sum256(manifest); hex.EncodeToString(sum[:]) != req.Digest {
		return req, nil, errors.New("önbellekteki manifesto istekteki özetle aynı değil")
	}
	var revs []byte
	if req.Revocations != "" {
		if revs, err = readCached(cache, req.Revocations, release.MaxRevocationsSize); err != nil {
			return req, nil, err
		}
	}
	src := updater.Source{Manifest: manifest, Revocations: revs, Where: "koordinatör aynası (" + req.Payload + ")", Open: func(context.Context) (io.ReadCloser, error) {
		f, err := openCached(cache, req.Payload)
		if err != nil {
			return nil, err
		}
		if !compressed {
			return f, nil
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("sıkıştırılmış program bozuk: %w", err)
		}
		return gzReadCloser{gz, f}, nil
	}}
	if err := updater.RequirePrivileges(); err != nil && o.Binary == nil && o.Package == nil {
		return req, nil, err
	}
	switch o.Paths.Mode {
	case ModeBinary:
		get := o.Binary
		if get == nil {
			get = binaryOptions
		}
		opts, err := get()
		if err != nil {
			return req, nil, err
		}
		opts.Root, opts.Artifact, opts.Logf, opts.Now = root, artifact, o.Logf, o.Now
		if err := sameVersion(opts, src, req.Version); err != nil {
			return req, nil, err
		}
		res, err := o.Apply(ctx, opts, src)
		return req, res, err
	case ModeDeb:
		get := o.Package
		if get == nil {
			get = packageOptions
		}
		po, err := get()
		if err != nil {
			return req, nil, err
		}
		po.Root, po.Artifact, po.Logf, po.Now = root, artifact, o.Logf, o.Now
		if err := sameVersion(po.Options, src, req.Version); err != nil {
			return req, nil, err
		}
		res, err := o.ApplyPackage(ctx, po, src)
		return req, res, err
	}
	return req, nil, errors.New("bilinmeyen kurulum biçimi")
}

// sameVersion requires the signed manifest to be the version requested.
func sameVersion(opts updater.Options, src updater.Source, want string) error {
	v, err := updater.VerifySource(opts, src)
	if err != nil {
		return err
	}
	if v.Manifest.Version != want {
		return fmt.Errorf("imzalı sürüm %s, istenen %s", v.Manifest.Version, want)
	}
	return nil
}

func binaryOptions() (updater.Options, error) {
	p, err := updater.DefaultPlatform()
	if err != nil {
		return updater.Options{}, err
	}
	return updater.Options{Exe: p.Exe, StateDir: p.StateDir, Services: p.Services, ReadMarker: p.ReadMarker}, nil
}

func openCached(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s düzenli bir dosya değil", name)
	}
	return root.Open(name)
}

func readCached(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := openCached(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s çok büyük", name)
	}
	return data, nil
}

type gzReadCloser struct {
	*gzip.Reader
	f *os.File
}

func (g gzReadCloser) Close() error {
	_ = g.Reader.Close()
	return g.f.Close()
}
