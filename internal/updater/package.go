package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/release"
)

// Package installs (ADR-0225). A Linux program that came with the .deb is
// updated by the package manager, never by replacing /usr/bin/openscale
// behind its back (ADR-0091). ApplyPackage runs the same verification as
// Apply — signed manifest, root key, revocation list, beta channel,
// rollback protection, size and SHA-256 of the staged copy — and then hands
// the verified package file to PackageOptions.Install (dpkg on Linux). The
// verified package is kept so a later failed update can go back to it.

// InstalledPackageFile is the last package ApplyPackage installed, kept in
// the update folder for the next rollback.
const InstalledPackageFile = "installed.deb"

// PackageOptions configure ApplyPackage. Options.Artifact is the package's
// name in the manifest; Options.Exe is the program the package installs.
type PackageOptions struct {
	Options
	// Install installs a verified package file; it must not return before the
	// package manager finished (it restarts running units itself).
	Install func(ctx context.Context, path string) error
}

// ApplyPackage verifies src and installs its package.
func ApplyPackage(ctx context.Context, po PackageOptions, src Source) (*Result, error) {
	opts := po.Options
	opts.defaults()
	if po.Install == nil {
		return nil, errors.New("paket kurucusu yok")
	}
	if j, err := ReadJournal(opts.StateDir); err != nil {
		return nil, err
	} else if j != nil {
		return nil, ErrPending
	}
	if err := checkRoot(opts); err != nil {
		return nil, err
	}
	if err := adoptRevocations(&opts, src); err != nil {
		return nil, err
	}
	v, err := Verify(opts, src.Manifest)
	if err != nil {
		return nil, err
	}
	m := &v.Manifest
	if err := CheckChannel(m.Version, prereleaseAllowed(opts)); err != nil {
		return nil, err
	}
	installed := opts.Installed
	if installed == "" {
		if installed, err = opts.ProgramVersion(ctx, opts.Exe); err != nil {
			return nil, fmt.Errorf("kurulu sürüm okunamadı (%s): %w", opts.Exe, err)
		}
	}
	if err := release.CheckUpgrade(installed, m.Version, opts.AllowDowngrade); err != nil {
		return nil, fmt.Errorf("geri alma koruması: kurulu %s, aday %s: %w", installed, m.Version, err)
	}
	if c, err := release.CompareVersions(installed, m.Version); err == nil && c == 0 && !opts.Reinstall {
		return nil, fmt.Errorf("%w (%s)", ErrAlreadyLatest, m.Version)
	}
	art, _ := m.Lookup(opts.Artifact)
	if free, err := diskguard.Free(opts.StateDir); err == nil && free < uint64(art.Size)*2+spaceMargin {
		return nil, fmt.Errorf("%w: %s", ErrNoSpace, opts.StateDir)
	}
	opts.Logf("Paket doğrulandı: %s %s; kurulu sürüm %s.", opts.Artifact, m.Version, installed)
	staged, err := stagePackage(ctx, opts, m, src)
	if err != nil {
		return nil, err
	}
	defer os.Remove(staged)
	running, err := runningServices(ctx, opts.Services)
	if err != nil {
		return nil, err
	}
	defer writeRestartHint(opts.StateDir, m.Version, opts.Now())() // restarthint.go
	start := opts.Now()
	res := &Result{From: installed, To: m.Version, Restarted: len(running) > 0}
	installErr := po.Install(ctx, staged)
	if installErr == nil {
		installErr = checkPackageResult(ctx, opts, running, m.Version, start)
	}
	if installErr == nil {
		res.Downtime = opts.Now().Sub(start)
		if err := os.Rename(staged, filepath.Join(opts.StateDir, InstalledPackageFile)); err != nil {
			res.Warnings = append(res.Warnings, "kurulan paket geri dönüş için saklanamadı: "+err.Error())
		}
		return res, nil
	}
	opts.Logf("Yeni paket sağlıklı çalışmadı (%v); önceki pakete dönülüyor.", installErr)
	prev := filepath.Join(opts.StateDir, InstalledPackageFile)
	if _, err := os.Stat(prev); err != nil {
		return res, fmt.Errorf("%w: %v; önceki paket saklı değil, elle kurun (apt install --reinstall openscale=<sürüm>)", ErrUnhealthy, installErr)
	}
	if err := po.Install(ctx, prev); err != nil {
		return res, fmt.Errorf("%w: %v; önceki paket de kurulamadı: %v", ErrUnhealthy, installErr, err)
	}
	startAll(ctx, opts, running)
	res.RolledBack = true
	return res, fmt.Errorf("%w: %v; önceki paket geri kuruldu", ErrUnhealthy, installErr)
}

// checkPackageResult requires the installed program to report the new
// version and every service that ran before to run stably again.
func checkPackageResult(ctx context.Context, opts Options, running []Service, want string, since time.Time) error {
	got, err := opts.ProgramVersion(ctx, opts.Exe)
	if err != nil {
		return fmt.Errorf("kurulan program çalıştırılamadı: %w", err)
	}
	if c, err := release.CompareVersions(got, want); err != nil || c != 0 {
		return fmt.Errorf("%w: program %q, manifesto %q", ErrVersionDiffer, got, want)
	}
	for _, s := range running {
		if st, err := s.Status(ctx); err == nil && !st.Running {
			// The package manager restarts only what ran; start it if not.
			_ = s.Start(ctx)
		}
		if err := waitHealthy(ctx, opts, s, "", since, opts.HealthTimeout); err != nil {
			return err
		}
	}
	return nil
}

// stagePackage copies the package into the update folder and checks it.
func stagePackage(ctx context.Context, opts Options, m *release.Manifest, src Source) (string, error) {
	art, _ := m.Lookup(opts.Artifact)
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(opts.StateDir, ".openscale-update-"+randomSuffix()+".deb")
	r, err := src.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("paket alınamadı (%s): %w", src.Where, err)
	}
	defer r.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(r, art.Size+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("paket yazılamadı: %w", err)
	}
	if n != art.Size {
		return "", fmt.Errorf("%s: %w (boyut %d, beklenen %d)", opts.Artifact, release.ErrDigestMismatch, n, art.Size)
	}
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
