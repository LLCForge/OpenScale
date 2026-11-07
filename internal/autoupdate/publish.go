package autoupdate

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/updater"
)

// PublishOptions configure Publish.
type PublishOptions struct {
	// Dist is the release folder scripts/release.sh wrote (dist/<V>).
	Dist string
	// StateDir is the coordinator's state directory; the mirror goes into
	// its ReleaseMirrorDir.
	StateDir string
	Root     release.PublicKey
	Now      func() time.Time
	Logf     func(format string, args ...any)
}

// PublishResult describes a publication.
type PublishResult struct {
	Version string
	Mirror  string
	Files   []string
}

// ErrUnsigned: the folder holds no signed manifest (scripts/release.sh
// --unsigned, or no signing key yet).
var ErrUnsigned = errors.New("klasörde imzalı sürüm dosyası (openscale-*.release.json) yok; imzasız sürüm otomatik güncellemeyle dağıtılmaz (docs/otomatik-guncelleme.md)")

// mirroredPrograms are the programs a mirror serves compressed.
var mirroredPrograms = []string{"openscale-windows-amd64.exe", "openscale-linux-amd64", "openscale-linux-arm64", "openscale-linux-armv7"}

// Publish verifies the signed release in o.Dist exactly as a device will
// and puts the manifest, the revocation list, the compressed programs and
// the Debian packages into the coordinator's mirror. The manifest goes
// first out and last in, so the coordinator never announces a half
// written publication.
func Publish(o PublishOptions) (*PublishResult, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Root.IsZero() {
		return nil, errors.New("sürüm kök açık anahtarı yok; yayımlamadan önce imzayı doğrulamak için gerekli (--root-key)")
	}
	if o.StateDir == "" {
		return nil, errors.New("koordinatör durum klasörü yok (--state-dir)")
	}
	matches, _ := filepath.Glob(filepath.Join(o.Dist, "openscale-*.release.json"))
	switch len(matches) {
	case 0:
		return nil, ErrUnsigned
	case 1:
	default:
		return nil, fmt.Errorf("%s içinde birden fazla imzalı sürüm dosyası var", o.Dist)
	}
	manifest, err := securefile.ReadLimited(matches[0], release.MaxSignedReleaseSize)
	if err != nil {
		return nil, err
	}
	revs, err := securefile.ReadLimited(filepath.Join(o.Dist, updater.RevocationsFile), release.MaxRevocationsSize)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		revs = nil
	}
	list, err := updater.EnforcedRevocations("", o.Root, nil, revs, o.Logf)
	if err != nil {
		return nil, err
	}
	v, err := release.Verify(o.Root, manifest, release.VerifyOptions{Now: o.Now(), Revocations: list})
	if err != nil {
		return nil, fmt.Errorf("imzalı sürüm doğrulanamadı: %w", err)
	}
	m := &v.Manifest
	name := "openscale-" + m.Version + ".release.json"
	if filepath.Base(matches[0]) != name {
		return nil, fmt.Errorf("manifesto dosyasının adı %s olmalı", name)
	}
	type item struct{ src, dst string }
	var items []item
	for _, a := range m.Artifacts {
		switch {
		case slices.Contains(mirroredPrograms, a.Name):
			items = append(items, item{a.Name, a.Name + ".gz"})
		case strings.HasSuffix(a.Name, ".deb"):
			items = append(items, item{a.Name, a.Name})
		}
	}
	if len(items) == 0 {
		return nil, errors.New("sürümde aynada sunulacak program veya paket yok")
	}
	for _, it := range items {
		if _, ok := coordinator.MirrorFileAllowed(it.dst); !ok {
			return nil, fmt.Errorf("%s aynada sunulamaz", it.dst)
		}
	}
	mirror := filepath.Join(o.StateDir, coordinator.ReleaseMirrorDir)
	if err := os.MkdirAll(mirror, 0o700); err != nil {
		return nil, err
	}
	if err := matchOwner(mirror, o.StateDir); err != nil {
		return nil, err
	}
	// Stop announcing the old publication.
	old, _ := filepath.Glob(filepath.Join(mirror, "openscale-*.release.json"))
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return nil, err
		}
	}
	res := &PublishResult{Version: m.Version, Mirror: mirror}
	keep := map[string]bool{name: true}
	for _, it := range items {
		in, err := os.Open(filepath.Join(o.Dist, it.src))
		if err != nil {
			return nil, fmt.Errorf("%s okunamadı: %w", it.src, err)
		}
		err = m.CheckFile(it.src, in)
		in.Close()
		if err != nil {
			return nil, err
		}
		o.Logf("Aynaya yazılıyor: %s", it.dst)
		if err := writeMirrorFile(mirror, o.StateDir, it.dst, filepath.Join(o.Dist, it.src), it.dst != it.src); err != nil {
			return nil, err
		}
		keep[it.dst] = true
		res.Files = append(res.Files, it.dst)
	}
	if revs != nil {
		if err := writeMirrorBytes(mirror, o.StateDir, updater.RevocationsFile, revs); err != nil {
			return nil, err
		}
		keep[updater.RevocationsFile] = true
		res.Files = append(res.Files, updater.RevocationsFile)
	}
	entries, err := os.ReadDir(mirror)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !keep[e.Name()] {
			_ = os.RemoveAll(filepath.Join(mirror, e.Name()))
		}
	}
	if err := writeMirrorBytes(mirror, o.StateDir, name, manifest); err != nil {
		return nil, err
	}
	res.Files = append(res.Files, name)
	return res, nil
}

func writeMirrorBytes(mirror, owner, name string, data []byte) error {
	return writeMirror(mirror, owner, name, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func writeMirrorFile(mirror, owner, name, src string, compress bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeMirror(mirror, owner, name, func(w io.Writer) error {
		if !compress {
			_, err := io.Copy(w, in)
			return err
		}
		gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
		if err != nil {
			return err
		}
		if _, err := io.Copy(gz, in); err != nil {
			return err
		}
		return gz.Close()
	})
}

// writeMirror writes a temporary file the coordinator ignores and renames
// it into place.
func writeMirror(mirror, owner, name string, fill func(io.Writer) error) error {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(mirror, ".publish-"+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	err = fill(f)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s yazılamadı: %w", name, err)
	}
	if err := matchOwner(tmp, owner); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(mirror, name)); err != nil {
		return err
	}
	ok = true
	return nil
}
