// Command releaseverify verifies a downloaded OpenScale release (ADR-0022):
// the signature chain from the release root key to the manifest, and the
// size and SHA-256 of each file. It never connects to the network.
//
//	openscale-release-verify -manifest openscale-0.9.0.release.json [FILE...]
//
// With no FILE arguments every file listed in the manifest must be present
// next to the manifest (or in -dir). The release root public key is embedded
// at build time (-ldflags "-X main.embeddedRootKey=osrelkey1:...") or given
// with -root-key.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

// embeddedRootKey is set by scripts/release.sh from build/release/root.pub.
var embeddedRootKey = ""

const (
	exitOK       = 0
	exitFailed   = 1
	exitUsage    = 2
	maxKeyFile   = 4096
	maxRevokList = release.MaxRevocationsSize
	// revocationsFile is the signed list published next to a manifest.
	revocationsFile = "revocations.json"
)

type options struct {
	rootKey         string
	rootFingerprint string
	manifest        string
	dir             string
	revocations     string
	installed       string
	allowDowngrade  bool
	requireValidNow bool
	presentOnly     bool
	printSums       bool
	files           []string
	// witness, witnessKey and advisories: #581 and #582 (p13.go).
	witness    string
	witnessKey string
	advisories string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	opts, err := parse(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "releaseverify:", err)
		return exitUsage
	}
	if err := verify(opts, stdout, now); err != nil {
		fmt.Fprintln(stderr, "DOĞRULANAMADI:", err)
		return exitFailed
	}
	return exitOK
}

func parse(args []string, stderr io.Writer) (*options, error) {
	o := &options{}
	fl := flag.NewFlagSet("releaseverify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.StringVar(&o.rootKey, "root-key", "", "sürüm kök açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...); varsayılan: gömülü anahtar")
	fl.StringVar(&o.rootFingerprint, "root-fingerprint", "", "kök anahtarın beklenen parmak izi (ayrı kanaldan)")
	fl.StringVar(&o.manifest, "manifest", "", "imzalı sürüm dosyası (*.release.json)")
	fl.StringVar(&o.dir, "dir", "", "dosyaların klasörü (varsayılan: manifestonun klasörü)")
	fl.StringVar(&o.revocations, "revocations", "", "kök imzalı iptal listesi (varsayılan: manifestonun yanındaki "+revocationsFile+")")
	fl.StringVar(&o.installed, "installed", "", "kurulu sürüm; daha eski bir sürüm reddedilir (geri alma koruması)")
	fl.BoolVar(&o.allowDowngrade, "allow-downgrade", false, "eski sürüme dönmeye bilerek izin ver")
	fl.BoolVar(&o.requireValidNow, "require-valid-cert", false, "imzalama sertifikası şu an da geçerli olmalı")
	fl.BoolVar(&o.presentOnly, "present-only", false, "dosya verilmezse yalnızca klasörde bulunanları doğrula")
	fl.BoolVar(&o.printSums, "print-sums", false, "doğrulanan manifestoyu SHA256SUMS biçiminde yaz")
	addP13Flags(fl, o)
	if err := fl.Parse(args); err != nil {
		return nil, err
	}
	if o.manifest == "" && o.advisories == "" {
		return nil, errors.New("-manifest gerekli")
	}
	if o.dir == "" {
		o.dir = filepath.Dir(o.manifest)
	}
	o.files = fl.Args()
	return o, nil
}

func verify(o *options, stdout io.Writer, now time.Time) error {
	root, err := rootKey(o.rootKey)
	if err != nil {
		return err
	}
	if o.rootFingerprint != "" && release.NormalizeFingerprint(o.rootFingerprint) != release.NormalizeFingerprint(root.Fingerprint()) {
		return fmt.Errorf("kök anahtar parmak izi beklenenle eşleşmiyor: %s", root.Fingerprint())
	}
	if o.manifest == "" {
		return checkAdvisories(o, root, "", stdout) // #582: only the advisory list
	}
	var rev *release.Revocations
	if o.revocations != "" {
		data, err := securefile.ReadLimited(o.revocations, maxRevokList)
		if err != nil {
			return err
		}
		if rev, err = release.VerifyRevocations(root, data); err != nil {
			return err
		}
	}
	if rev == nil {
		// A list published next to the manifest applies without a flag.
		listData, err := securefile.ReadLimited(filepath.Join(filepath.Dir(o.manifest), revocationsFile), maxRevokList)
		switch {
		case err == nil:
			if rev, err = release.VerifyRevocations(root, listData); err != nil {
				return err
			}
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
	}
	data, err := securefile.ReadLimited(o.manifest, release.MaxSignedReleaseSize)
	if err != nil {
		return err
	}
	v, err := release.Verify(root, data, release.VerifyOptions{Now: now, Revocations: rev, RequireValidNow: o.requireValidNow})
	if err != nil {
		return err
	}
	m := &v.Manifest
	if o.installed != "" {
		if err := release.CheckUpgrade(o.installed, m.Version, o.allowDowngrade); err != nil {
			return fmt.Errorf("geri alma koruması: %w (bilerek eski sürüm için -allow-downgrade)", err)
		}
	}
	fmt.Fprintf(stdout, "Sürüm: %s %s (derleme %s, imza %s)\n", m.Product, m.Version, m.Build, m.Created.Format(time.RFC3339))
	fmt.Fprintf(stdout, "Kök anahtar: %s\nİmzalama anahtarı: %s (geçerli %s - %s)\n", root.Fingerprint(), v.Certificate.SigningKey.Fingerprint(),
		v.Certificate.NotBefore.Format("2006-01-02"), v.Certificate.NotAfter.Format("2006-01-02"))

	targets, err := targets(o, m)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if err := checkFile(m, t); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "TAMAM  %s\n", filepath.Base(t))
	}
	if o.printSums {
		fmt.Fprint(stdout, m.SHA256Sums())
	}
	return checkP13(o, root, v, data, stdout)
}

// targets returns the paths to check: the given files, or the manifest's
// files in the release directory.
func targets(o *options, m *release.Manifest) ([]string, error) {
	if len(o.files) > 0 {
		out := make([]string, 0, len(o.files))
		for _, f := range o.files {
			if !strings.ContainsAny(f, `/\`) {
				f = filepath.Join(o.dir, f)
			}
			out = append(out, f)
		}
		return out, nil
	}
	var out []string
	for _, a := range m.Artifacts {
		p := filepath.Join(o.dir, a.Name)
		if _, err := os.Lstat(p); err != nil {
			if errors.Is(err, fs.ErrNotExist) && o.presentOnly {
				continue
			}
			return nil, fmt.Errorf("%s eksik: %w", a.Name, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("klasörde manifestodaki dosyalardan hiçbiri yok")
	}
	return out, nil
}

func checkFile(m *release.Manifest, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s normal bir dosya değil", path)
	}
	return m.CheckFile(filepath.Base(path), f)
}

func rootKey(flagValue string) (release.PublicKey, error) {
	s := flagValue
	if s == "" {
		s = embeddedRootKey
	}
	if s == "" {
		return release.PublicKey{}, errors.New("sürüm kök anahtarı yok: bu doğrulayıcı gömülü anahtarsız derlenmiş, -root-key verin")
	}
	if strings.HasPrefix(s, release.PublicKeyPrefix) {
		return release.ParsePublicKey(s)
	}
	data, err := securefile.ReadLimited(s, maxKeyFile)
	if err != nil {
		return release.PublicKey{}, err
	}
	return release.ParsePublicKey(string(bytes.TrimSpace(data)))
}
