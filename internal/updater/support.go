package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

// EmbeddedRootKey is the release root public key, set by
// scripts/release.sh (-X .../internal/updater.EmbeddedRootKey=osrelkey1:...).
var EmbeddedRootKey = ""

const (
	versionTimeout = 20 * time.Second
	maxVersionOut  = 4 << 10
	maxKeyFile     = 4 << 10
)

// RunVersion runs "<exe> version --json" with a small environment and
// returns the version it reports, without the build stamp.
func RunVersion(ctx context.Context, exe string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "version", "--json")
	cmd.Env = minimalEnv()
	cmd.Dir = filepath.Dir(exe)
	var out limitedBuffer
	out.max = maxVersionOut
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return ParseVersionOutput(out.Bytes())
}

// ParseVersionOutput reads the output of "openscale version --json".
func ParseVersionOutput(data []byte) (string, error) {
	var v struct {
		Schema  int    `json:"schema"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &v); err != nil || v.Version == "" {
		return "", errors.New("program sürümünü bildirmedi")
	}
	ver, _, _ := strings.Cut(v.Version, " ") // "0.9.0 (20261030.0412)"
	if _, err := release.ParseVersion(ver); err != nil {
		return "", fmt.Errorf("program geçersiz bir sürüm bildirdi: %q", v.Version)
	}
	return ver, nil
}

func minimalEnv() []string {
	if runtime.GOOS != "windows" {
		return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	}
	var env []string
	for _, k := range []string{"SystemRoot", "SystemDrive", "windir", "TEMP", "TMP", "ProgramData", "ProgramFiles"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }

func (b *limitedBuffer) String() string { return b.buf.String() }

// LoadRootKey reads a release root public key: the text form
// (osrelkey1:...) or a file holding it. Empty uses the embedded key, then
// the platform's default file.
func LoadRootKey(spec string) (release.PublicKey, string, error) {
	if spec == "" {
		if EmbeddedRootKey != "" {
			k, err := release.ParsePublicKey(EmbeddedRootKey)
			return k, "programa gömülü", err
		}
		spec = DefaultRootKeyFile()
		if spec == "" {
			return release.PublicKey{}, "", errors.New("sürüm kök açık anahtarı yok; --root-key ile verin")
		}
		if _, err := os.Stat(spec); err != nil {
			return release.PublicKey{}, "", fmt.Errorf("sürüm kök açık anahtarı yok (%s); --root-key ile verin", spec)
		}
	}
	if strings.HasPrefix(strings.TrimSpace(spec), release.PublicKeyPrefix) {
		k, err := release.ParsePublicKey(spec)
		return k, "komut satırı", err
	}
	data, err := securefile.ReadLimited(spec, maxKeyFile)
	if err != nil {
		return release.PublicKey{}, "", err
	}
	k, err := release.ParsePublicKey(string(data))
	return k, spec, err
}

// LoadSource prepares a release from ref: a signed manifest file
// (*.release.json), a folder holding exactly one, or an https:// URL of a
// manifest on the owner's server. The program is looked up next to the
// manifest under artifact, unless program names it.
func LoadSource(ctx context.Context, ref, program, artifact string, client *http.Client) (Source, error) {
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return loadURL(ctx, ref, program, artifact, client)
	}
	manifest := ref
	if info, err := os.Stat(ref); err == nil && info.IsDir() {
		matches, _ := filepath.Glob(filepath.Join(ref, "openscale-*.release.json"))
		switch len(matches) {
		case 0:
			return Source{}, fmt.Errorf("%s içinde imzalı sürüm dosyası (openscale-*.release.json) yok", ref)
		case 1:
			manifest = matches[0]
		default:
			return Source{}, fmt.Errorf("%s içinde birden fazla imzalı sürüm dosyası var; dosyayı adıyla verin", ref)
		}
	}
	data, err := securefile.ReadLimited(manifest, release.MaxSignedReleaseSize)
	if err != nil {
		return Source{}, fmt.Errorf("imzalı sürüm dosyası okunamadı: %w", err)
	}
	if program == "" {
		program = filepath.Join(filepath.Dir(manifest), artifact)
	}
	revocations, err := securefile.ReadLimited(filepath.Join(filepath.Dir(manifest), RevocationsFile), release.MaxRevocationsSize)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return Source{}, fmt.Errorf("iptal listesi okunamadı: %w", err)
		}
		revocations = nil
	}
	return Source{Manifest: data, Revocations: revocations, Where: program, Open: func(context.Context) (io.ReadCloser, error) {
		return os.Open(program)
	}}, nil
}

// HTTPClient is the client for the owner's server: HTTPS only, no
// redirect to another scheme, bounded time.
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("çok fazla yönlendirme")
			}
			if req.URL.Scheme != "https" {
				return errors.New("yalnızca https adreslerine yönlendirme kabul edilir")
			}
			return nil
		},
	}
}

func loadURL(ctx context.Context, ref, program, artifact string, client *http.Client) (Source, error) {
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		// SECURITY FIX: CWE-319 updates are fetched over HTTPS only; the
		// signature protects integrity, TLS keeps the server's content and
		// the owner's request private.
		return Source{}, errors.New("adres https:// ile başlamalı ve kullanıcı bilgisi içermemeli")
	}
	if client == nil {
		client = HTTPClient()
	}
	data, err := fetch(ctx, client, u.String(), release.MaxSignedReleaseSize)
	if err != nil {
		return Source{}, fmt.Errorf("imzalı sürüm dosyası indirilemedi: %w", err)
	}
	if program == "" {
		base := *u
		base.RawQuery = ""
		base.Path = strings.TrimSuffix(base.Path, "/")
		if i := strings.LastIndex(base.Path, "/"); i >= 0 {
			base.Path = base.Path[:i+1] + url.PathEscape(artifact)
		} else {
			base.Path = "/" + url.PathEscape(artifact)
		}
		program = base.String()
	} else if p, err := url.Parse(program); err != nil || p.Scheme != "https" || p.User != nil {
		return Source{}, errors.New("program adresi https:// ile başlamalı")
	}
	return Source{Manifest: data, Revocations: fetchRevocations(ctx, client, u), Where: program, Open: func(ctx context.Context) (io.ReadCloser, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, program, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("sunucu %s döndürdü", resp.Status)
		}
		return resp.Body, nil
	}}, nil
}

func fetch(ctx context.Context, client *http.Client, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sunucu %s döndürdü", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("dosya çok büyük")
	}
	return data, nil
}

// plainKeys lists the key files that are stored without DPAPI.
func plainKeys(files []string) []string {
	var out []string
	for _, f := range files {
		if s, err := securefile.FileScheme(f); err == nil && s == securefile.SchemeNone {
			out = append(out, f)
		}
	}
	return out
}

// keyWarnings explains what to do when the new version protected key
// files the previous version stored in plain form (ADR-0060): an older
// version without DPAPI support cannot read them.
func keyWarnings(wasPlain []string) []string {
	var changed []string
	for _, f := range wasPlain {
		if s, err := securefile.FileScheme(f); err == nil && s != securefile.SchemeNone {
			changed = append(changed, f)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("yeni sürüm şu anahtar dosyalarını DPAPI ile korudu: %s. Önceki sürüm DPAPI desteklemiyorsa servis anahtarı okuyamaz; servisi durdurup 'openscale key unprotect --data-dir <veri klasörü>' çalıştırın (ADR-0060)",
		strings.Join(changed, ", "))}
}

// ProtectedKeys lists the key files that are DPAPI-protected now.
func ProtectedKeys(files []string) []string {
	var out []string
	for _, f := range files {
		if s, err := securefile.FileScheme(f); err == nil && s != securefile.SchemeNone {
			out = append(out, f)
		}
	}
	return out
}
