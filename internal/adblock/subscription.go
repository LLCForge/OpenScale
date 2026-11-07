package adblock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Subscription limits.
const (
	MaxSubscriptions       = 32
	DefaultFetchTimeout    = 60 * time.Second
	MaxFetchTimeout        = 5 * time.Minute
	maxURLLen              = 2048
	maxRedirects           = 3
	ManifestName           = "adblock-manifest.json"
	manifestVersion        = 1
	maxManifestSize        = 64 << 10
	artifactFilePermission = 0o644
)

// Errors of the subscription path.
var (
	ErrNotExitNode    = errors.New("liste aboneliği yalnızca çıkış düğümünde indirilebilir")
	ErrDigestMismatch = errors.New("indirilen listenin SHA-256 özeti imzalı belgedeki özetle uyuşmuyor; liste reddedildi")
	ErrTooLarge       = fmt.Errorf("indirilen liste %d MiB'tan büyük", MaxDownloadSize>>20)
)

// Subscription is a list the owner approved in the signed document: its
// category, its https address and the SHA-256 digest of the exact content
// the owner reviewed. A list whose content changes is rejected until the
// owner signs the new digest; nothing is fetched that the owner did not
// name (ADR-0008).
type Subscription struct {
	Category string `json:"category"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

// Validate checks the address and the digest form.
func (s Subscription) Validate() error {
	if _, err := ParseCategory(s.Category); err != nil {
		return err
	}
	if err := validURL(s.URL); err != nil {
		return err
	}
	if len(s.SHA256) != 64 || strings.ToLower(s.SHA256) != s.SHA256 {
		return errors.New("SHA-256 özeti 64 küçük onaltılık karakter olmalı")
	}
	if _, err := hex.DecodeString(s.SHA256); err != nil {
		return errors.New("SHA-256 özeti onaltılık değil")
	}
	return nil
}

func validURL(raw string) error {
	if raw == "" || len(raw) > maxURLLen || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return errors.New("abonelik adresi geçersiz")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("abonelik adresi okunamadı: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("abonelik adresi yalnızca https olabilir")
	}
	if u.User != nil {
		return errors.New("abonelik adresinde kullanıcı bilgisi olamaz")
	}
	if u.Hostname() == "" {
		return errors.New("abonelik adresinde sunucu yok")
	}
	return nil
}

// ValidateSubscriptions checks a document's subscription list.
func ValidateSubscriptions(subs []Subscription) error {
	if len(subs) > MaxSubscriptions {
		return fmt.Errorf("en fazla %d liste aboneliği olabilir", MaxSubscriptions)
	}
	seen := map[string]bool{}
	for i, s := range subs {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("abonelik %d: %w", i+1, err)
		}
		if seen[s.URL] {
			return fmt.Errorf("abonelik %d: adres iki kez yazılmış", i+1)
		}
		seen[s.URL] = true
	}
	return nil
}

// Artifact is a verified list ready to hand to the devices: the content
// is stored as a file whose SHA-256 is the subscription's pinned digest.
type Artifact struct {
	Category string `json:"category"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	File     string `json:"file"`
	Names    int    `json:"names"`
	Skipped  int    `json:"skipped"`
}

// Fetcher downloads approved subscriptions. It refuses to run unless
// ExitNode is set: lists are fetched once on the exit node and handed to
// the other devices as files with their digest.
type Fetcher struct {
	ExitNode bool
	// Client is used as given except for its redirect rule, which always
	// refuses non-https targets; nil uses a client without a proxy.
	Client  *http.Client
	Timeout time.Duration
}

func (f *Fetcher) client() *http.Client {
	var c http.Client
	if f.Client != nil {
		c = *f.Client
	} else {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil // ADR-0008: no address the owner did not name
		c.Transport = t
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("çok fazla yönlendirme")
		}
		if req.URL.Scheme != "https" {
			return errors.New("https olmayan bir adrese yönlendirme reddedildi")
		}
		return nil
	}
	return &c
}

// Fetch downloads s (at most MaxDownloadSize bytes, within the timeout),
// checks its digest against the pinned one and that it is a readable
// list. It returns the artifact description (File is empty until
// WriteArtifact) and the content.
func (f *Fetcher) Fetch(ctx context.Context, s Subscription) (Artifact, []byte, error) {
	if f == nil || !f.ExitNode {
		return Artifact{}, nil, ErrNotExitNode
	}
	if err := s.Validate(); err != nil {
		return Artifact{}, nil, err
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	if timeout > MaxFetchTimeout {
		timeout = MaxFetchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return Artifact{}, nil, err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := f.client().Do(req)
	if err != nil {
		return Artifact{}, nil, fmt.Errorf("liste indirilemedi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Artifact{}, nil, fmt.Errorf("liste indirilemedi: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxDownloadSize {
		return Artifact{}, nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownloadSize+1))
	if err != nil {
		return Artifact{}, nil, fmt.Errorf("liste indirilemedi: %w", err)
	}
	if len(data) > MaxDownloadSize {
		return Artifact{}, nil, ErrTooLarge
	}
	a, err := VerifyContent(s.Category, s.SHA256, data)
	if err != nil {
		return Artifact{}, nil, err
	}
	return a, data, nil
}

// VerifyContent checks data against the pinned digest and that it reads
// as a list of the category.
func VerifyContent(category, sha string, data []byte) (Artifact, error) {
	c, err := ParseCategory(category)
	if err != nil {
		return Artifact{}, err
	}
	want, err := hex.DecodeString(sha)
	if err != nil || len(want) != sha256.Size {
		return Artifact{}, errors.New("SHA-256 özeti geçersiz")
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return Artifact{}, ErrDigestMismatch
	}
	a := Artifact{Category: c.String(), SHA256: hex.EncodeToString(got[:]), Size: int64(len(data))}
	a.Skipped, err = ParseList(bytes.NewReader(data), MaxDownloadSize, func(string, bool) error {
		a.Names++
		return nil
	})
	if err != nil {
		return Artifact{}, err
	}
	if a.Names == 0 {
		return Artifact{}, errors.New("indirilen içerik hiç alan adı içermiyor")
	}
	return a, nil
}

// artifactFile is the file name of a list: category and digest prefix.
func artifactFile(a Artifact) string {
	return a.Category + "-" + a.SHA256[:16] + ".list"
}

// WriteArtifact stores data in dir under a name derived from the digest
// (written to a temporary file and renamed) and returns the artifact with
// File set.
func WriteArtifact(dir string, a Artifact, data []byte) (Artifact, error) {
	if _, err := VerifyContent(a.Category, a.SHA256, data); err != nil {
		return Artifact{}, err
	}
	a.File = artifactFile(a)
	if err := writeAtomic(filepath.Join(dir, a.File), data); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".adblock-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, artifactFilePermission); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// Manifest lists the artifacts handed to the devices.
type Manifest struct {
	Version int        `json:"version"`
	Lists   []Artifact `json:"lists"`
}

// WriteManifest stores the manifest in dir.
func WriteManifest(dir string, lists []Artifact) error {
	m := Manifest{Version: manifestVersion, Lists: append([]Artifact(nil), lists...)}
	sort.Slice(m.Lists, func(i, j int) bool { return m.Lists[i].File < m.Lists[j].File })
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, ManifestName), b)
}

// LoadDistributed is the device side: it reads the manifest and the list
// files from dir, accepts only artifacts whose digest is one the owner
// approved in subs (the signed document), verifies every file and builds
// the matcher together with the local keep list (may be nil).
func LoadDistributed(dir string, subs []Subscription, keep io.Reader) (*Matcher, []Artifact, error) {
	if err := ValidateSubscriptions(subs); err != nil {
		return nil, nil, err
	}
	approved := map[string]string{} // digest -> category
	for _, s := range subs {
		approved[s.SHA256] = s.Category
	}
	f, err := openRegular(filepath.Join(dir, ManifestName), maxManifestSize)
	if err != nil {
		return nil, nil, err
	}
	var m Manifest
	err = json.NewDecoder(io.LimitReader(f, maxManifestSize)).Decode(&m)
	f.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("liste bildirimi okunamadı: %w", err)
	}
	if m.Version != manifestVersion || len(m.Lists) > MaxSubscriptions {
		return nil, nil, errors.New("liste bildirimi desteklenmiyor")
	}
	b := NewBuilder()
	var used []Artifact
	for _, a := range m.Lists {
		cat, ok := approved[a.SHA256]
		if !ok || cat != a.Category {
			continue // not (or no longer) approved: ignored, never trusted
		}
		if a.File != artifactFile(a) {
			return nil, nil, fmt.Errorf("liste dosya adı beklenmiyor: %q", a.File)
		}
		data, err := readLimited(filepath.Join(dir, a.File), MaxDownloadSize)
		if err != nil {
			return nil, nil, err
		}
		got, err := VerifyContent(a.Category, a.SHA256, data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", a.File, err)
		}
		c, _ := ParseCategory(a.Category)
		if _, err := b.addList(c, bytes.NewReader(data), MaxDownloadSize); err != nil {
			return nil, nil, err
		}
		got.File = a.File
		used = append(used, got)
	}
	if keep != nil {
		if _, err := b.AddKeep(keep); err != nil {
			return nil, nil, err
		}
	}
	return b.Build(), used, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
