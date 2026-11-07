package filesend

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// Time-limited single file links (#460). The owner offers one file to
// one device for a number of downloads or hours; the link is served
// inside the tunnel (on the serve port) and closes itself afterwards.
// Unlike a published directory it is never permanent.
//
// The link's secret appears only in the URL given to the owner once; the
// store keeps its SHA-256. A request is served only to the named device
// (identified by its tunnel source address by the caller), only while the
// link lives and only while the file is unchanged since the link was made.

const (
	// LinkPrefix is the URL path prefix of links.
	LinkPrefix = "/l/"
	// MaxLinks bounds the active links.
	MaxLinks = 64
	// MaxLinkDownloads bounds the downloads of one link.
	MaxLinkDownloads = 100
	// MinLinkTTL and MaxLinkTTL bound a link's lifetime.
	MinLinkTTL = time.Minute
	MaxLinkTTL = 30 * 24 * time.Hour

	linkStoreSchema = 1
	maxLinkFile     = 1 << 20
)

var (
	// ErrLinkNotFound is returned for unknown, expired or used up links.
	ErrLinkNotFound = errors.New("filesend: bağlantı yok veya süresi doldu")
)

// Link is one offered file.
type Link struct {
	ID           string    `json:"id"`
	TokenHash    string    `json:"token_hash"`
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Device       string    `json:"device"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	Created      time.Time `json:"created"`
	Expires      time.Time `json:"expires"`
	MaxDownloads int       `json:"max_downloads"`
	Downloads    int       `json:"downloads"`
}

// Live reports whether the link may still be used at now.
func (l Link) Live(now time.Time) bool {
	return now.Before(l.Expires) && l.Downloads < l.MaxDownloads
}

type linkFile struct {
	V     int    `json:"v"`
	Links []Link `json:"links"`
}

// LinkStore keeps the links in a file (owner only).
type LinkStore struct {
	mu    sync.Mutex
	file  string
	now   func() time.Time
	links []Link
	// OnDownload, when set, is called after a download started.
	OnDownload func(l Link)
}

// OpenLinkStore reads the store at file (missing is empty).
func OpenLinkStore(file string, now func() time.Time) (*LinkStore, error) {
	if now == nil {
		now = time.Now
	}
	s := &LinkStore{file: file, now: now}
	data, err := securefile.ReadPrivate(file, maxLinkFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	var f linkFile
	if err := json.Unmarshal(data, &f); err != nil || f.V != linkStoreSchema {
		return nil, errors.New("filesend: bağlantı dosyası bozuk")
	}
	s.links = f.Links
	return s, nil
}

func (s *LinkStore) saveLocked() error {
	data, err := json.MarshalIndent(linkFile{V: linkStoreSchema, Links: s.links}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.file), 0o700); err != nil {
		return err
	}
	return securefile.Replace(s.file, data)
}

// pruneLocked drops links that can no longer be used.
func (s *LinkStore) pruneLocked() bool {
	now := s.now()
	n := len(s.links)
	s.links = slices.DeleteFunc(s.links, func(l Link) bool { return !l.Live(now) })
	return len(s.links) != n
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte("openscale link\x00" + tok))
	return hex.EncodeToString(h[:])
}

// Create offers the regular file at path to device. It returns the link
// and its secret token (shown once; the URL is LinkPrefix + token).
func (s *LinkStore) Create(path, device string, ttl time.Duration, downloads int) (Link, string, error) {
	if !filepath.IsAbs(path) {
		return Link{}, "", errors.New("dosya yolu mutlak olmalı")
	}
	if ttl < MinLinkTTL || ttl > MaxLinkTTL {
		return Link{}, "", fmt.Errorf("geçerlilik süresi %s ile %s arasında olmalı", MinLinkTTL, MaxLinkTTL)
	}
	if downloads < 1 || downloads > MaxLinkDownloads {
		return Link{}, "", fmt.Errorf("indirme sayısı 1 ile %d arasında olmalı", MaxLinkDownloads)
	}
	if device == "" {
		return Link{}, "", errors.New("cihaz adı gerekli")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Link{}, "", errors.New("dosya bulunamadı veya normal bir dosya değil")
	}
	name, err := SanitizeName(filepath.Base(path))
	if err != nil {
		return Link{}, "", errors.New("dosya adı güvenli değil")
	}
	tok := make([]byte, 32)
	id := make([]byte, 8)
	if _, err := rand.Read(tok); err != nil {
		return Link{}, "", err
	}
	if _, err := rand.Read(id); err != nil {
		return Link{}, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tok)
	now := s.now().UTC()
	l := Link{ID: hex.EncodeToString(id), TokenHash: hashToken(token), Path: filepath.Clean(path), Name: name, Device: device,
		Size: info.Size(), ModTime: info.ModTime().UTC(), Created: now, Expires: now.Add(ttl), MaxDownloads: downloads}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if len(s.links) >= MaxLinks {
		return Link{}, "", fmt.Errorf("en çok %d etkin bağlantı olabilir", MaxLinks)
	}
	s.links = append(s.links, l)
	if err := s.saveLocked(); err != nil {
		s.links = s.links[:len(s.links)-1]
		return Link{}, "", err
	}
	return l, token, nil
}

// List returns the live links, newest first.
func (s *LinkStore) List() []Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruneLocked() {
		_ = s.saveLocked()
	}
	out := slices.Clone(s.links)
	slices.SortFunc(out, func(a, b Link) int { return b.Created.Compare(a.Created) })
	return out
}

// Active reports whether some link is live.
func (s *LinkStore) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	return slices.ContainsFunc(s.links, func(l Link) bool { return l.Live(now) })
}

// Revoke ends a link at once.
func (s *LinkStore) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.links)
	s.links = slices.DeleteFunc(s.links, func(l Link) bool { return l.ID == id })
	if len(s.links) == n {
		return false, nil
	}
	return true, s.saveLocked()
}

// claim finds the link of token for peer and, for a download, counts it.
func (s *LinkStore) claim(token, peer string, count bool) (Link, error) {
	h := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	i := slices.IndexFunc(s.links, func(l Link) bool { return l.TokenHash == h })
	if i < 0 || !s.links[i].Live(now) || s.links[i].Device != peer {
		// The same answer for a wrong device, so a link's existence is not
		// confirmed to anyone else.
		return Link{}, ErrLinkNotFound
	}
	if count {
		s.links[i].Downloads++
		if err := s.saveLocked(); err != nil {
			s.links[i].Downloads--
			return Link{}, err
		}
	}
	return s.links[i], nil
}

// ServeLink serves GET or HEAD LinkPrefix+token to peer, the device name
// the caller identified from the tunnel source address.
func (s *LinkStore) ServeLink(w http.ResponseWriter, r *http.Request, peer string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(w, "Yalnızca indirme", http.StatusMethodNotAllowed)
		return
	}
	token, ok := strings.CutPrefix(r.URL.Path, LinkPrefix)
	if !ok || len(token) != 43 || strings.ContainsAny(token, "/.") {
		http.Error(w, "Bağlantı yok veya süresi doldu", http.StatusNotFound)
		return
	}
	l, err := s.claim(token, peer, false)
	if err != nil {
		http.Error(w, "Bağlantı yok veya süresi doldu", http.StatusNotFound)
		return
	}
	f, err := os.Open(l.Path)
	if err != nil {
		http.Error(w, "Dosya artık yok", http.StatusGone)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != l.Size || !info.ModTime().UTC().Equal(l.ModTime) {
		// SECURITY: only the file the owner offered is served, not
		// whatever replaced it later.
		http.Error(w, "Dosya bağlantı oluşturulduktan sonra değişti", http.StatusConflict)
		return
	}
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(l.Name))
	h.Set("Content-Length", fmt.Sprint(l.Size))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if l, err = s.claim(token, peer, true); err != nil {
		http.Error(w, "Bağlantı yok veya süresi doldu", http.StatusNotFound)
		return
	}
	if s.OnDownload != nil {
		s.OnDownload(l)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(w, f, l.Size)
}
