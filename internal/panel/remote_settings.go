package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Local settings of remote panel access and the read-only API keys
// (ADR-0107). Both live in the network directory next to the root key,
// readable only by the owner (securefile, 0600), and are never part of the
// signed document: turning remote access on is this computer's choice.

const (
	// RemoteSettingsFile holds the switch and the remote password hash.
	RemoteSettingsFile = "panel-remote.json"
	// APIKeysFile holds the SHA-256 digests of the API keys.
	APIKeysFile = "api-keys.json"

	remoteSchema       = 1
	maxRemoteFile      = 16 << 10
	minRemotePassword  = 12
	maxRemotePassword  = 256
	remoteSaltBytes    = 16
	remoteHashBytes    = 32
	remoteArgonTime    = 3
	remoteArgonMemory  = 64 * 1024
	remoteArgonThreads = 4

	// MaxAPIKeys bounds the keys of one network.
	MaxAPIKeys       = 16
	maxAPIKeyName    = 64
	apiKeyPrefix     = "osk_"
	apiKeyIDBytes    = 4
	apiKeySecretSize = 32
)

// Errors of the settings stores.
var (
	ErrRemotePasswordWeak = errors.New("uzak erişim parolası en az 12 karakter olmalı ve tahmin edilmesi zor olmalı")
	ErrAPIKeyNotFound     = errors.New("API anahtarı bulunamadı")
	ErrTooManyAPIKeys     = fmt.Errorf("en çok %d API anahtarı olabilir; önce birini silin", MaxAPIKeys)
)

// RemotePassword is an Argon2id digest of the remote access password.
type RemotePassword struct {
	Alg       string `json:"alg"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
	Hash      []byte `json:"hash"`
}

// RemoteSettings is RemoteSettingsFile.
type RemoteSettings struct {
	Schema   int             `json:"schema"`
	Enabled  bool            `json:"enabled"`
	Password *RemotePassword `json:"password,omitempty"`
	// ChangedAt is when the switch or the password last changed.
	ChangedAt time.Time `json:"changed_at"`
}

// Ready reports whether the remote listener may run.
func (s RemoteSettings) Ready() bool { return s.Enabled && s.Password != nil }

// LoadRemoteSettings reads dir/RemoteSettingsFile. A missing file means
// remote access was never turned on.
func LoadRemoteSettings(dir string) (RemoteSettings, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, RemoteSettingsFile), maxRemoteFile)
	if errors.Is(err, fs.ErrNotExist) {
		return RemoteSettings{Schema: remoteSchema}, nil
	}
	if err != nil {
		return RemoteSettings{}, err
	}
	var s RemoteSettings
	if err := json.Unmarshal(data, &s); err != nil || s.Schema != remoteSchema {
		return RemoteSettings{}, errors.New("uzak erişim ayar dosyası bozuk")
	}
	if s.Password != nil && !s.Password.valid() {
		return RemoteSettings{}, errors.New("uzak erişim parola özeti geçersiz")
	}
	return s, nil
}

// SaveRemoteSettings replaces dir/RemoteSettingsFile atomically.
func SaveRemoteSettings(dir string, s RemoteSettings) error {
	s.Schema = remoteSchema
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, RemoteSettingsFile), data)
}

// CheckRemotePassword rejects passwords too short or easy to guess.
func CheckRemotePassword(pw []byte) error {
	n := utf8.RuneCount(pw)
	if n < minRemotePassword || len(pw) > maxRemotePassword || !utf8.Valid(pw) {
		return ErrRemotePasswordWeak
	}
	if strings.ContainsFunc(string(pw), unicode.IsControl) {
		return ErrRemotePasswordWeak
	}
	if trust.EstimatePassphraseBits(pw) < trust.MinPassphraseBits {
		return ErrRemotePasswordWeak
	}
	return nil
}

// HashRemotePassword derives the stored digest. random supplies the salt.
func HashRemotePassword(pw []byte, random io.Reader) (*RemotePassword, error) {
	if err := CheckRemotePassword(pw); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, remoteSaltBytes)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}
	p := &RemotePassword{Alg: "argon2id", Time: remoteArgonTime, MemoryKiB: remoteArgonMemory, Threads: remoteArgonThreads, Salt: salt}
	p.Hash = argon2.IDKey(pw, salt, p.Time, p.MemoryKiB, p.Threads, remoteHashBytes)
	return p, nil
}

// valid bounds the parameters so a damaged file cannot make one check
// take minutes or gigabytes.
func (p *RemotePassword) valid() bool {
	return p.Alg == "argon2id" && p.Time >= 1 && p.Time <= 10 &&
		p.MemoryKiB >= 8*1024 && p.MemoryKiB <= 256*1024 && p.Threads >= 1 && p.Threads <= 16 &&
		len(p.Salt) >= remoteSaltBytes && len(p.Salt) <= 64 && len(p.Hash) == remoteHashBytes
}

// Verify compares pw with the digest in constant time.
func (p *RemotePassword) Verify(pw []byte) bool {
	if p == nil || !p.valid() || len(pw) == 0 || len(pw) > maxRemotePassword {
		return false
	}
	got := argon2.IDKey(pw, p.Salt, p.Time, p.MemoryKiB, p.Threads, remoteHashBytes)
	return subtle.ConstantTimeCompare(got, p.Hash) == 1
}

// APIKey is one read-only API key (ADR-0107). Only the digest is stored.
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
	// Remote lets the key work on the tunnel listener too; otherwise it is
	// accepted only by the loopback panel.
	Remote bool `json:"remote"`
}

type apiKeysFile struct {
	Schema int      `json:"schema"`
	Keys   []APIKey `json:"keys"`
}

// LoadAPIKeys reads dir/APIKeysFile; a missing file has no keys.
func LoadAPIKeys(dir string) ([]APIKey, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, APIKeysFile), maxRemoteFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f apiKeysFile
	if err := json.Unmarshal(data, &f); err != nil || f.Schema != remoteSchema || len(f.Keys) > MaxAPIKeys {
		return nil, errors.New("API anahtarı dosyası bozuk")
	}
	return f.Keys, nil
}

func saveAPIKeys(dir string, keys []APIKey) error {
	data, err := json.MarshalIndent(apiKeysFile{Schema: remoteSchema, Keys: keys}, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, APIKeysFile), data)
}

func validAPIKeyName(name string) bool {
	if name == "" || len(name) > maxAPIKeyName {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

func apiKeyDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey adds a key and returns its secret, shown to the owner once.
func CreateAPIKey(dir, name string, remote bool, random io.Reader, now time.Time) (string, APIKey, error) {
	if !validAPIKeyName(name) {
		return "", APIKey{}, errors.New("anahtar adı 1-64 karakter olmalı: harf, rakam, '-', '_' veya '.'")
	}
	keys, err := LoadAPIKeys(dir)
	if err != nil {
		return "", APIKey{}, err
	}
	if len(keys) >= MaxAPIKeys {
		return "", APIKey{}, ErrTooManyAPIKeys
	}
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, apiKeyIDBytes+apiKeySecretSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", APIKey{}, err
	}
	id := hex.EncodeToString(buf[:apiKeyIDBytes])
	for _, k := range keys {
		if k.ID == id || k.Name == name {
			return "", APIKey{}, errors.New("bu adla veya kimlikle bir anahtar zaten var")
		}
	}
	secret := apiKeyPrefix + id + "_" + base64.RawURLEncoding.EncodeToString(buf[apiKeyIDBytes:])
	k := APIKey{ID: id, Name: name, Digest: apiKeyDigest(secret), CreatedAt: now.UTC().Truncate(time.Second), Remote: remote}
	if err := saveAPIKeys(dir, append(keys, k)); err != nil {
		return "", APIKey{}, err
	}
	return secret, k, nil
}

// RevokeAPIKey removes the key with the id or name.
func RevokeAPIKey(dir, idOrName string) (APIKey, error) {
	keys, err := LoadAPIKeys(dir)
	if err != nil {
		return APIKey{}, err
	}
	i := slices.IndexFunc(keys, func(k APIKey) bool { return k.ID == idOrName || k.Name == idOrName })
	if i < 0 {
		return APIKey{}, ErrAPIKeyNotFound
	}
	k := keys[i]
	if err := saveAPIKeys(dir, slices.Delete(keys, i, i+1)); err != nil {
		return APIKey{}, err
	}
	return k, nil
}

// lookupAPIKey finds the key a bearer secret belongs to.
func lookupAPIKey(dir, secret string) (APIKey, bool) {
	rest, ok := strings.CutPrefix(secret, apiKeyPrefix)
	if !ok || len(secret) > 128 {
		return APIKey{}, false
	}
	id, _, ok := strings.Cut(rest, "_")
	if !ok || len(id) != 2*apiKeyIDBytes {
		return APIKey{}, false
	}
	keys, err := LoadAPIKeys(dir)
	if err != nil {
		return APIKey{}, false
	}
	digest := apiKeyDigest(secret)
	for _, k := range keys {
		if k.ID == id && subtle.ConstantTimeCompare([]byte(k.Digest), []byte(digest)) == 1 {
			return k, true
		}
	}
	return APIKey{}, false
}
