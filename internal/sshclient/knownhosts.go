package sshclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"golang.org/x/crypto/ssh"
)

// Trust on first use for host keys (ADR-0203). The first key a target
// shows is pinned in a small JSON file; a later different key is refused
// with HostKeyChangedError until the owner explicitly forgets the old
// one. The file holds only public keys.

const knownHostsVersion = 1

// maxKnownHosts bounds the pinned targets; maxKnownHostsFile the file.
const (
	maxKnownHosts     = 4096
	maxKnownHostsFile = 4 << 20
)

// HostKeyStatus tells what Check did.
type HostKeyStatus int

// Host key check results.
const (
	// HostKeyKnown: the key matches the pinned one.
	HostKeyKnown HostKeyStatus = iota + 1
	// HostKeyPinned: no key was pinned; this one is now.
	HostKeyPinned
	// HostKeyCertified: the key is a host certificate from a trusted
	// authority; nothing is pinned.
	HostKeyCertified
)

// HostKeyInfo describes the key a target showed.
type HostKeyInfo struct {
	Host        string
	Type        string
	Fingerprint string
	Status      HostKeyStatus
}

// HostKeyChangedError is returned when a target shows a key other than
// the pinned one: a reinstalled system, or someone in the middle.
type HostKeyChangedError struct {
	Host     string
	Pinned   string // fingerprint of the pinned key
	Received string // fingerprint of the key shown now
	Since    time.Time
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("sshclient: %s sunucu anahtarı değişti (kayıtlı %s, gelen %s); ortadaki saldırı olabilir, bağlantı kesildi",
		e.Host, e.Pinned, e.Received)
}

// ErrHostKeyChanged matches every HostKeyChangedError with errors.Is.
var ErrHostKeyChanged = errors.New("sshclient: sunucu anahtarı değişti")

// Is lets errors.Is(err, ErrHostKeyChanged) match.
func (e *HostKeyChangedError) Is(target error) bool { return target == ErrHostKeyChanged }

type pinned struct {
	Key       string    `json:"key"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type knownFile struct {
	Version int                `json:"version"`
	Hosts   map[string]*pinned `json:"hosts"`
}

// KnownHosts is the pinned host key store. Safe for concurrent use within
// one process.
type KnownHosts struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

// OpenKnownHosts uses the file at path (created on first pin).
func OpenKnownHosts(path string) *KnownHosts {
	return &KnownHosts{path: path, now: time.Now}
}

func (k *KnownHosts) load() (*knownFile, error) {
	data, err := securefile.ReadLimited(k.path, maxKnownHostsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return &knownFile{Version: knownHostsVersion, Hosts: map[string]*pinned{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sshclient: bilinen sunucular okunamadı: %w", err)
	}
	var f knownFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Version != knownHostsVersion {
		return nil, errors.New("sshclient: bilinen sunucular dosyası bozuk; elle silinmesi gerekir")
	}
	if f.Hosts == nil {
		f.Hosts = map[string]*pinned{}
	}
	for h, p := range f.Hosts {
		if p == nil || validHost(h) != nil {
			return nil, errors.New("sshclient: bilinen sunucular dosyası bozuk; elle silinmesi gerekir")
		}
	}
	return &f, nil
}

func (k *KnownHosts) save(f *knownFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(k.path, append(data, '\n'))
}

func validHost(h string) error {
	if h == "" || len(h) > 300 || strings.ContainsAny(h, " \t\r\n\x00") {
		return errors.New("sshclient: geçersiz sunucu adı")
	}
	return nil
}

func keyLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// Check compares key with the pinned key of host and pins it when there
// is none yet.
func (k *KnownHosts) Check(host string, key ssh.PublicKey) (HostKeyInfo, error) {
	if err := validHost(host); err != nil {
		return HostKeyInfo{}, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.load()
	if err != nil {
		return HostKeyInfo{}, err
	}
	info := HostKeyInfo{Host: host, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
	now := k.now().UTC()
	line := keyLine(key)
	if p, ok := f.Hosts[host]; ok {
		if p.Key != line {
			old := p.Key
			pinnedFP := "?"
			if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(old)); err == nil {
				pinnedFP = ssh.FingerprintSHA256(pk)
			}
			return info, &HostKeyChangedError{Host: host, Pinned: pinnedFP, Received: info.Fingerprint, Since: p.FirstSeen}
		}
		info.Status = HostKeyKnown
		if now.Sub(p.LastSeen) > time.Hour {
			p.LastSeen = now
			_ = k.save(f) // best effort; the key itself is unchanged
		}
		return info, nil
	}
	if len(f.Hosts) >= maxKnownHosts {
		return info, errors.New("sshclient: bilinen sunucu sınırı doldu")
	}
	f.Hosts[host] = &pinned{Key: line, FirstSeen: now, LastSeen: now}
	if err := k.save(f); err != nil {
		return info, fmt.Errorf("sshclient: sunucu anahtarı kaydedilemedi: %w", err)
	}
	info.Status = HostKeyPinned
	return info, nil
}

// Forget removes the pinned key of host; the next connection pins again.
// The owner calls it after confirming that the key change is expected.
func (k *KnownHosts) Forget(host string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.load()
	if err != nil {
		return false, err
	}
	if _, ok := f.Hosts[host]; !ok {
		return false, nil
	}
	delete(f.Hosts, host)
	return true, k.save(f)
}

// Entry is one pinned host.
type Entry struct {
	Host        string    `json:"host"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// List returns the pinned hosts sorted by name.
func (k *KnownHosts) List() ([]Entry, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.load()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(f.Hosts))
	for _, h := range slices.Sorted(maps.Keys(f.Hosts)) {
		p := f.Hosts[h]
		e := Entry{Host: h, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen, Fingerprint: "?"}
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.Key)); err == nil {
			e.Type, e.Fingerprint = pk.Type(), ssh.FingerprintSHA256(pk)
		}
		out = append(out, e)
	}
	return out, nil
}
