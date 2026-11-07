package upstream

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/securefile"
)

// On-disk layout under the device state directory (ADR-0142):
//
//	upstream/            0700
//	  <name>.conf        0600  canonical provider configuration (private key)
//	  settings.json      0600  active profile, behaviour when the tunnel is down, labels
//	  status.json        0600  written by the running tunnel, read by "status"
//
// The running "openscale up" re-reads settings.json, so "use" and "off"
// take effect without a restart and without a control socket.
const (
	DirName      = "upstream"
	settingsFile = "settings.json"
	statusFile   = "status.json"
	confSuffix   = ".conf"
	maxProfiles  = 64
	maxLabel     = 48
	maxSmallFile = 64 << 10
)

// What happens to members' internet traffic while the upstream tunnel is
// down.
const (
	// OnDownDrop drops it (default): nothing leaves with this host's own
	// address.
	OnDownDrop = "drop"
	// OnDownDirect lets it leave directly from this host, the way an exit
	// node without an upstream works. A deliberate, warned choice.
	OnDownDirect = "direct"
)

// MTU bounds of the upstream interface. 1420 fits WireGuard over IPv6 on a
// 1500-byte link, the provider default.
const (
	DefaultMTU = 1420
	MinMTU     = 1280
	MaxMTU     = 1420
)

// ErrNotFound is returned for an unknown profile name.
var ErrNotFound = errors.New("üst çıkış profili bulunamadı")

// Settings are the owner's choices.
type Settings struct {
	// Active is the profile in use; "" is off.
	Active string `json:"active,omitempty"`
	// OnDown is OnDownDrop or OnDownDirect; "" means OnDownDrop.
	OnDown string `json:"on_down,omitempty"`
	// MTU of the upstream interface; 0 means DefaultMTU.
	MTU int `json:"mtu,omitempty"`
	// Labels are display names per profile, e.g. "Mullvad · İsveç".
	Labels map[string]string `json:"labels,omitempty"`
	// Providers names the provider kind per profile (ProviderMullvad,
	// ProviderWARP, ProviderWireGuard); display and report only.
	Providers map[string]string `json:"providers,omitempty"`
	// Tor is the Tor exit mode (ADR-0142, Tor appendix). It excludes an
	// active WireGuard profile.
	Tor *TorSettings `json:"tor,omitempty"`
}

// Provider kinds of a WireGuard profile, as the owner named them at import.
const (
	ProviderWireGuard = "wireguard"
	ProviderMullvad   = "mullvad"
	ProviderWARP      = "warp"
)

// ValidateProvider accepts "" and the known provider kinds.
func ValidateProvider(p string) error {
	switch p {
	case "", ProviderWireGuard, ProviderMullvad, ProviderWARP:
		return nil
	}
	return fmt.Errorf("sağlayıcı türü %q geçersiz (mullvad, warp veya wireguard)", p)
}

// Provider returns the provider kind of a profile; ProviderWireGuard when
// the owner named none.
func (s Settings) Provider(name string) string {
	if p := s.Providers[name]; p != "" {
		return p
	}
	return ProviderWireGuard
}

// Kind is what members exit through: KindTor, a provider kind, or "" when
// the upstream exit is off.
func (s Settings) Kind() string {
	switch {
	case s.TorEnabled():
		return KindTor
	case s.Active != "":
		return s.Provider(s.Active)
	}
	return ""
}

// FailOpen reports whether traffic leaves directly while the tunnel is down.
func (s Settings) FailOpen() bool { return s.OnDown == OnDownDirect }

// EffectiveMTU is MTU or the default.
func (s Settings) EffectiveMTU() int {
	if s.MTU == 0 {
		return DefaultMTU
	}
	return s.MTU
}

// Label returns the display name of a profile ("" when none).
func (s Settings) Label(name string) string { return s.Labels[name] }

func (s Settings) validate() error {
	if s.Active != "" {
		if err := ValidateName(s.Active); err != nil {
			return err
		}
	}
	switch s.OnDown {
	case "", OnDownDrop, OnDownDirect:
	default:
		return fmt.Errorf("geçersiz düşme davranışı %q (drop veya direct)", s.OnDown)
	}
	if s.MTU != 0 && (s.MTU < MinMTU || s.MTU > MaxMTU) {
		return fmt.Errorf("MTU %d ile %d arasında olmalı", MinMTU, MaxMTU)
	}
	if len(s.Labels) > maxProfiles || len(s.Providers) > maxProfiles {
		return errors.New("çok fazla etiket")
	}
	for name, p := range s.Providers {
		if err := ValidateName(name); err != nil {
			return err
		}
		if err := ValidateProvider(p); err != nil {
			return err
		}
	}
	if s.Tor != nil {
		if err := s.Tor.validate(); err != nil {
			return err
		}
		if s.Tor.Enabled && s.Active != "" {
			return errors.New("Tor çıkışı ve WireGuard üst çıkış profili aynı anda etkin olamaz")
		}
	}
	for name, label := range s.Labels {
		if err := ValidateName(name); err != nil {
			return err
		}
		if err := ValidateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

// Status is what the running tunnel reports. It holds no key.
type Status struct {
	Active    string `json:"active,omitempty"`
	Label     string `json:"label,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Endpoint is the provider server; local file only (ADR-0008).
	Endpoint string `json:"endpoint,omitempty"`
	// Connected is true while the last handshake is recent enough for the
	// session keys to be valid.
	Connected bool `json:"connected"`
	// LastHandshake is a Unix time, 0 before the first handshake.
	LastHandshake int64  `json:"last_handshake,omitempty"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	// Mode is "tunnel" (members exit through the provider), "blocked"
	// (tunnel down, traffic dropped), "direct" (tunnel down, traffic leaves
	// from this host) or "off".
	Mode       string `json:"mode"`
	OnDown     string `json:"on_down,omitempty"`
	Reconnects uint64 `json:"reconnects,omitempty"`
	Error      string `json:"error,omitempty"`
	// Kind is KindTor or the provider kind of the active profile ("" off).
	Kind string `json:"kind,omitempty"`
	// Tor is the Tor exit's state; nil unless Kind is KindTor.
	Tor *TorStatus `json:"tor,omitempty"`
	// Updated is when the running process last wrote the file (Unix).
	Updated int64 `json:"updated"`
}

// Status modes.
const (
	ModeTunnel  = "tunnel"
	ModeBlocked = "blocked"
	ModeDirect  = "direct"
	ModeOff     = "off"
)

// Profile is one imported configuration, without its private key.
type Profile struct {
	Name      string
	Label     string
	Endpoint  netip.AddrPort
	Address4  string
	Address6  string
	DNS       []string
	PublicKey string
	Active    bool
}

// Store is the upstream directory of one device state directory.
type Store struct {
	dir string
}

// OpenStore returns the store under stateDir, creating it with 0700.
func OpenStore(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("durum klasörü boş")
	}
	dir := filepath.Join(stateDir, DirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("üst çıkış klasörü oluşturulamadı: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s bir klasör değil", dir)
	}
	// SECURITY FIX: CWE-732 the folder holds provider private keys.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("üst çıkış klasörünün izinleri düzeltilemedi: %w", err)
		}
	}
	return &Store{dir: dir}, nil
}

// Dir is the store's folder.
func (s *Store) Dir() string { return s.dir }

// ValidateName accepts lowercase letters, digits and inner hyphens, 1-32
// characters: the name becomes a file name.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 32 {
		return fmt.Errorf("profil adı 1-32 karakter olmalı: %q", name)
	}
	for i, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0 && i < len(name)-1)
		if !ok {
			return fmt.Errorf("profil adı yalnızca küçük harf, rakam ve aradaki tire içerebilir: %q", name)
		}
	}
	return nil
}

// ValidateLabel accepts up to 48 printable characters.
func ValidateLabel(label string) error {
	if !utf8.ValidString(label) || utf8.RuneCountInString(label) > maxLabel {
		return fmt.Errorf("etiket en fazla %d karakter olmalı", maxLabel)
	}
	for _, r := range label {
		if !unicode.IsPrint(r) {
			return errors.New("etikette yazdırılamayan karakter var")
		}
	}
	return nil
}

// NameFromFile turns a downloaded file name such as "se-got-wg-001.conf"
// into a profile name.
func NameFromFile(path string) string {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	var b strings.Builder
	dash := false
	for _, r := range base {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 32 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *Store) confPath(name string) string { return filepath.Join(s.dir, name+confSuffix) }

// Import stores a provider configuration under name. The original file
// is parsed and written back in canonical form (comments dropped) with
// 0600; an existing profile is replaced only with replace.
func (s *Store) Import(name, label string, data []byte, replace bool) (*Config, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if err := ValidateLabel(label); err != nil {
		return nil, err
	}
	return s.ImportWith(name, label, data, ImportOptions{Replace: replace})
}

// ImportOptions are the choices of ImportWith.
type ImportOptions struct {
	// Replace replaces an existing profile of the same name.
	Replace bool
	// Resolve turns an Endpoint name into an address, once, now (Cloudflare
	// WARP files name their server). Nil refuses names.
	Resolve Resolver
	// Provider is ProviderMullvad, ProviderWARP, ProviderWireGuard or "".
	Provider string
}

// ImportWith is Import with an Endpoint resolver and a provider kind.
func (s *Store) ImportWith(name, label string, data []byte, opts ImportOptions) (*Config, error) {
	replace := opts.Replace
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if err := ValidateLabel(label); err != nil {
		return nil, err
	}
	if err := ValidateProvider(opts.Provider); err != nil {
		return nil, err
	}
	cfg, err := ParseWith(data, opts.Resolve)
	if err != nil {
		return nil, err
	}
	names, err := s.names()
	if err != nil {
		cfg.Wipe()
		return nil, err
	}
	exists := slices.Contains(names, name)
	if !exists && len(names) >= maxProfiles {
		cfg.Wipe()
		return nil, fmt.Errorf("en fazla %d profil saklanabilir", maxProfiles)
	}
	if exists && !replace {
		cfg.Wipe()
		return nil, fmt.Errorf("%q profili zaten var; değiştirmek için --replace", name)
	}
	out := cfg.Marshal()
	defer clear(out)
	if exists {
		err = securefile.Replace(s.confPath(name), out)
	} else {
		err = securefile.WriteNew(s.confPath(name), out)
	}
	if err != nil {
		cfg.Wipe()
		return nil, fmt.Errorf("profil yazılamadı: %w", err)
	}
	if err := s.UpdateSettings(func(st *Settings) error {
		if opts.Provider == "" || opts.Provider == ProviderWireGuard {
			delete(st.Providers, name)
		} else {
			if st.Providers == nil {
				st.Providers = map[string]string{}
			}
			st.Providers[name] = opts.Provider
		}
		if label == "" {
			delete(st.Labels, name)
			return nil
		}
		if st.Labels == nil {
			st.Labels = map[string]string{}
		}
		st.Labels[name] = label
		return nil
	}); err != nil {
		cfg.Wipe()
		return nil, err
	}
	return cfg, nil
}

// Load reads a profile; the caller wipes it. A file other local users
// can read is refused (securefile.ReadPrivate).
func (s *Store) Load(name string) (*Config, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := securefile.ReadPrivate(s.confPath(name), MaxConfSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return Parse(data)
}

// ProfileModTime returns when a profile file was last written.
func (s *Store) ProfileModTime(name string) (time.Time, error) {
	if err := ValidateName(name); err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(s.confPath(name))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Remove deletes a profile that is not active.
func (s *Store) Remove(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	st, err := s.Settings()
	if err != nil {
		return err
	}
	if st.Active == name {
		return fmt.Errorf("%q etkin; önce 'exit-node upstream off' veya başka bir profil seç", name)
	}
	if err := os.Remove(s.confPath(name)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return err
	}
	return s.UpdateSettings(func(st *Settings) error {
		delete(st.Labels, name)
		delete(st.Providers, name)
		return nil
	})
}

func (s *Store) names() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, confSuffix) {
			continue
		}
		name := strings.TrimSuffix(n, confSuffix)
		if ValidateName(name) == nil {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// List returns every profile without private keys. A profile that cannot
// be read is listed with only its name.
func (s *Store) List() ([]Profile, error) {
	names, err := s.names()
	if err != nil {
		return nil, err
	}
	st, err := s.Settings()
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(names))
	for _, name := range names {
		p := Profile{Name: name, Label: st.Label(name), Active: st.Active == name}
		if cfg, err := s.Load(name); err == nil {
			p.Endpoint = cfg.Endpoint
			p.Address4 = cfg.Address4.String()
			if cfg.Address6.IsValid() {
				p.Address6 = cfg.Address6.String()
			}
			for _, a := range cfg.DNS {
				p.DNS = append(p.DNS, a.String())
			}
			p.PublicKey = cfg.PublicKeyString()
			cfg.Wipe()
		}
		out = append(out, p)
	}
	return out, nil
}

// Settings reads settings.json; a missing file is the zero value.
func (s *Store) Settings() (Settings, error) {
	data, err := securefile.ReadPrivate(filepath.Join(s.dir, settingsFile), maxSmallFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var st Settings
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return Settings{}, fmt.Errorf("%s bozuk: %w", settingsFile, err)
	}
	if err := st.validate(); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", settingsFile, err)
	}
	return st, nil
}

// UpdateSettings reads, changes and atomically writes settings.json.
func (s *Store) UpdateSettings(change func(*Settings) error) error {
	st, err := s.Settings()
	if err != nil {
		return err
	}
	if err := change(&st); err != nil {
		return err
	}
	if len(st.Labels) == 0 {
		st.Labels = nil
	}
	if len(st.Providers) == 0 {
		st.Providers = nil
	}
	if err := st.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(s.dir, settingsFile), append(data, '\n'))
}

// Use makes name the active profile; it turns the Tor exit off.
func (s *Store) Use(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if _, err := os.Stat(s.confPath(name)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return err
	}
	return s.UpdateSettings(func(st *Settings) error {
		st.Active = name
		st.Tor = nil
		return nil
	})
}

// WriteStatus replaces status.json.
func (s *Store) WriteStatus(st Status) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(s.dir, statusFile), append(data, '\n'))
}

// ReadStatus reads status.json; ok is false when no tunnel ever wrote it.
func (s *Store) ReadStatus() (Status, bool, error) {
	data, err := securefile.ReadPrivate(filepath.Join(s.dir, statusFile), maxSmallFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Status{}, false, nil
	}
	if err != nil {
		return Status{}, false, err
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return Status{}, false, fmt.Errorf("%s bozuk: %w", statusFile, err)
	}
	return st, true, nil
}

// Stale reports whether a status is too old to describe a running process.
func (st Status) Stale(now time.Time) bool {
	return now.Unix()-st.Updated > int64(3*statusRefresh/time.Second)
}
