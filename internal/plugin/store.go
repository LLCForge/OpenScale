package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// DirName is the plugin folder inside the owner's network folder (#788):
// <network folder>/plugins/<name>.wasm and <name>.json.
const DirName = "plugins"

// Store limits.
const (
	MaxModuleSize = 4 << 20 // bytes of one .wasm file
	MaxPlugins    = 32      // pinned plugins
	maxDirEntries = 1024    // directory entries looked at
)

// Pin is one plugin the owner approved in the signed network document:
// the plugin name and the SHA-256 digests (lowercase hex) of its module
// and manifest files. Nothing that is not pinned is ever loaded.
type Pin struct {
	Name           string `json:"name"`
	ModuleSHA256   string `json:"module_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// PinSource supplies the pins of the verified signed document. The signed
// document type (internal/trust) implements it once its plugin field
// exists; the order of the pins is the order plugins are consulted.
type PinSource interface {
	PinnedPlugins() []Pin
}

// PinList is a ready PinSource.
type PinList []Pin

// PinnedPlugins implements PinSource.
func (p PinList) PinnedPlugins() []Pin { return p }

// Status of a plugin in the store.
type Status string

const (
	StatusLoaded         Status = "loaded"          // verified and running
	StatusVerified       Status = "verified"        // digests match; not yet compiled
	StatusUnpinned       Status = "unpinned"        // in the folder, not in the signed document
	StatusMissing        Status = "missing"         // pinned, file absent
	StatusDigestMismatch Status = "digest_mismatch" // pinned, file differs from the pin
	StatusInvalid        Status = "invalid"         // bad manifest or module
)

var statusLabels = map[Status]string{
	StatusLoaded:         "Yüklendi",
	StatusVerified:       "Doğrulandı",
	StatusUnpinned:       "İmzalı belgede sabitlenmemiş, yüklenmedi",
	StatusMissing:        "Sabitlenmiş ama dosya yok",
	StatusDigestMismatch: "Özet uyuşmuyor, yüklenmedi",
	StatusInvalid:        "Geçersiz, yüklenmedi",
}

// Label is the Turkish panel text of the status.
func (s Status) Label() string { return statusLabels[s] }

// Entry is one row of the panel's plugin list (#788, #790).
type Entry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version,omitempty"`
	Description    string   `json:"description,omitempty"`
	Hooks          []string `json:"hooks"`
	Data           []string `json:"data"`
	DataLabels     []string `json:"data_labels"`
	OnError        string   `json:"on_error,omitempty"`
	ModuleSHA256   string   `json:"module_sha256,omitempty"`
	ManifestSHA256 string   `json:"manifest_sha256,omitempty"`
	ModuleSize     int      `json:"module_size,omitempty"`
	Pinned         bool     `json:"pinned"`
	Status         Status   `json:"status"`
	StatusLabel    string   `json:"status_label"`
	Reason         string   `json:"reason,omitempty"`
	MemoryLimitMiB int      `json:"memory_limit_mib"`
	CallTimeoutMS  int      `json:"call_timeout_ms"`
}

func (e *Entry) set(s Status, reason string) {
	e.Status, e.StatusLabel, e.Reason = s, s.Label(), reason
}

func (e *Entry) fill(m Manifest) {
	e.Version, e.Description, e.OnError = m.Version, m.Description, m.OnError
	e.Hooks, e.Data, e.DataLabels = slices.Clone(m.Hooks), slices.Clone(m.Data), m.DataLabels()
}

// Store is the result of reading the plugin folder against the pins.
type Store struct {
	entries []Entry
	sources []source
}

type source struct {
	entry    int
	manifest Manifest
	module   []byte
}

// Entries returns a copy of the store rows: pinned plugins in pin order,
// then unpinned files by name.
func (s *Store) Entries() []Entry { return cloneEntries(s.entries) }

func cloneEntries(in []Entry) []Entry {
	out := slices.Clone(in)
	for i := range out {
		out[i].Hooks = slices.Clone(out[i].Hooks)
		out[i].Data = slices.Clone(out[i].Data)
		out[i].DataLabels = slices.Clone(out[i].DataLabels)
	}
	return out
}

// LoadStoreDir reads the plugin folder dir. A folder that does not exist
// is an empty folder (the feature is off).
func LoadStoreDir(dir string, pins PinSource) (*Store, error) {
	fi, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return LoadStore(nil, pins)
	}
	if err != nil {
		return nil, fmt.Errorf("plugin: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("plugin: %s is not a folder", dir)
	}
	return LoadStore(os.DirFS(dir), pins)
}

type dirFile struct{ wasm, json bool }

// LoadStore reads plugins from fsys (nil means an empty folder). Only
// pinned plugins whose module and manifest digests both match are kept
// for loading; the bytes that were hashed are the bytes that will run.
func LoadStore(fsys fs.FS, pins PinSource) (*Store, error) {
	var pl []Pin
	if pins != nil {
		pl = pins.PinnedPlugins()
	}
	if len(pl) > MaxPlugins {
		return nil, fmt.Errorf("plugin: more than %d pinned plugins", MaxPlugins)
	}
	for i, p := range pl {
		if !validName(p.Name) || !validDigest(p.ModuleSHA256) || !validDigest(p.ManifestSHA256) {
			return nil, fmt.Errorf("plugin: pin %d is malformed", i)
		}
		for _, q := range pl[:i] {
			if q.Name == p.Name {
				return nil, fmt.Errorf("plugin: plugin %q pinned twice", p.Name)
			}
		}
	}

	files := map[string]*dirFile{}
	if fsys != nil {
		des, err := fs.ReadDir(fsys, ".")
		if err != nil {
			return nil, fmt.Errorf("plugin: read folder: %w", err)
		}
		if len(des) > maxDirEntries {
			des = des[:maxDirEntries]
		}
		for _, de := range des {
			name := de.Name()
			base, isWasm := strings.CutSuffix(name, ".wasm")
			isJSON := false
			if !isWasm {
				base, isJSON = strings.CutSuffix(name, ".json")
			}
			if !isWasm && !isJSON || !de.Type().IsRegular() {
				continue
			}
			f := files[base]
			if f == nil {
				f = &dirFile{}
				files[base] = f
			}
			f.wasm = f.wasm || isWasm
			f.json = f.json || isJSON
		}
	}

	st := &Store{}
	pinned := map[string]bool{}
	for _, p := range pl {
		pinned[p.Name] = true
		e := Entry{Name: p.Name, Pinned: true, Hooks: []string{}, Data: []string{}, DataLabels: []string{NothingLabel},
			ModuleSHA256: p.ModuleSHA256, ManifestSHA256: p.ManifestSHA256}
		src, status, reason := verifyPinned(fsys, files[p.Name], p, &e)
		e.set(status, reason)
		st.entries = append(st.entries, e)
		if status == StatusVerified {
			src.entry = len(st.entries) - 1
			st.sources = append(st.sources, src)
		}
	}

	var extra []string
	for base := range files {
		if !pinned[base] {
			extra = append(extra, base)
		}
	}
	slices.Sort(extra)
	for _, base := range extra {
		if len(st.entries) >= MaxPlugins*2 {
			break
		}
		st.entries = append(st.entries, describeUnpinned(fsys, base, files[base]))
	}
	return st, nil
}

func verifyPinned(fsys fs.FS, f *dirFile, p Pin, e *Entry) (source, Status, string) {
	if fsys == nil || f == nil || !f.wasm || !f.json {
		return source{}, StatusMissing, "modül veya bildirge dosyası klasörde yok"
	}
	mb, err := readLimited(fsys, p.Name+".json", MaxManifestSize)
	if err != nil {
		return source{}, StatusInvalid, "bildirge okunamadı: " + err.Error()
	}
	if digest(mb) != p.ManifestSHA256 {
		return source{}, StatusDigestMismatch, "bildirge özeti imzalı belgedekiyle uyuşmuyor"
	}
	m, err := ParseManifest(mb)
	if err != nil {
		return source{}, StatusInvalid, err.Error()
	}
	e.fill(m)
	if m.Name != p.Name {
		return source{}, StatusInvalid, "bildirgedeki ad dosya adıyla uyuşmuyor"
	}
	wb, err := readLimited(fsys, p.Name+".wasm", MaxModuleSize)
	if err != nil {
		return source{}, StatusInvalid, "modül okunamadı: " + err.Error()
	}
	e.ModuleSize = len(wb)
	if digest(wb) != p.ModuleSHA256 {
		return source{}, StatusDigestMismatch, "modül özeti imzalı belgedekiyle uyuşmuyor"
	}
	return source{manifest: m, module: wb}, StatusVerified, ""
}

// describeUnpinned shows an unpinned plugin with its digests so the owner
// can pin it after checking it. Its manifest is untrusted display data.
func describeUnpinned(fsys fs.FS, base string, f *dirFile) Entry {
	e := Entry{Name: base, Hooks: []string{}, Data: []string{}, DataLabels: []string{NothingLabel}}
	e.set(StatusUnpinned, "")
	if !validName(base) {
		e.Name = truncate(strings.ToValidUTF8(base, "?"), maxNameLen)
		e.set(StatusInvalid, "dosya adı geçersiz")
		return e
	}
	if f.json {
		if mb, err := readLimited(fsys, base+".json", MaxManifestSize); err == nil {
			e.ManifestSHA256 = digest(mb)
			if m, err := ParseManifest(mb); err == nil && m.Name == base {
				e.fill(m)
			} else {
				e.Reason = "bildirge geçersiz"
			}
		}
	}
	if f.wasm {
		if wb, err := readLimited(fsys, base+".wasm", MaxModuleSize); err == nil {
			e.ModuleSHA256, e.ModuleSize = digest(wb), len(wb)
		}
	}
	return e
}

func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Digest returns the lowercase hex SHA-256 of b, the form used in pins.
func Digest(b []byte) string { return digest(b) }

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
