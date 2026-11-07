package flightrec

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/securefile"
)

// A frozen ring is a Snapshot, gzip compressed and sealed with
// bundlecrypt. Stored snapshots are sealed to this computer's own
// recorder key (keyFile, readable only by the service's account), so a
// copy of the data directory alone does not disclose them; exporting one
// for a helper opens it and seals it again to the helper's public key.

const (
	// SnapshotSchema is the version of the Snapshot JSON.
	SnapshotSchema = 1
	// keyFile is the recorder key in the store directory.
	keyFile = "flightrec.key"
	// DefaultKeep is how many stored snapshots are kept.
	DefaultKeep = 5
	// maxKeyFile and maxSnapshotFile bound reads.
	maxKeyFile      = 4 << 10
	maxSnapshotFile = bundlecrypt.MaxPlaintext + 1<<10
	// maxPlainSnapshot bounds an opened snapshot.
	maxPlainSnapshot = 64 << 20
)

// Reasons of a freeze.
const (
	ReasonManual          = "manual"
	ReasonTunnelDown      = "tunnel_down"
	ReasonCoordinatorLost = "coordinator_lost"
)

var (
	reasonRe = regexp.MustCompile(`^[a-z][a-z_]{0,23}$`)
	idRe     = regexp.MustCompile(`^fr-(\d{8}-\d{6})(?:-(\d{1,3}))?-([a-z][a-z_]{0,23})$`)
)

// Errors.
var (
	ErrNotFound  = errors.New("kayıt bulunamadı")
	ErrBadID     = errors.New("geçersiz kayıt kimliği")
	ErrBadReason = errors.New("geçersiz dondurma nedeni")
	ErrEmpty     = errors.New("uçuş kaydedicide henüz kayıt yok")
)

// Snapshot is one frozen ring.
type Snapshot struct {
	Schema  int       `json:"schema"`
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	Reason  string    `json:"reason"`
	Version string    `json:"version,omitempty"`
	Stats   Stats     `json:"stats"`
	Entries []Entry   `json:"entries"`
}

// Info describes a stored snapshot without opening it.
type Info struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
	Size   int64     `json:"size"`
	seq    int
}

// ValidID reports whether id names a stored snapshot.
func ValidID(id string) bool { return len(id) <= 64 && idRe.MatchString(id) }

// Freeze copies the ring into a snapshot.
func (r *Recorder) Freeze(reason, version string) (Snapshot, error) {
	if !reasonRe.MatchString(reason) {
		return Snapshot{}, ErrBadReason
	}
	entries := r.Snapshot()
	if len(entries) == 0 {
		return Snapshot{}, ErrEmpty
	}
	at := r.now().UTC().Truncate(time.Second)
	return Snapshot{Schema: SnapshotSchema, ID: "fr-" + at.Format("20060102-150405") + "-" + reason, At: at, Reason: reason, Version: version,
		Stats: r.Stats(), Entries: entries}, nil
}

// Encode compresses the snapshot.
func (s Snapshot) Encode() ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > bundlecrypt.MaxPlaintext {
		return nil, bundlecrypt.ErrTooLarge
	}
	return buf.Bytes(), nil
}

// DecodeSnapshot reverses Encode.
func DecodeSnapshot(data []byte) (Snapshot, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Snapshot{}, fmt.Errorf("uçuş kaydı açılamadı: %w", err)
	}
	defer zr.Close()
	plain, err := io.ReadAll(io.LimitReader(zr, maxPlainSnapshot+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("uçuş kaydı açılamadı: %w", err)
	}
	if len(plain) > maxPlainSnapshot {
		return Snapshot{}, bundlecrypt.ErrTooLarge
	}
	var s Snapshot
	if err := json.Unmarshal(plain, &s); err != nil || s.Schema != SnapshotSchema {
		return Snapshot{}, errors.New("uçuş kaydı biçimi tanınmadı")
	}
	return s, nil
}

// Seal encodes and seals the snapshot to a recipient.
func (s Snapshot) Seal(random io.Reader, to *ecdh.PublicKey) ([]byte, error) {
	plain, err := s.Encode()
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return bundlecrypt.Seal(random, to, plain)
}

// Store keeps sealed snapshots in one directory.
type Store struct {
	dir    string
	keep   int
	random io.Reader
	key    *bundlecrypt.KeyPair
	mu     sync.Mutex
}

// OpenStore opens dir (created 0700), creating the recorder key on first
// use. keep <= 0 uses DefaultKeep.
func OpenStore(dir string, keep int, random io.Reader) (*Store, error) {
	if dir == "" {
		return nil, errors.New("uçuş kaydedici için klasör yok")
	}
	if keep <= 0 {
		keep = DefaultKeep
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("uçuş kaydedici klasörü oluşturulamadı: %w", err)
	}
	path := filepath.Join(dir, keyFile)
	data, err := securefile.ReadPrivate(path, maxKeyFile)
	var key *bundlecrypt.KeyPair
	switch {
	case err == nil:
		key, err = bundlecrypt.ParseKeyFile(data)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("uçuş kaydedici anahtarı bozuk: %w", err)
		}
	case errors.Is(err, fs.ErrNotExist):
		key, err = bundlecrypt.Generate(random)
		if err != nil {
			return nil, err
		}
		out, err := key.MarshalKeyFile()
		if err != nil {
			return nil, err
		}
		werr := securefile.WriteNew(path, out)
		clear(out)
		if werr != nil {
			return nil, fmt.Errorf("uçuş kaydedici anahtarı yazılamadı: %w", werr)
		}
	default:
		return nil, fmt.Errorf("uçuş kaydedici anahtarı okunamadı: %w", err)
	}
	return &Store{dir: dir, keep: keep, random: random, key: key}, nil
}

// Save seals s to the recorder key, writes it and removes the oldest
// snapshots beyond the limit.
func (st *Store) Save(s Snapshot) (Info, error) {
	if !ValidID(s.ID) {
		return Info{}, ErrBadID
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	id := s.ID
	for n := 2; ; n++ {
		if _, err := os.Lstat(filepath.Join(st.dir, id+".osb")); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if n > 99 {
			return Info{}, errors.New("aynı saniyede çok fazla dondurma")
		}
		id = fmt.Sprintf("fr-%s-%d-%s", s.At.Format("20060102-150405"), n, s.Reason)
	}
	s.ID = id
	sealed, err := s.Seal(st.random, st.key.Private.PublicKey())
	if err != nil {
		return Info{}, err
	}
	if err := securefile.WriteNew(filepath.Join(st.dir, id+".osb"), sealed); err != nil {
		return Info{}, fmt.Errorf("uçuş kaydı yazılamadı: %w", err)
	}
	st.pruneLocked()
	return Info{ID: id, At: s.At, Reason: s.Reason, Size: int64(len(sealed))}, nil
}

// List returns the stored snapshots, newest first.
func (st *Store) List() ([]Info, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.listLocked()
}

func (st *Store) listLocked() ([]Info, error) {
	ents, err := os.ReadDir(st.dir)
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, e := range ents {
		name := e.Name()
		id, ok := strings.CutSuffix(name, ".osb")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		m := idRe.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		at, err := time.Parse("20060102-150405", m[1])
		if err != nil {
			continue
		}
		var size int64
		if fi, err := e.Info(); err == nil {
			size = fi.Size()
		}
		seq := 0
		if m[2] != "" {
			seq, _ = strconv.Atoi(m[2])
		}
		out = append(out, Info{ID: id, At: at.UTC(), Reason: m[3], Size: size, seq: seq})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		if out[i].seq != out[j].seq {
			return out[i].seq > out[j].seq
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (st *Store) pruneLocked() {
	list, err := st.listLocked()
	if err != nil {
		return
	}
	for _, old := range list[min(st.keep, len(list)):] {
		_ = os.Remove(filepath.Join(st.dir, old.ID+".osb"))
	}
}

// Open reads and opens a stored snapshot.
func (st *Store) Open(id string) (Snapshot, error) {
	if !ValidID(id) {
		return Snapshot{}, ErrBadID
	}
	sealed, err := securefile.ReadLimited(filepath.Join(st.dir, id+".osb"), maxSnapshotFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}
	plain, err := bundlecrypt.Open(st.key, sealed)
	if err != nil {
		return Snapshot{}, err
	}
	defer clear(plain)
	return DecodeSnapshot(plain)
}

// Export opens a stored snapshot and seals it to a helper's key.
func (st *Store) Export(id string, to *ecdh.PublicKey) ([]byte, error) {
	s, err := st.Open(id)
	if err != nil {
		return nil, err
	}
	return s.Seal(st.random, to)
}

// Throttle thins out automatic freezes: at most one per interval.
type Throttle struct {
	Every time.Duration
	mu    sync.Mutex
	last  time.Time
}

// Allow reports whether a freeze may happen at now, and if so records it.
func (t *Throttle) Allow(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.last.IsZero() && now.Sub(t.last) < t.Every {
		return false
	}
	t.last = now
	return true
}
