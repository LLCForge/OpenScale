package posture

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Tamper log (#606, ADR-0207). The device records SHA-256 digests of the
// OpenScale program, its service definition and the network directory's
// files. When a digest changes outside OpenScale's own update or edit (a
// legitimate change calls Accept first), the device writes a signed event
// to an append-only, hash chained local log and hands it to the sink that
// sends it to the owner's devices. Peers verify the signature against the
// device's signing key from the signed document.
//
// A tamper event is the device's own statement: malware that controls the
// device can also stop the watcher. Its value is in catching changes made
// while OpenScale runs, and in an untampered record of when they were
// seen.

// Tamper event kinds.
const (
	TamperChanged = "changed"
	TamperRemoved = "removed"
	TamperAdded   = "added"
)

// TamperEvent is one signed observation.
type TamperEvent struct {
	Device string    `json:"device"`
	Seq    uint64    `json:"seq"`
	At     time.Time `json:"at"`
	Path   string    `json:"path"`
	Kind   string    `json:"kind"`
	Old    string    `json:"old,omitempty"`
	New    string    `json:"new,omitempty"`
	// Prev is the SHA-256 of the previous log line (hash chain).
	Prev string `json:"prev"`
	Sig  []byte `json:"sig,omitempty"`
}

func (e TamperEvent) signedBytes() []byte {
	e.Sig = nil
	b, _ := json.Marshal(e)
	return append([]byte("openscale/tamper/v1\x00"), b...)
}

// Verify checks the event's signature with the device's signing key.
func (e TamperEvent) Verify(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && len(e.Sig) == ed25519.SignatureSize &&
		ed25519.Verify(pub, e.signedBytes(), e.Sig)
}

// Validate checks an event received from another device.
func (e TamperEvent) Validate() error {
	switch {
	case e.Device == "" || len(e.Device) > 64:
		return errors.New("tamper event: device")
	case e.Path == "" || len(e.Path) > 512:
		return errors.New("tamper event: path")
	case e.Kind != TamperChanged && e.Kind != TamperRemoved && e.Kind != TamperAdded:
		return errors.New("tamper event: kind")
	case (e.Old != "" && !validDigest(e.Old)) || (e.New != "" && !validDigest(e.New)) || (e.Prev != "" && !validDigest(e.Prev)):
		return errors.New("tamper event: digest")
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// TamperSink delivers events to other devices (the node's control
// channel). It must not block for long.
type TamperSink interface {
	PublishTamper(TamperEvent) error
}

// TamperConfig configures a watcher.
type TamperConfig struct {
	// Device is this device's name in the document.
	Device string
	// Paths are files or directories to watch (directories one level
	// deep; at most MaxTamperFiles files in all).
	Paths []string
	// StateDir holds the baseline and the log (owner-only).
	StateDir string
	// Key signs events (the device signing key). Required.
	Key ed25519.PrivateKey
	// Sink, if set, receives every new event.
	Sink TamperSink
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// MaxTamperFiles bounds the watched files.
const MaxTamperFiles = 2000

const maxTamperHash = 1 << 30

// TamperWatcher compares digests with the baseline.
type TamperWatcher struct {
	cfg  TamperConfig
	mu   sync.Mutex
	base map[string]string
	seq  uint64
	prev string
}

type tamperState struct {
	Files map[string]string `json:"files"`
	Seq   uint64            `json:"seq"`
	Prev  string            `json:"prev"`
}

const (
	tamperStateFile = "tamper-baseline.json"
	tamperLogFile   = "tamper.log"
)

// OpenTamperWatcher loads the baseline, creating it on first use.
func OpenTamperWatcher(cfg TamperConfig) (*TamperWatcher, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize || cfg.Device == "" || cfg.StateDir == "" {
		return nil, errors.New("tamper watcher: key, device and state directory required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	w := &TamperWatcher{cfg: cfg}
	b, err := os.ReadFile(filepath.Join(cfg.StateDir, tamperStateFile))
	switch {
	case err == nil:
		var st tamperState
		if err := json.Unmarshal(b, &st); err != nil || st.Files == nil {
			return nil, errors.New("kurcalama taban çizgisi bozuk")
		}
		w.base, w.seq, w.prev = st.Files, st.Seq, st.Prev
	case errors.Is(err, fs.ErrNotExist):
		cur, err := w.snapshot()
		if err != nil {
			return nil, err
		}
		w.base = cur
		if err := w.save(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return w, nil
}

func (w *TamperWatcher) files() ([]string, error) {
	var out []string
	for _, p := range w.cfg.Paths {
		st, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				out = append(out, filepath.Clean(p))
				continue
			}
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, filepath.Clean(p))
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type().IsRegular() && e.Name() != tamperStateFile && e.Name() != tamperLogFile {
				out = append(out, filepath.Join(p, e.Name()))
			}
		}
	}
	if len(out) > MaxTamperFiles {
		return nil, fmt.Errorf("izlenecek dosya sayısı %d sınırını aşıyor", MaxTamperFiles)
	}
	sort.Strings(out)
	return out, nil
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxTamperHash)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (w *TamperWatcher) snapshot() (map[string]string, error) {
	files, err := w.files()
	if err != nil {
		return nil, err
	}
	cur := make(map[string]string, len(files))
	for _, f := range files {
		d, err := hashFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		cur[f] = d
	}
	return cur, nil
}

func (w *TamperWatcher) save() error {
	b, err := json.Marshal(tamperState{Files: w.base, Seq: w.seq, Prev: w.prev})
	if err != nil {
		return err
	}
	tmp := filepath.Join(w.cfg.StateDir, tamperStateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(w.cfg.StateDir, tamperStateFile))
}

// Accept records the current digest of path as legitimate (after an
// update or an edit made by OpenScale itself).
func (w *TamperWatcher) Accept(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	path = filepath.Clean(path)
	d, err := hashFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		delete(w.base, path)
		return w.save()
	}
	if err != nil {
		return err
	}
	w.base[path] = d
	return w.save()
}

// Check compares the files with the baseline, logs and publishes an
// event per difference and makes the new state the baseline.
func (w *TamperWatcher) Check() ([]TamperEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cur, err := w.snapshot()
	if err != nil {
		return nil, err
	}
	var events []TamperEvent
	add := func(path, kind, old, nw string) {
		events = append(events, TamperEvent{Device: w.cfg.Device, Path: path, Kind: kind, Old: old, New: nw})
	}
	paths := make([]string, 0, len(cur)+len(w.base))
	for p := range w.base {
		paths = append(paths, p)
	}
	for p := range cur {
		if _, ok := w.base[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		old, hadOld := w.base[p]
		nw, hasNew := cur[p]
		switch {
		case hadOld && !hasNew:
			add(p, TamperRemoved, old, "")
		case !hadOld && hasNew:
			add(p, TamperAdded, "", nw)
		case old != nw:
			add(p, TamperChanged, old, nw)
		}
	}
	if len(events) == 0 {
		return nil, nil
	}
	f, err := os.OpenFile(filepath.Join(w.cfg.StateDir, tamperLogFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	now := w.cfg.Now().UTC()
	for i := range events {
		w.seq++
		events[i].Seq, events[i].At, events[i].Prev = w.seq, now, w.prev
		events[i].Sig = ed25519.Sign(w.cfg.Key, events[i].signedBytes())
		line, err := json.Marshal(events[i])
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(line)
		w.prev = hex.EncodeToString(sum[:])
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	w.base = cur
	if err := w.save(); err != nil {
		return nil, err
	}
	if w.cfg.Sink != nil {
		for _, e := range events {
			_ = w.cfg.Sink.PublishTamper(e)
		}
	}
	return events, nil
}

// VerifyTamperLog reads a log and checks every signature and the hash
// chain. It returns the events and the first problem found.
func VerifyTamperLog(r io.Reader, pub ed25519.PublicKey) ([]TamperEvent, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	var out []TamperEvent
	prev := ""
	var seq uint64
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e TamperEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return out, fmt.Errorf("satır %d okunamadı", len(out)+1)
		}
		if err := e.Validate(); err != nil {
			return out, err
		}
		if !e.Verify(pub) {
			return out, fmt.Errorf("olay %d imzası geçersiz", e.Seq)
		}
		if e.Prev != prev || e.Seq != seq+1 {
			return out, fmt.Errorf("olay %d zinciri kopuk (silinmiş veya değiştirilmiş kayıt)", e.Seq)
		}
		sum := sha256.Sum256(line)
		prev, seq = hex.EncodeToString(sum[:]), e.Seq
		out = append(out, e)
	}
	return out, sc.Err()
}
