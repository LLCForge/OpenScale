package service

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/logcrypt"
)

// Encrypted debug log (#44, ADR-0060, ADR-0110). Debug records carry
// tunnel and endpoint addresses (ADR-0008), so while the owner has turned
// the debug level on they never reach the plain service log: they are
// sealed with logcrypt under a key derived from this device's signing seed
// and written to logs/debug-*.oslog. "openscale key log-decrypt" reads
// them on this device. Without a device key (before joining a network)
// debug records are dropped rather than written in plain text.

const (
	debugLogPrefix   = "debug-"
	debugLogSuffix   = ".oslog"
	debugLogMaxBytes = 20 << 20
	debugLogKeep     = 3
)

// DebugSeedFunc returns the device signing seed; the caller wipes it.
type DebugSeedFunc func() ([]byte, error)

// DeviceSigningSeed reads the seed of this computer's device key.
func DeviceSigningSeed(dataDir string) ([]byte, error) {
	s, err := readSecrets(filepath.Join(dataDir, DeviceDir, deviceKeyFile))
	if err != nil {
		return nil, err
	}
	seed := append([]byte(nil), s.SigningSeed...)
	wipe(s.SigningSeed)
	wipe(s.WireGuardPrivate)
	return seed, nil
}

// debugSink writes sealed records to a rotating set of files.
type debugSink struct {
	dir  string
	seed DebugSeedFunc
	now  func() time.Time

	mu      sync.Mutex
	f       *os.File
	w       *logcrypt.Writer
	size    int64
	lastErr error
}

func (s *debugSink) open() error {
	seed, err := s.seed()
	if err != nil {
		return err
	}
	defer wipe(seed)
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	name := debugLogPrefix + s.now().UTC().Format("20060102T150405.000000000") + debugLogSuffix
	f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	w, err := logcrypt.NewWriter(f, seed, rand.Reader)
	if err != nil {
		_ = f.Close()
		return err
	}
	s.f, s.w, s.size = f, w, 0
	s.prune()
	return nil
}

// prune keeps the newest debugLogKeep files.
func (s *debugSink) prune() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, debugLogPrefix) && strings.HasSuffix(n, debugLogSuffix) && e.Type().IsRegular() {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for len(names) > debugLogKeep {
		_ = os.Remove(filepath.Join(s.dir, names[0]))
		names = names[1:]
	}
}

func (s *debugSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil || s.size >= debugLogMaxBytes {
		if s.f != nil {
			_ = s.f.Close()
			s.f, s.w = nil, nil
		}
		if err := s.open(); err != nil {
			// Fail closed: the record is dropped, never written in plain.
			s.lastErr = err
			return len(p), nil
		}
	}
	n, err := s.w.Write(p)
	s.size += int64(n)
	return n, err
}

func (s *debugSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f, s.w = nil, nil
	return err
}

// debugCryptHandler sends debug records to the sealed sink and the rest to
// next.
type debugCryptHandler struct {
	next  slog.Handler
	debug slog.Handler
}

// NewDebugCryptHandler wraps next (the plain service log handler, whose
// level decides what is logged at all). dir is the log folder. The returned
// closer closes the current sealed file.
func NewDebugCryptHandler(next slog.Handler, dir string, seed DebugSeedFunc, level slog.Leveler) (slog.Handler, io.Closer) {
	sink := &debugSink{dir: dir, seed: seed, now: time.Now}
	return &debugCryptHandler{next: next, debug: slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: level})}, sink
}

func (h *debugCryptHandler) Enabled(ctx context.Context, l slog.Level) bool {
	if l < slog.LevelInfo {
		return h.debug.Enabled(ctx, l)
	}
	return h.next.Enabled(ctx, l)
}

func (h *debugCryptHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < slog.LevelInfo {
		return h.debug.Handle(ctx, r)
	}
	return h.next.Handle(ctx, r)
}

func (h *debugCryptHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &debugCryptHandler{next: h.next.WithAttrs(as), debug: h.debug.WithAttrs(as)}
}

func (h *debugCryptHandler) WithGroup(name string) slog.Handler {
	return &debugCryptHandler{next: h.next.WithGroup(name), debug: h.debug.WithGroup(name)}
}
