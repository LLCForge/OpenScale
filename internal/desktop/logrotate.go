package desktop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service log rotation with size and age limits (#43, F-196). The log
// rotates while the service runs, not only at start: once the file passes
// maxLogSize it becomes service.log.1, older files move up, at most
// logKeep files are kept and rotated files older than logMaxAge are
// deleted. Logs never carry keys and, at info level, no IP addresses
// (ADR-0008, #42), so this is about disk use and retention.
const (
	logKeep        = 5
	logMaxAge      = 14 * 24 * time.Hour
	logPruneEvery  = time.Hour
	rotatedLogPerm = 0o600
)

// rotatingLog is an io.WriteCloser over the service log.
type rotatingLog struct {
	mu        sync.Mutex
	path      string
	maxSize   int64
	keep      int
	maxAge    time.Duration
	now       func() time.Time
	f         *os.File
	size      int64
	lastPrune time.Time
}

func openRotatingLog(path string, maxSize int64, keep int, maxAge time.Duration, now func() time.Time) (*rotatingLog, error) {
	if maxSize <= 0 || keep < 1 {
		return nil, errors.New("invalid log limits")
	}
	l := &rotatingLog{path: path, maxSize: maxSize, keep: keep, maxAge: maxAge, now: now}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.open(); err != nil {
		return nil, err
	}
	if l.size > l.maxSize {
		if err := l.rotate(); err != nil {
			return nil, err
		}
	}
	l.prune()
	return l, nil
}

func (l *rotatingLog) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, rotatedLogPerm)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f, l.size = f, info.Size()
	return nil
}

// Write appends p, rotating first when p would pass the size limit.
func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(p)) > l.maxSize {
		// A failed rotation keeps logging into the reopened file rather
		// than losing lines.
		_ = l.rotate()
		if l.f == nil {
			return 0, os.ErrClosed
		}
	}
	if l.now().Sub(l.lastPrune) >= logPruneEvery {
		l.prune()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// Close closes the current file.
func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

func (l *rotatingLog) rotated(n int) string { return l.path + "." + strconv.Itoa(n) }

// rotate shifts service.log.N to .N+1 (dropping the last) and starts a new
// file. On Windows an open file cannot be renamed, so it is closed first.
func (l *rotatingLog) rotate() error {
	if err := l.f.Close(); err != nil {
		return err
	}
	l.f = nil
	_ = os.Remove(l.rotated(l.keep))
	for n := l.keep - 1; n >= 1; n-- {
		if err := os.Rename(l.rotated(n), l.rotated(n+1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errors.Join(err, l.open())
		}
	}
	if err := os.Rename(l.path, l.rotated(1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(err, l.open())
	}
	return l.open()
}

// prune deletes rotated files beyond keep or older than maxAge.
func (l *rotatingLog) prune() {
	l.lastPrune = l.now()
	matches, err := filepath.Glob(l.path + ".*")
	if err != nil {
		return
	}
	for _, m := range matches {
		n, err := strconv.Atoi(strings.TrimPrefix(m, l.path+"."))
		if err != nil {
			continue // not ours
		}
		info, err := os.Stat(m)
		if err != nil {
			continue
		}
		if n > l.keep || (l.maxAge > 0 && l.now().Sub(info.ModTime()) > l.maxAge) {
			_ = os.Remove(m)
		}
	}
}

// String is for diagnostics.
func (l *rotatingLog) String() string {
	return fmt.Sprintf("%s (en fazla %d dosya, %d MiB, %s)", l.path, l.keep+1, l.maxSize>>20, l.maxAge)
}
