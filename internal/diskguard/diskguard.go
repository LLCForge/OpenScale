// Package diskguard keeps OpenScale working when the disk fills up (#205,
// ADR-0095).
//
// Two rules: logs and other history yield first, and the signed network
// document can always be written. Logs go through a Writer that stops
// writing (and counts what it dropped) while free space is below a low
// water mark. Every data directory holds a small reserve file; when a
// critical write fails because the disk is full, WriteCritical deletes the
// reserve and tries once more, so the document write gets that space.
package diskguard

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// ReserveFile is the reserve kept in a data directory.
	ReserveFile = ".openscale-reserve"
	// DefaultReserve is the reserve size: several network documents
	// (trust.MaxEnvelopeSize is 1 MiB) and their state files.
	DefaultReserve = 4 << 20
	// DefaultLowWater: below this much free space logs stop.
	DefaultLowWater = 64 << 20
	// checkEvery bounds how often a Writer asks the OS for free space.
	checkEvery = 15 * time.Second
)

// ErrUnsupported is returned by Free where the OS query is not implemented;
// callers then behave as if there were enough space.
var ErrUnsupported = errors.New("free disk space query is not supported on this system")

// Free returns the bytes available to this process on the file system that
// holds dir.
func Free(dir string) (uint64, error) { return freeBytes(dir) }

// IsDiskFull reports whether err means the disk (or the quota) is full.
func IsDiskFull(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOSPC) {
		return true
	}
	return isDiskFullOS(err)
}

// EnsureReserve creates dir's reserve file of size bytes unless it already
// exists. It does nothing (and returns nil) when the disk is already low:
// taking the last free space for a reserve would only move the problem.
func EnsureReserve(dir string, size int64) error {
	if size <= 0 {
		size = DefaultReserve
	}
	path := filepath.Join(dir, ReserveFile)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().IsRegular() && info.Size() >= size {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", ReserveFile)
		}
	}
	if free, err := Free(dir); err == nil && free < uint64(size)*4+DefaultLowWater {
		return nil
	}
	f, err := os.CreateTemp(dir, ".openscale-reserve-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Real zero blocks, not a sparse file: the space must be allocated now.
	buf := make([]byte, 64<<10)
	var werr error
	for left := size; left > 0 && werr == nil; {
		n := int64(len(buf))
		if left < n {
			n = left
		}
		_, werr = f.Write(buf[:n])
		left -= n
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	return nil
}

// ReleaseReserve deletes dir's reserve file. It reports whether one was
// removed.
func ReleaseReserve(dir string) (bool, error) {
	err := os.Remove(filepath.Join(dir, ReserveFile))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}

// WriteCritical runs write; when it fails because the disk is full, it
// frees dir's reserve and runs write once more. The reserve is recreated
// later by EnsureReserve, once there is space again.
func WriteCritical(dir string, write func() error) error {
	err := write()
	if !IsDiskFull(err) {
		return err
	}
	if released, rerr := ReleaseReserve(dir); rerr != nil || !released {
		return err
	}
	return write()
}

// Writer passes writes through while dir has at least lowWater bytes
// free and drops them otherwise. Dropped writes report success so a logger
// never fails or blocks on a full disk.
type Writer struct {
	w        io.Writer
	dir      string
	lowWater uint64
	now      func() time.Time
	free     func(string) (uint64, error)

	mu      sync.Mutex
	checked time.Time
	allow   bool
	dropped atomic.Uint64
}

// NewWriter wraps w; lowWater <= 0 uses DefaultLowWater.
func NewWriter(w io.Writer, dir string, lowWater int64) *Writer {
	if lowWater <= 0 {
		lowWater = DefaultLowWater
	}
	return &Writer{w: w, dir: dir, lowWater: uint64(lowWater), now: time.Now, free: Free, allow: true}
}

func (g *Writer) allowed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if !g.checked.IsZero() && now.Sub(g.checked) < checkEvery {
		return g.allow
	}
	g.checked = now
	free, err := g.free(g.dir)
	// An unknown amount of free space never stops the log.
	g.allow = err != nil || free >= g.lowWater
	return g.allow
}

// Write implements io.Writer.
func (g *Writer) Write(p []byte) (int, error) {
	if !g.allowed() {
		g.dropped.Add(1)
		return len(p), nil
	}
	n, err := g.w.Write(p)
	if IsDiskFull(err) {
		// Stop until the next check rather than failing every line.
		g.mu.Lock()
		g.allow, g.checked = false, g.now()
		g.mu.Unlock()
		g.dropped.Add(1)
		return len(p), nil
	}
	return n, err
}

// Close closes the wrapped writer when it is an io.Closer.
func (g *Writer) Close() error {
	if c, ok := g.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Dropped returns how many writes were dropped for lack of space.
func (g *Writer) Dropped() uint64 { return g.dropped.Load() }
