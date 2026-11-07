package coordinator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/release"
)

// Release mirror (ADR-0225). The owner puts a signed release into
// <state>/release-mirror ("openscale update publish"); the coordinator
// announces its version and serves its files inside the tunnel in
// control-sized chunks. The coordinator is untrusted: it neither verifies
// nor vouches for anything. It only bounds what it reads: an allowlist of
// file names, regular files only (os.Root: no path outside the folder, no
// symbolic link out of it), a size limit per file and a file count limit.
// Devices verify the signed manifest and every byte against it.

// ReleaseMirrorDir is the mirror folder inside the coordinator's state
// directory.
const ReleaseMirrorDir = "release-mirror"

// ReleaseSourceStatusFile, next to the mirror, is written by "openscale
// update source sync" (internal/autoupdate): the owner's upstream source and
// when it was last checked. The coordinator only passes both on.
const ReleaseSourceStatusFile = "release-source-status.json"

// SourceStatus is the content of ReleaseSourceStatusFile.
type SourceStatus struct {
	Schema    int       `json:"schema"`
	Source    string    `json:"source"`
	LastCheck time.Time `json:"lastCheck"`
	Version   string    `json:"version,omitempty"`
	Error     string    `json:"error,omitempty"`
}

const (
	maxMirrorFiles    = 16
	maxMirrorArtifact = 256 << 20
)

var (
	mirrorManifestRe = regexp.MustCompile(`^openscale-([0-9A-Za-z.+-]{1,48})\.release\.json$`)
	mirrorDebRe      = regexp.MustCompile(`^openscale_[0-9A-Za-z.+~]{1,48}_(amd64|arm64|armhf)\.deb$`)
	// mirrorPrograms are the compressed programs "update publish" writes.
	mirrorPrograms = []string{
		"openscale-windows-amd64.exe.gz", "openscale-linux-amd64.gz", "openscale-linux-arm64.gz", "openscale-linux-armv7.gz",
	}
)

// MirrorFileAllowed reports whether a mirror may serve name, and its size
// limit.
func MirrorFileAllowed(name string) (int64, bool) {
	switch {
	case !control.ValidReleaseFileName(name):
		return 0, false
	case mirrorManifestRe.MatchString(name):
		return release.MaxSignedReleaseSize, true
	case name == "revocations.json":
		return release.MaxRevocationsSize, true
	case slices.Contains(mirrorPrograms, name), mirrorDebRe.MatchString(name):
		return maxMirrorArtifact, true
	}
	return 0, false
}

type mirrorEntry struct {
	size  int64
	mtime time.Time
}

// mirrorSnapshot is one loaded publication.
type mirrorSnapshot struct {
	version, manifestName, digest string
	manifest                      []byte
	files                         map[string]mirrorEntry
	stamp                         string
}

type releaseMirror struct {
	dir    string
	logger *slog.Logger

	mu  sync.Mutex
	cur *mirrorSnapshot
	// source and checked come from ReleaseSourceStatusFile.
	source  string
	checked time.Time
	// lastErr is logged once per change.
	lastErr string
}

func newReleaseMirror(dir string, logger *slog.Logger) *releaseMirror {
	m := &releaseMirror{dir: dir, logger: logger}
	if dir != "" {
		m.reload()
	}
	return m
}

func (m *releaseMirror) snapshot() *mirrorSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// reload reads the folder again when its listing changed.
func (m *releaseMirror) reload() {
	if m == nil || m.dir == "" {
		return
	}
	snap, err := m.load()
	src := readSourceStatus(filepath.Join(filepath.Dir(m.dir), ReleaseSourceStatusFile))
	m.mu.Lock()
	defer m.mu.Unlock()
	m.source, m.checked = src.Source, src.LastCheck
	if err != nil {
		if msg := err.Error(); msg != m.lastErr {
			m.lastErr = msg
			if !errors.Is(err, fs.ErrNotExist) {
				m.logger.Warn("release mirror not served", "error", msg)
			}
		}
		m.cur = nil
		return
	}
	m.lastErr = ""
	if m.cur != nil && snap != nil && m.cur.stamp == snap.stamp {
		return
	}
	if snap != nil && (m.cur == nil || m.cur.digest != snap.digest) {
		m.logger.Info("release mirror loaded", "release", snap.version, "files", len(snap.files))
	}
	m.cur = snap
}

// openRoot opens the folder for one operation. It is not kept open: an
// open directory handle would keep the owner from removing or replacing the
// folder on Windows.
func (m *releaseMirror) openRoot() (*os.Root, error) { return os.OpenRoot(m.dir) }

func (m *releaseMirror) load() (*mirrorSnapshot, error) {
	root, err := m.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	snap := &mirrorSnapshot{files: map[string]mirrorEntry{}}
	var stamp strings.Builder
	for _, e := range entries {
		limit, ok := MirrorFileAllowed(e.Name())
		if !ok {
			continue // temporary files of a publication, anything else
		}
		info, err := root.Lstat(e.Name())
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
			return nil, errors.New("mirror file " + e.Name() + " is not a regular file within its size limit")
		}
		if len(snap.files) >= maxMirrorFiles {
			return nil, errors.New("too many mirror files")
		}
		snap.files[e.Name()] = mirrorEntry{size: info.Size(), mtime: info.ModTime()}
		stamp.WriteString(e.Name() + "\x00" + strconv.FormatInt(info.Size(), 10) + "\x00" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + "\n")
		if sub := mirrorManifestRe.FindStringSubmatch(e.Name()); sub != nil {
			if snap.manifestName != "" {
				return nil, errors.New("more than one release manifest in the mirror")
			}
			if _, err := release.ParseVersion(sub[1]); err != nil {
				return nil, errors.New("release manifest name has no valid version")
			}
			snap.manifestName, snap.version = e.Name(), sub[1]
		}
	}
	if snap.manifestName == "" {
		return nil, nil // nothing published (a publication in progress removes it first)
	}
	data, err := readRootFile(root, snap.manifestName, release.MaxSignedReleaseSize)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != snap.files[snap.manifestName].size {
		return nil, errors.New("release manifest changed while loading")
	}
	sum := sha256.Sum256(data)
	snap.manifest, snap.digest, snap.stamp = data, hex.EncodeToString(sum[:]), stamp.String()
	return snap, nil
}

// readSourceStatus reads the sync's report; anything unusable is no source.
func readSourceStatus(path string) SourceStatus {
	var st SourceStatus
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &st) != nil || len(st.Source) > control.MaxReleaseSource {
		return SourceStatus{}
	}
	for _, r := range st.Source {
		if r < '!' || r > '~' {
			return SourceStatus{}
		}
	}
	return st
}

func readRootFile(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file too large")
	}
	return data, nil
}

// read returns up to n bytes of name at off, refusing a file that is no
// longer the one listed in snap.
func (m *releaseMirror) read(snap *mirrorSnapshot, name string, off int64, n int) ([]byte, error) {
	if name == snap.manifestName {
		end := min(off+int64(n), int64(len(snap.manifest)))
		return snap.manifest[off:end], nil
	}
	root, err := m.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	want := snap.files[name]
	if err != nil || !info.Mode().IsRegular() || info.Size() != want.size || !info.ModTime().Equal(want.mtime) {
		return nil, errors.New("changed")
	}
	buf := make([]byte, min(int64(n), want.size-off))
	k, err := f.ReadAt(buf, off)
	if err != nil && !(errors.Is(err, io.EOF) && k == len(buf)) {
		return nil, err
	}
	return buf[:k], nil
}

// releaseAnnounce answers TypeRelease.
func (s *Server) releaseAnnounce() control.Message {
	snap := s.rel.snapshot()
	s.rel.mu.Lock()
	resp := control.Message{T: control.TypeRelease, Source: s.rel.source}
	if !s.rel.checked.IsZero() && s.rel.checked.Unix() > 0 {
		resp.Checked = s.rel.checked.Unix()
	}
	s.rel.mu.Unlock()
	if snap != nil {
		resp.Release, resp.File, resp.Digest, resp.Size = snap.version, snap.manifestName, snap.digest, len(snap.manifest)
	}
	return resp
}

// releaseChunk answers TypeReleaseFile.
func (s *Server) releaseChunk(req control.Message) control.Message {
	snap := s.rel.snapshot()
	switch {
	case snap == nil:
		return control.Message{T: control.TypeError, Error: "no release"}
	case req.Digest != snap.digest:
		return control.Message{T: control.TypeError, Error: "release changed"}
	}
	entry, ok := snap.files[req.File]
	if !ok {
		return control.Message{T: control.TypeError, Error: "not found"}
	}
	if int64(req.Offset) > entry.size {
		return control.Message{T: control.TypeError, Error: "offset out of range"}
	}
	data, err := s.rel.read(snap, req.File, int64(req.Offset), control.ChunkSize)
	if err != nil {
		// A publication in progress; the next reload picks up the new one.
		return control.Message{T: control.TypeError, Error: "release changed"}
	}
	return control.Message{T: control.TypeReleaseFile, File: req.File, Digest: snap.digest, Offset: req.Offset, Total: int(entry.size), Data: data}
}

// ReleaseMirrorHandler answers TypeRelease and TypeReleaseFile requests
// from dir exactly as a running coordinator does, without WireGuard (tests
// of the device side). reload reads the folder again.
func ReleaseMirrorHandler(dir string, logger *slog.Logger) (handle func(control.Message) control.Message, reload func()) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	s := &Server{rel: newReleaseMirror(dir, logger)}
	return func(req control.Message) control.Message {
		switch req.T {
		case control.TypeRelease:
			return s.releaseAnnounce()
		case control.TypeReleaseFile:
			return s.releaseChunk(req)
		}
		return control.Message{T: control.TypeError, Error: "unknown message type"}
	}, s.rel.reload
}
