package rdesk

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"image"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Server side of protocol version 3 (ADR-0146).

// Annotation is a mark a viewer draws on this device's screen (#425). It
// carries no input: it is shown in a transparent, click-through layer and
// disappears at Expires (AnnotateClear removes the session's marks).
type Annotation struct {
	// Session is the session's id; marks of different sessions are kept
	// apart.
	Session uint64
	Peer    string
	Kind    AnnotationKind
	Color   [3]uint8
	// Points are virtual desktop pixels.
	Points  []image.Point
	Expires time.Time
}

// AnnotateFunc shows a mark. It runs on the session's read goroutine and
// must return quickly. A nil AnnotateFunc ignores annotations.
type AnnotateFunc func(Annotation)

// FileRoot is a folder the owner chose for browsing from a session (#435).
type FileRoot struct {
	// Name is the root's name in the viewer (first path segment).
	Name string
	// Path is the absolute folder.
	Path string
}

const (
	maxFileRoots    = 16
	echoMinInterval = 200 * time.Millisecond
	annotateRate    = 30 // marks per second
)

// validateFileRoots checks the owner's folders.
func validateFileRoots(roots []FileRoot) error {
	if len(roots) > maxFileRoots {
		return fmt.Errorf("rdesk: en fazla %d dosya kökü", maxFileRoots)
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if !validEntryName(r.Name) || strings.ContainsAny(r.Name, ":") {
			return fmt.Errorf("rdesk: geçersiz dosya kökü adı %q", r.Name)
		}
		key := strings.ToLower(r.Name)
		if seen[key] {
			return fmt.Errorf("rdesk: dosya kökü adı yinelendi: %q", r.Name)
		}
		seen[key] = true
		if !filepath.IsAbs(r.Path) {
			return fmt.Errorf("rdesk: dosya kökü mutlak yol olmalı: %q", r.Path)
		}
	}
	return nil
}

// FileRootsFromPaths names each folder after its last element, adding a
// number when names repeat.
func FileRootsFromPaths(paths []string) []FileRoot {
	out := make([]FileRoot, 0, len(paths))
	used := map[string]bool{}
	for _, p := range paths {
		base := filepath.Base(filepath.Clean(p))
		if !validEntryName(base) || strings.ContainsAny(base, ":") {
			base = "klasor"
		}
		name := base
		for i := 2; used[strings.ToLower(name)]; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		used[strings.ToLower(name)] = true
		out = append(out, FileRoot{Name: name, Path: p})
	}
	return out
}

type sessionV3 struct {
	mu         sync.Mutex
	lastEcho   time.Time
	tokens     float64
	tokenAt    time.Time
	annotated  bool
	fileBusy   bool
	fileID     uint32
	fileCancel context.CancelFunc
}

// handleV3 serves the version 3 messages; it runs on the read goroutine.
func (sess *session) handleV3(t msgType, p []byte) error {
	switch t {
	case msgEcho:
		v, err := decodeEcho(p)
		if err != nil {
			return err
		}
		now := time.Now()
		sess.v3.mu.Lock()
		drop := now.Sub(sess.v3.lastEcho) < echoMinInterval
		if !drop {
			sess.v3.lastEcho = now
		}
		sess.v3.mu.Unlock()
		if !drop {
			_, _ = sess.send(encodeEcho(msgEchoReply, v))
		}
		return nil
	case msgAnnotate:
		a, err := decodeAnnotation(p)
		if err != nil {
			return err
		}
		sess.touch()
		sess.annotate(a)
		return nil
	case msgFileList, msgFileGet:
		id, path, err := decodeFileReq(p)
		if err != nil {
			return err
		}
		sess.touch()
		sess.fileOp(t, id, path)
		return nil
	case msgFileCancel:
		id, err := decodeCancel(p)
		if err != nil {
			return err
		}
		sess.v3.mu.Lock()
		if sess.v3.fileBusy && sess.v3.fileID == id && sess.v3.fileCancel != nil {
			sess.v3.fileCancel()
		}
		sess.v3.mu.Unlock()
		return nil
	}
	return fmt.Errorf("%w: bilinmeyen ileti %#x", ErrProtocol, uint8(t))
}

// annotate maps a mark to the desktop and shows it, at most annotateRate
// marks per second (the rest are dropped).
func (sess *session) annotate(a annotationMsg) {
	fn := sess.srv.cfg.Annotate
	if fn == nil {
		return
	}
	now := time.Now()
	sess.v3.mu.Lock()
	if sess.v3.tokenAt.IsZero() {
		sess.v3.tokens = annotateRate
	} else {
		sess.v3.tokens = min(annotateRate, sess.v3.tokens+now.Sub(sess.v3.tokenAt).Seconds()*annotateRate)
	}
	sess.v3.tokenAt = now
	if sess.v3.tokens < 1 {
		sess.v3.mu.Unlock()
		return
	}
	sess.v3.tokens--
	sess.v3.annotated = true
	sess.v3.mu.Unlock()

	sess.mu.Lock()
	view, scale := sess.view, max(sess.scale, 1)
	sess.mu.Unlock()
	if view.Empty() {
		return
	}
	pts := make([]image.Point, len(a.points))
	for i, pt := range a.points {
		x, y := mapPoint(view, scale, pt.X, pt.Y)
		pts[i] = image.Pt(x, y)
	}
	fn(Annotation{Session: sess.id, Peer: sess.peer, Kind: a.kind, Color: AnnotationColors[a.color], Points: pts, Expires: now.Add(AnnotationTTL)})
}

// finishV3 removes the session's marks and stops a running file operation.
func (sess *session) finishV3() {
	sess.v3.mu.Lock()
	annotated := sess.v3.annotated
	sess.v3.annotated = false
	if sess.v3.fileCancel != nil {
		sess.v3.fileCancel()
	}
	sess.v3.mu.Unlock()
	if annotated && sess.srv.cfg.Annotate != nil {
		sess.srv.cfg.Annotate(Annotation{Session: sess.id, Peer: sess.peer, Kind: AnnotateClear, Expires: time.Now()})
	}
}

// filesAllowed: a control session, a files rule from the viewer (asked
// again for every request) and at least one folder chosen by the owner.
func (sess *session) filesAllowed() bool {
	cfg := &sess.srv.cfg
	if sess.mode != ModeControl || len(cfg.FileRoots) == 0 {
		return false
	}
	return sess.sessionHas(ChanFiles)
}

// fileOp starts one listing or fetch; only one runs at a time.
func (sess *session) fileOp(t msgType, id uint32, path string) {
	reply := func(status uint8, reason string) {
		if t == msgFileList {
			_, _ = sess.send(encodeListing(id, status, reason, nil, false))
		} else {
			_, _ = sess.send(encodeFileDone(id, status, reason, 0, [sha256.Size]byte{}))
		}
	}
	if !sess.filesAllowed() {
		reply(fileDenied, "")
		return
	}
	sess.v3.mu.Lock()
	if sess.v3.fileBusy {
		sess.v3.mu.Unlock()
		reply(fileBusy, "")
		return
	}
	ctx, cancel := context.WithCancel(sess.ctx)
	sess.v3.fileBusy, sess.v3.fileID, sess.v3.fileCancel = true, id, cancel
	sess.v3.mu.Unlock()
	// release frees the slot before the final reply is sent, so a viewer
	// that starts the next operation on receiving it is not told "busy".
	release := sync.OnceFunc(func() {
		sess.v3.mu.Lock()
		sess.v3.fileBusy, sess.v3.fileCancel = false, nil
		sess.v3.mu.Unlock()
	})
	sess.bg.Go(func() {
		defer func() {
			release()
			cancel()
		}()
		if t == msgFileList {
			st, reason, entries, trunc := sess.listFiles(path)
			release()
			_, _ = sess.send(encodeListing(id, st, reason, entries, trunc))
			return
		}
		sess.sendFile(ctx, id, path, release)
	})
}

func (sess *session) findRoot(name string) (FileRoot, bool) {
	for _, r := range sess.srv.cfg.FileRoots {
		if strings.EqualFold(r.Name, name) {
			return r, true
		}
	}
	return FileRoot{}, false
}

func fileErrStatus(err error) (uint8, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fileNotFound, ""
	case errors.Is(err, fs.ErrPermission):
		return fileDenied, "sistem erişim izni vermiyor"
	}
	return fileFailed, ""
}

// openInRoot opens rel inside the named root; os.Root refuses paths and
// symbolic links that leave it.
func (sess *session) openInRoot(rootName, rel string) (*os.Root, *os.File, error) {
	fr, ok := sess.findRoot(rootName)
	if !ok {
		return nil, nil, fs.ErrNotExist
	}
	r, err := os.OpenRoot(fr.Path)
	if err != nil {
		return nil, nil, err
	}
	f, err := r.Open(rel)
	if err != nil {
		_ = r.Close()
		if !errors.Is(err, fs.ErrPermission) {
			err = errors.Join(fs.ErrNotExist, err)
		}
		return nil, nil, err
	}
	return r, f, nil
}

func (sess *session) listFiles(path string) (uint8, string, []FileEntry, bool) {
	rootName, rel, ok := splitBrowsePath(path)
	if !ok {
		return fileNotFound, "geçersiz yol", nil, false
	}
	if rootName == "" {
		roots := sess.srv.cfg.FileRoots
		out := make([]FileEntry, 0, len(roots))
		for _, r := range roots {
			out = append(out, FileEntry{Name: r.Name, Dir: true})
		}
		return fileOK, "", out, false
	}
	r, f, err := sess.openInRoot(rootName, rel)
	if err != nil {
		st, reason := fileErrStatus(err)
		return st, reason, nil, false
	}
	defer r.Close()
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.IsDir() {
		return fileNotRegular, "klasör değil", nil, false
	}
	ents, err := f.ReadDir(maxListEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		st, reason := fileErrStatus(err)
		return st, reason, nil, false
	}
	trunc := len(ents) > maxListEntries
	if trunc {
		ents = ents[:maxListEntries]
	}
	out := make([]FileEntry, 0, len(ents))
	for _, e := range ents {
		if !validEntryName(e.Name()) {
			continue
		}
		var info fs.FileInfo
		if e.Type()&fs.ModeSymlink != 0 {
			// Followed only inside the root.
			info, err = r.Stat(filepath.ToSlash(filepath.Join(rel, e.Name())))
		} else {
			info, err = e.Info()
		}
		if err != nil {
			continue
		}
		fe := FileEntry{Name: e.Name(), Dir: info.IsDir(), ModTime: info.ModTime()}
		if info.Mode().IsRegular() {
			fe.Size = info.Size()
		}
		out = append(out, fe)
	}
	slices.SortFunc(out, func(a, b FileEntry) int {
		if a.Dir != b.Dir {
			if a.Dir {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.Name, b.Name))
	})
	return fileOK, "", out, trunc
}

// sendFile streams one regular file in chunks and ends with its size and
// SHA-256; the viewer checks both.
func (sess *session) sendFile(ctx context.Context, id uint32, path string, release func()) {
	done := func(status uint8, reason string) {
		release()
		_, _ = sess.send(encodeFileDone(id, status, reason, 0, [sha256.Size]byte{}))
	}
	rootName, rel, ok := splitBrowsePath(path)
	if !ok || rootName == "" || rel == "." {
		done(fileNotRegular, "")
		return
	}
	r, f, err := sess.openInRoot(rootName, rel)
	if err != nil {
		done(fileErrStatus(err))
		return
	}
	defer r.Close()
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		done(fileErrStatus(err))
		return
	}
	if !st.Mode().IsRegular() {
		done(fileNotRegular, "")
		return
	}
	if st.Size() > MaxFetchBytes {
		done(fileTooLarge, "")
		return
	}
	sess.srv.log.Info("uzak masaüstü oturumundan dosya çekiliyor", "peer", sess.peer, "root", rootName, "path", rel, "size", st.Size())
	h := sha256.New()
	buf := make([]byte, fileChunkLen)
	var off uint64
	for {
		if ctx.Err() != nil {
			done(fileCancelled, "")
			return
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			if off+uint64(n) > MaxFetchBytes {
				done(fileTooLarge, "")
				return
			}
			h.Write(buf[:n])
			if _, err := sess.send(encodeChunk(id, off, buf[:n])); err != nil {
				return
			}
			off += uint64(n)
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			done(fileFailed, "okuma hatası")
			return
		}
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	sess.sum.addFile(rootName+"/"+rel, int64(off), sum) // #667
	release()
	_, _ = sess.send(encodeFileDone(id, fileOK, "", off, sum))
}
