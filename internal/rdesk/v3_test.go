package rdesk

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"image"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A version 3 client falls back to version 2 when an older server refuses
// the hello, without a second consent (the refusal comes first).
func TestV3FallbackToV2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var versions []uint8
	go func() {
		for range 3 {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, p, err := readMsg(bufio.NewReader(c), maxHelloBytes)
			if err == nil && len(p) > len(helloMagic) {
				v := p[len(helloMagic)]
				mu.Lock()
				versions = append(versions, v)
				mu.Unlock()
				if v >= ProtocolVersionExt {
					// What an older server answers to an unknown version.
					_, _ = c.Write(encodeWelcome(statusBadRequest, "desteklenen protokol sürümü 2"))
				} else {
					_, _ = c.Write(encodeWelcome(statusDenied, ""))
				}
			}
			_ = c.Close()
		}
	}()
	_, err = Dial(testCtx(t), ln.Addr().(*net.TCPAddr).AddrPort(), DialOptions{})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v, want the version 2 answer", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(versions, []uint8{ProtocolVersionLogin, ProtocolVersionExt, ProtocolVersionE2E}) {
		t.Fatalf("hello versions %v", versions)
	}
}

func TestV3StatsEcho(t *testing.T) {
	h := newHarness(t, nil)
	c, err := Dial(testCtx(t), h.addr, DialOptions{Monitor: 0, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.Extended() {
		t.Fatal("server should speak version 3")
	}
	if _, err := c.NextFrame(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "echo round trip", func() bool { return c.Stats().RTT > 0 })
	st := c.Stats()
	if st.Version < ProtocolVersionExt || st.Frames == 0 || st.Bytes == 0 || st.Width == 0 || st.Scale != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestV3Annotations(t *testing.T) {
	var mu sync.Mutex
	var got []Annotation
	h := newHarness(t, func(c *Config) {
		c.Annotate = func(a Annotation) {
			mu.Lock()
			got = append(got, a)
			mu.Unlock()
		}
	})
	c, err := Dial(testCtx(t), h.addr, DialOptions{Mode: ModeView, Monitor: 0, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NextFrame(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if err := c.Annotate(AnnotatePointer, 0, []image.Point{{10, 20}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Annotate(AnnotateStroke, 4, []image.Point{{1, 1}, {5, 5}, {9, 2}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Annotate(AnnotateStroke, 4, []image.Point{{1, 1}}); err == nil {
		t.Fatal("one point stroke accepted")
	}
	if err := c.Annotate(AnnotatePointer, 9, []image.Point{{1, 1}}); err == nil {
		t.Fatal("bad color accepted")
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	waitFor(t, "annotations", func() bool { return count() == 2 })
	mu.Lock()
	a := got[0]
	mu.Unlock()
	if a.Kind != AnnotatePointer || a.Peer != "laptop" || len(a.Points) != 1 || a.Color != AnnotationColors[0] || !a.Expires.After(time.Now()) {
		t.Fatalf("annotation %+v", a)
	}
	// Rate limit: a burst is cut at annotateRate.
	for range 200 {
		_ = c.Annotate(AnnotatePointer, 1, []image.Point{{3, 3}})
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "clear on end", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) > 0 && got[len(got)-1].Kind == AnnotateClear
	})
	if n := count(); n > 2+annotateRate+5 {
		t.Fatalf("rate limit let %d marks through", n)
	}
	if h.inj.opened.Load() != 0 {
		t.Fatal("view session opened input injection")
	}
}

func TestAnnotationSet(t *testing.T) {
	var s AnnotationSet
	now := time.Now()
	s.Apply(Annotation{Session: 1, Kind: AnnotatePointer, Points: []image.Point{{1, 1}}, Expires: now.Add(time.Second)})
	s.Apply(Annotation{Session: 2, Kind: AnnotatePointer, Points: []image.Point{{2, 2}}, Expires: now.Add(time.Second)})
	s.Apply(Annotation{Session: 1, Kind: AnnotatePointer, Expires: now.Add(-time.Second)})
	if n := len(s.Active(now)); n != 2 {
		t.Fatalf("active %d", n)
	}
	s.Apply(Annotation{Session: 1, Kind: AnnotateClear})
	if a := s.Active(now); len(a) != 1 || a[0].Session != 2 {
		t.Fatalf("after clear %+v", a)
	}
	if len(s.Active(now.Add(2*time.Second))) != 0 {
		t.Fatal("expired marks kept")
	}
	for range maxLiveAnnotations + 10 {
		s.Apply(Annotation{Session: 3, Kind: AnnotatePointer, Expires: now.Add(time.Hour)})
	}
	if len(s.Active(now)) != maxLiveAnnotations {
		t.Fatal("set not bounded")
	}
}

func fileHarness(t *testing.T, files bool) (*harness, string) {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("merhaba"), 0o600))
	must(os.MkdirAll(filepath.Join(dir, "alt", "derin"), 0o700))
	must(os.WriteFile(filepath.Join(dir, "alt", "b.bin"), bytes.Repeat([]byte{7}, 3*fileChunkLen+11), 0o600))
	outside := t.TempDir()
	must(os.WriteFile(filepath.Join(outside, "gizli.txt"), []byte("sır"), 0o600))
	// A link out of the root; skipped where links need privileges.
	_ = os.Symlink(filepath.Join(outside, "gizli.txt"), filepath.Join(dir, "kacis.txt"))
	h := newHarness(t, func(c *Config) { c.FileRoots = []FileRoot{{Name: "belgeler", Path: dir}} })
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop", Files: files})
	return h, dir
}

func TestV3FileBrowse(t *testing.T) {
	h, _ := fileHarness(t, true)
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Monitor: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roots, _, err := c.ListFiles(ctx, "")
	if err != nil || len(roots) != 1 || roots[0].Name != "belgeler" || !roots[0].Dir {
		t.Fatalf("roots %+v %v", roots, err)
	}
	ents, trunc, err := c.ListFiles(ctx, "belgeler")
	if err != nil || trunc {
		t.Fatal(err, trunc)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name)
	}
	if len(names) < 2 || names[0] != "alt" || !slices.Contains(names, "a.txt") {
		t.Fatalf("listing %v", names)
	}
	var buf bytes.Buffer
	n, err := c.FetchFile(ctx, "belgeler/a.txt", &buf, 0)
	if err != nil || n != 7 || buf.String() != "merhaba" {
		t.Fatalf("fetch %d %q %v", n, buf.String(), err)
	}
	buf.Reset()
	n, err = c.FetchFile(ctx, "belgeler/alt/b.bin", &buf, 0)
	if err != nil || n != 3*fileChunkLen+11 || sha256.Sum256(buf.Bytes()) != sha256.Sum256(bytes.Repeat([]byte{7}, 3*fileChunkLen+11)) {
		t.Fatalf("big fetch %d %v", n, err)
	}
	if _, err := c.FetchFile(ctx, "belgeler/alt/b.bin", &bytes.Buffer{}, 100); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("limit: %v", err)
	}
	// The session keeps working after a cancelled transfer.
	if _, err := c.FetchFile(ctx, "belgeler/kacis.txt", &bytes.Buffer{}, 0); err == nil {
		t.Fatal("symbolic link out of the root followed")
	}
	if _, err := c.FetchFile(ctx, "belgeler/alt", &bytes.Buffer{}, 0); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("folder fetched: %v", err)
	}
	if _, _, err := c.ListFiles(ctx, "belgeler/yok"); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, _, err := c.ListFiles(ctx, "baska"); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("unknown root: %v", err)
	}
	if _, _, err := c.ListFiles(ctx, "belgeler/../.."); err == nil {
		t.Fatal("dot dot accepted")
	}
	for _, p := range []string{"belgeler/../a.txt", "belgeler//a.txt", `belgeler.txt`, "/belgeler/a.txt", "belgeler/C:x"} {
		if _, _, ok := splitBrowsePath(p); ok {
			t.Fatalf("%q accepted", p)
		}
	}
	if c.Err() != nil {
		t.Fatalf("session ended: %v", c.Err())
	}
}

func TestV3FileBrowseDenied(t *testing.T) {
	h, _ := fileHarness(t, false)
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Monitor: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ListFiles(ctx, ""); !errors.Is(err, ErrFileDenied) {
		t.Fatalf("no files rule: %v", err)
	}
	_ = c.Close()
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop", Files: true})
	v, err := Dial(ctx, h.addr, DialOptions{Mode: ModeView, Monitor: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, _, err := v.ListFiles(ctx, ""); !errors.Is(err, ErrFileDenied) {
		t.Fatalf("view session: %v", err)
	}
	// A view session that sends the request anyway is refused by the
	// server.
	op := &fileOpState{list: true}
	v.v3.opMu.Lock()
	op.id = v.v3.nextID.Add(1)
	op.res = make(chan opResult, 1)
	v.v3.pmu.Lock()
	v.v3.op = op
	v.v3.pmu.Unlock()
	v.v3.opMu.Unlock()
	if err := v.write(encodeFileReq(msgFileList, op.id, "")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-op.res:
		if r.err != nil || r.l.status != fileDenied {
			t.Fatalf("server answer %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
}

func TestFileRootsValidation(t *testing.T) {
	abs, _ := filepath.Abs(t.TempDir())
	if err := validateFileRoots([]FileRoot{{Name: "a", Path: abs}, {Name: "A", Path: abs}}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if err := validateFileRoots([]FileRoot{{Name: "a", Path: "rel"}}); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := validateFileRoots([]FileRoot{{Name: "../a", Path: abs}}); err == nil {
		t.Fatal("bad name accepted")
	}
	roots := FileRootsFromPaths([]string{filepath.Join(abs, "x"), filepath.Join(abs, "y", "x")})
	if roots[0].Name != "x" || roots[1].Name != "x-2" || validateFileRoots(roots) != nil {
		t.Fatalf("names %+v", roots)
	}
	if _, err := New(Config{Authorize: func(netip.Addr, Mode) Decision { return Decision{} }, Indicator: func(SessionEvent) {}, FileRoots: []FileRoot{{Name: "a", Path: "rel"}}}); err == nil {
		t.Fatal("New accepted bad roots")
	}
}

func TestV3Codecs(t *testing.T) {
	ents := []FileEntry{{Name: "a", Dir: true, ModTime: time.Unix(10, 0).UTC()}, {Name: "ç.txt", Size: 42, ModTime: time.Unix(20, 0).UTC()}}
	l, err := decodeListing(payload(t, encodeListing(7, fileOK, "", ents, true), msgFileListing))
	if err != nil || l.id != 7 || !l.truncated || !slices.Equal(l.entries, ents) {
		t.Fatalf("listing %+v %v", l, err)
	}
	if _, err := decodeListing(payload(t, encodeListing(7, fileOK, "", []FileEntry{{Name: "a/b"}}, false), msgFileListing)); err == nil {
		t.Fatal("slash in name accepted")
	}
	sum := sha256.Sum256([]byte("x"))
	f, err := decodeFileDone(payload(t, encodeFileDone(3, fileOK, "", 1, sum), msgFileDone))
	if err != nil || f.id != 3 || f.size != 1 || f.sum != sum {
		t.Fatalf("done %+v %v", f, err)
	}
	id, off, data, err := decodeChunk(payload(t, encodeChunk(5, 9, []byte("abc")), msgFileChunk))
	if err != nil || id != 5 || off != 9 || string(data) != "abc" {
		t.Fatal("chunk")
	}
	if _, _, _, err := decodeChunk(payload(t, encodeChunk(5, 0, make([]byte, fileChunkLen+1)), msgFileChunk)); err == nil {
		t.Fatal("oversized chunk accepted")
	}
	a, err := decodeAnnotation(payload(t, annotationMsg{kind: AnnotateStroke, color: 2, points: []image.Point{{1, 2}, {3, 4}}}.encode(), msgAnnotate))
	if err != nil || a.kind != AnnotateStroke || len(a.points) != 2 || a.points[1] != image.Pt(3, 4) {
		t.Fatal("annotation")
	}
	rid, path, err := decodeFileReq(payload(t, encodeFileReq(msgFileGet, 9, "kök/a"), msgFileGet))
	if err != nil || rid != 9 || path != "kök/a" {
		t.Fatal("request")
	}
	for p, want := range map[string]bool{"": true, "a": true, "a/b c/d": true, "a/": false, "a/./b": false, "a\x00": false, strings.Repeat("a", maxBrowsePath+1): false} {
		if _, _, ok := splitBrowsePath(p); ok != want {
			t.Errorf("splitBrowsePath(%q) = %v", p, ok)
		}
	}
}

func FuzzV3Decoders(f *testing.F) {
	f.Add(encodeListing(1, fileOK, "x", []FileEntry{{Name: "a", Size: 3}}, false)[headerLen:])
	f.Add(encodeFileDone(1, fileOK, "", 3, [32]byte{})[headerLen:])
	f.Add(annotationMsg{kind: AnnotatePointer, points: []image.Point{{1, 1}}}.encode()[headerLen:])
	f.Add(encodeFileReq(msgFileList, 1, "a/b")[headerLen:])
	f.Fuzz(func(t *testing.T, p []byte) {
		if l, err := decodeListing(p); err == nil {
			for _, e := range l.entries {
				if !validEntryName(e.Name) {
					t.Fatalf("bad name %q", e.Name)
				}
			}
		}
		_, _ = decodeFileDone(p)
		_, _, _, _ = decodeChunk(p)
		if a, err := decodeAnnotation(p); err == nil && !validAnnotation(a.kind, a.color, len(a.points)) {
			t.Fatal("invalid annotation decoded")
		}
		if _, path, err := decodeFileReq(p); err == nil {
			if root, rel, ok := splitBrowsePath(path); ok && (strings.Contains(rel, "..") && slices.Contains(strings.Split(rel, "/"), "..") || strings.ContainsAny(root, `/\`)) {
				t.Fatalf("unsafe path %q passed", path)
			}
		}
		_, _ = decodeEcho(p)
		_, _ = decodeCancel(p)
	})
}
