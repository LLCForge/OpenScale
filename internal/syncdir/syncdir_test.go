package syncdir

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestValidatePath(t *testing.T) {
	for _, p := range []string{"a.txt", "docs/rapor.pdf", "Ünicode/çalışma.docx", ".gizli", "a/b/c/d.e"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"", ".", "..", "../x", "a/../b", "/abs", "a//b", "a\\b", "C:/x", "a/CON", "nul.txt",
		"x\u202egpj.exe", "a/b ", "a/b.", ".openscale-sync/index.json", ".OpenScale-Sync/x", "a:b", "tab\tx", strings.Repeat("a/", 70) + "x"} {
		if ValidatePath(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func e(content string, mtime int64) Entry {
	return Entry{Size: int64(len(content)), MTime: mtime, Hash: hashOf(content)}
}

func TestPlan(t *testing.T) {
	type tc struct {
		name              string
		mode              FolderMode
		local, remote, b  Index
		propagate         bool
		want              ActionKind // 0: nothing
		wantConflictLoser string
	}
	a1, a2, a3 := e("bir", 1), e("iki", 2), e("üç", 3)
	cases := []tc{
		{"same", SendReceive, Index{"f": a1}, Index{"f": a1}, nil, false, 0, ""},
		{"new remote", SendReceive, Index{}, Index{"f": a1}, nil, false, ActFetch, ""},
		{"new local", SendReceive, Index{"f": a1}, Index{}, nil, false, 0, ""},
		{"remote changed", SendReceive, Index{"f": a1}, Index{"f": a2}, Index{"f": a1}, false, ActFetch, ""},
		{"local changed", SendReceive, Index{"f": a2}, Index{"f": a1}, Index{"f": a1}, false, 0, ""},
		{"remote deleted, kept", SendReceive, Index{"f": a1}, Index{}, Index{"f": a1}, false, 0, ""},
		{"remote deleted, propagated", SendReceive, Index{"f": a1}, Index{}, Index{"f": a1}, true, ActDelete, ""},
		{"remote deleted, local changed", SendReceive, Index{"f": a2}, Index{}, Index{"f": a1}, true, 0, ""},
		{"local deleted", SendReceive, Index{}, Index{"f": a1}, Index{"f": a1}, true, 0, ""},
		{"local deleted, remote changed", SendReceive, Index{}, Index{"f": a2}, Index{"f": a1}, true, ActFetch, ""},
		{"conflict, remote newer", SendReceive, Index{"f": a2}, Index{"f": a3}, Index{"f": a1}, false, ActConflictTakeRemote, a2.Hash},
		{"conflict, local newer", SendReceive, Index{"f": a3}, Index{"f": a2}, Index{"f": a1}, false, ActConflictKeepLocal, a2.Hash},
		{"conflict, no base", SendReceive, Index{"f": a2}, Index{"f": a3}, nil, false, ActConflictTakeRemote, a2.Hash},
		{"receive-only overrides", ReceiveOnly, Index{"f": a2}, Index{"f": a1}, Index{"f": a1}, false, ActFetch, ""},
		{"receive-only restores", ReceiveOnly, Index{}, Index{"f": a1}, Index{"f": a1}, false, ActFetch, ""},
	}
	for _, c := range cases {
		acts, _ := Plan(c.mode, c.local, c.remote, c.b, PlanOptions{PropagateDeletes: c.propagate})
		if c.want == 0 {
			if len(acts) != 0 {
				t.Errorf("%s: unexpected %+v", c.name, acts)
			}
			continue
		}
		if len(acts) != 1 || acts[0].Kind != c.want {
			t.Errorf("%s: got %+v", c.name, acts)
			continue
		}
		if c.wantConflictLoser != "" && acts[0].ConflictPath != ConflictName("f", c.wantConflictLoser) {
			t.Errorf("%s: conflict path %q", c.name, acts[0].ConflictPath)
		}
	}
	// Both devices pick the same winner.
	l, r := Index{"f": a2}, Index{"f": a3}
	x, _ := Plan(SendReceive, l, r, nil, PlanOptions{})
	y, _ := Plan(SendReceive, r, l, nil, PlanOptions{})
	if x[0].ConflictPath != y[0].ConflictPath {
		t.Fatalf("devices disagree: %q vs %q", x[0].ConflictPath, y[0].ConflictPath)
	}
	// Case-only differences are skipped.
	acts, skipped := Plan(SendReceive, Index{"Rapor.txt": a1}, Index{"rapor.txt": a2}, nil, PlanOptions{})
	if len(acts) != 0 || len(skipped) != 1 {
		t.Fatalf("case fold: %+v %+v", acts, skipped)
	}
}

// node is one device: a folder and a server sharing it with "peer".
type node struct {
	name   string
	dir    string
	folder *Folder
	addr   netip.AddrPort
}

func startServer(t *testing.T, cfg ServerConfig) netip.AddrPort {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func newNode(t *testing.T, name, peer string, cfg FolderConfig) *node {
	t.Helper()
	n := &node{name: name, dir: filepath.Join(t.TempDir(), name)}
	if err := os.MkdirAll(n.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.ID, cfg.Path = "docs", n.dir
	f, err := OpenFolder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	n.folder = f
	n.addr = startServer(t, ServerConfig{
		Authorize: func(remote netip.Addr) Access {
			if !remote.IsLoopback() {
				return Access{}
			}
			return Access{Peer: peer, Folders: []string{"docs"}}
		},
		Folder: func(id string) *Folder {
			if id == "docs" {
				return f
			}
			return nil
		},
	})
	return n
}

func (n *node) write(t *testing.T, p, content string, mtime time.Time) {
	t.Helper()
	full := filepath.Join(n.dir, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(full, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func (n *node) read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(n.dir, filepath.FromSlash(p)))
	if err != nil {
		return "<yok>"
	}
	return string(b)
}

func (n *node) pullFrom(t *testing.T, peer *node) PullResult {
	t.Helper()
	c, err := Dial(testCtx(t), peer.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := n.folder.Pull(testCtx(t), peer.name, c.Folder("docs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) > 0 {
		t.Fatalf("%s pull failed: %+v", n.name, res.Failed)
	}
	return res
}

func TestTwoWaySync(t *testing.T) {
	a := newNode(t, "a", "b", FolderConfig{})
	b := newNode(t, "b", "a", FolderConfig{})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	a.write(t, "rapor.txt", "ilk", t0)
	a.write(t, "alt/klasör/not.md", "not", t0)
	if r := b.pullFrom(t, a); r.Fetched != 2 {
		t.Fatalf("fetched %d", r.Fetched)
	}
	if b.read(t, "alt/klasör/not.md") != "not" {
		t.Fatal("nested file missing")
	}
	if r := a.pullFrom(t, b); r.Fetched+r.Conflicts+r.Deleted != 0 {
		t.Fatalf("echo: %+v", r)
	}
	// A change on b reaches a; a's old version is kept.
	b.write(t, "rapor.txt", "ikinci", t0.Add(time.Minute))
	a.pullFrom(t, b)
	if a.read(t, "rapor.txt") != "ikinci" {
		t.Fatal("change not pulled")
	}
	vs, err := a.folder.Versions()
	if err != nil || len(vs) != 1 || vs[0].Path != "rapor.txt" {
		t.Fatalf("versions %+v %v", vs, err)
	}
	b.pullFrom(t, a)

	// Both change the same file: the newer wins on both devices and the
	// other version is kept next to it on both.
	a.write(t, "rapor.txt", "a sürümü", t0.Add(2*time.Minute))
	b.write(t, "rapor.txt", "b sürümü", t0.Add(3*time.Minute))
	a.pullFrom(t, b)
	b.pullFrom(t, a)
	a.pullFrom(t, b)
	conflict := ConflictName("rapor.txt", hashOf("a sürümü"))
	for _, n := range []*node{a, b} {
		if n.read(t, "rapor.txt") != "b sürümü" || n.read(t, conflict) != "a sürümü" {
			t.Fatalf("%s: main %q conflict %q", n.name, n.read(t, "rapor.txt"), n.read(t, conflict))
		}
	}
	// Converged: nothing more to do in either direction.
	if r := a.pullFrom(t, b); r.Fetched+r.Conflicts+r.Deleted != 0 {
		t.Fatalf("not converged: %+v", r)
	}
	if r := b.pullFrom(t, a); r.Fetched+r.Conflicts+r.Deleted != 0 {
		t.Fatalf("not converged: %+v", r)
	}

	// Deleting is not propagated by default.
	if err := os.Remove(filepath.Join(a.dir, "alt", "klasör", "not.md")); err != nil {
		t.Fatal(err)
	}
	b.pullFrom(t, a)
	if b.read(t, "alt/klasör/not.md") != "not" {
		t.Fatal("deletion propagated without opt-in")
	}
	a.pullFrom(t, b)
	if a.read(t, "alt/klasör/not.md") != "<yok>" {
		t.Fatal("deleted file came back")
	}
}

func TestDeletePropagationAndVersions(t *testing.T) {
	a := newNode(t, "a", "b", FolderConfig{})
	b := newNode(t, "b", "a", FolderConfig{PropagateDeletes: true, Versions: 1})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	a.write(t, "x.txt", "1", t0)
	b.pullFrom(t, a)
	for i := 2; i <= 4; i++ {
		a.write(t, "x.txt", strings.Repeat("v", i), t0.Add(time.Duration(i)*time.Minute))
		time.Sleep(5 * time.Millisecond)
		b.pullFrom(t, a)
	}
	vs, _ := b.folder.Versions()
	if len(vs) != 1 || vs[0].Size != 3 {
		t.Fatalf("versions kept: %+v", vs)
	}
	if err := os.Remove(filepath.Join(a.dir, "x.txt")); err != nil {
		t.Fatal(err)
	}
	if r := b.pullFrom(t, a); r.Deleted != 1 || b.read(t, "x.txt") != "<yok>" {
		t.Fatalf("delete not propagated: %+v", r)
	}
	vs, _ = b.folder.Versions()
	if len(vs) != 1 || vs[0].Size != 4 {
		t.Fatalf("deleted file not kept as a version: %+v", vs)
	}
	if err := b.folder.Restore(vs[0]); err != nil || b.read(t, "x.txt") != "vvvv" {
		t.Fatalf("restore: %v", err)
	}
}

func TestSendOnlyAndReceiveOnly(t *testing.T) {
	src := newNode(t, "kaynak", "ayna", FolderConfig{Mode: SendOnly})
	dst := newNode(t, "ayna", "kaynak", FolderConfig{Mode: ReceiveOnly})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	src.write(t, "a.txt", "asıl", t0)
	dst.pullFrom(t, src)
	dst.write(t, "a.txt", "yerel değişiklik", t0.Add(time.Hour))
	if _, err := src.folder.Pull(testCtx(t), "ayna", nil); !errors.Is(err, ErrSendOnly) {
		t.Fatalf("send-only pulled: %v", err)
	}
	dst.pullFrom(t, src)
	if dst.read(t, "a.txt") != "asıl" {
		t.Fatal("receive-only must mirror the source")
	}
	if vs, _ := dst.folder.Versions(); len(vs) != 1 {
		t.Fatal("local change not kept as a version")
	}
}

func TestServerDenies(t *testing.T) {
	a := newNode(t, "a", "b", FolderConfig{})
	a.write(t, "gizli.txt", "x", time.Now())
	c, err := Dial(testCtx(t), a.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Folder("baska").Index(testCtx(t)); !errors.Is(err, ErrDenied) {
		t.Fatalf("unshared folder: %v", err)
	}
	if _, err := c.Folder("docs").Index(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../gizli.txt", ".openscale-sync/index.json", "/etc/passwd"} {
		err := c.Folder("docs").Fetch(testCtx(t), p, e("x", 0), io.Discard)
		if err == nil {
			t.Fatalf("%q served", p)
		}
	}
	// Backup requests are refused without a backup directory.
	if _, err := c.Store("yedek").List(testCtx(t), KindManifest); !errors.Is(err, ErrDenied) {
		t.Fatalf("backup without target: %v", err)
	}
}

type fakeSource struct {
	ix   Index
	data map[string]string
}

func (f fakeSource) Index(context.Context) (Index, error) { return f.ix, nil }
func (f fakeSource) Fetch(_ context.Context, p string, _ Entry, w io.Writer) error {
	_, err := io.WriteString(w, f.data[p])
	return err
}

func TestHostilePeer(t *testing.T) {
	n := newNode(t, "a", "b", FolderConfig{})
	if _, err := n.folder.Pull(testCtx(t), "b", fakeSource{ix: Index{"../kaçış.txt": e("x", 1)}}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("escaping path: %v", err)
	}
	// Content that does not match the announced hash is never placed.
	res, err := n.folder.Pull(testCtx(t), "b", fakeSource{ix: Index{"a.txt": e("doğru", 1)}, data: map[string]string{"a.txt": "yanlış"}})
	if err != nil || len(res.Failed) != 1 || n.read(t, "a.txt") != "<yok>" {
		t.Fatalf("bad content: %+v %v", res, err)
	}
	// More bytes than announced.
	res, _ = n.folder.Pull(testCtx(t), "b", fakeSource{ix: Index{"b.txt": e("ab", 1)}, data: map[string]string{"b.txt": "abcdef"}})
	if len(res.Failed) != 1 || n.read(t, "b.txt") != "<yok>" {
		t.Fatalf("oversized content: %+v", res)
	}
}

func TestSymlinksAreNotFollowed(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "dış.txt"), []byte("dışarıda"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := newNode(t, "a", "b", FolderConfig{})
	if err := os.Symlink(outside, filepath.Join(n.dir, "bağ")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symbolic links need extra rights on Windows")
		}
		t.Fatal(err)
	}
	ix, err := n.folder.Scan()
	if err != nil {
		t.Fatal(err)
	}
	for p := range ix {
		if strings.HasPrefix(p, "bağ") {
			t.Fatalf("followed a link: %q", p)
		}
	}
	// A pull that would write through the link is confined to the folder.
	_, _ = n.folder.Pull(testCtx(t), "b", fakeSource{ix: Index{"bağ/yeni.txt": e("x", 1)}, data: map[string]string{"bağ/yeni.txt": "x"}})
	if _, err := os.Stat(filepath.Join(outside, "yeni.txt")); err == nil {
		t.Fatal("wrote outside the folder through a link")
	}
}

func backupServer(t *testing.T, acc Access) (netip.AddrPort, string) {
	dir := filepath.Join(t.TempDir(), "hedef")
	addr := startServer(t, ServerConfig{
		Authorize: func(netip.Addr) Access { return acc },
		BackupDir: dir,
	})
	return addr, dir
}

func TestBackupRoundTrip(t *testing.T) {
	src := newNode(t, "laptop", "x", FolderConfig{})
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	src.write(t, "maaş-bordrosu.pdf", "GİZLİ-İÇERİK-1", t0)
	src.write(t, "aile/fotoğraf.jpg", strings.Repeat("GİZLİ-FOTO", 200000), t0)
	addr, targetDir := backupServer(t, Access{Peer: "laptop", Backup: true, Quota: 1 << 30})
	key, created, err := LoadOrCreateBackupKey(filepath.Join(t.TempDir(), "backup.key"))
	if err != nil || !created {
		t.Fatal(err)
	}
	c, err := Dial(testCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	store := c.Store("belgeler")
	r1, err := Snapshot(testCtx(t), src.folder, key, store, "")
	if err != nil || r1.Uploaded != 2 {
		t.Fatalf("snapshot: %+v %v", r1, err)
	}
	src.write(t, "maaş-bordrosu.pdf", "GİZLİ-İÇERİK-2", t0.Add(time.Minute))
	r2, err := Snapshot(testCtx(t), src.folder, key, store, "")
	if err != nil || r2.Uploaded != 1 || r2.Reused != 1 {
		t.Fatalf("incremental: %+v %v", r2, err)
	}
	// The target holds no names and no content.
	err = filepath.WalkDir(targetDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		for _, leak := range []string{"maaş", "aile", "fotoğraf", "bordro"} {
			if strings.Contains(p, leak) {
				t.Errorf("name visible on target: %s", p)
			}
		}
		if d.Type().IsRegular() {
			data, _ := os.ReadFile(p)
			if bytes.Contains(data, []byte("GİZLİ")) || bytes.Contains(data, []byte("maaş")) {
				t.Errorf("plaintext on target: %s", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Restore the first snapshot with an exported and re-imported key.
	text, err := key.Export([]byte("uzun ve gizli parola"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportBackupKey(text, []byte("yanlış parola 123")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	key2, err := ImportBackupKey(text, []byte("uzun ve gizli parola"))
	if err != nil || key2.Fingerprint() != key.Fingerprint() {
		t.Fatalf("import: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "geri")
	n, err := Restore(testCtx(t), key2, store, r1.Name, dest)
	if err != nil || n != 2 {
		t.Fatalf("restore: %d %v", n, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "maaş-bordrosu.pdf")); string(got) != "GİZLİ-İÇERİK-1" {
		t.Fatalf("restored %q", got)
	}
	if _, err := Restore(testCtx(t), key2, store, r1.Name, dest); err == nil {
		t.Fatal("restore into a non-empty folder")
	}
	other, _ := NewBackupKey()
	if _, err := LoadManifest(testCtx(t), other, store, r1.Name); !errors.Is(err, ErrBackupKey) {
		t.Fatalf("other key: %v", err)
	}
	// Append only by default.
	if _, _, err := Prune(testCtx(t), key, store, 1); !errors.Is(err, ErrDenied) {
		t.Fatalf("prune without permission: %v", err)
	}
}

func TestBackupPruneAndQuota(t *testing.T) {
	src := newNode(t, "laptop", "x", FolderConfig{})
	src.write(t, "a.txt", "bir", time.Now().Add(-time.Hour))
	addr, _ := backupServer(t, Access{Peer: "laptop", Backup: true, Quota: 1 << 20, AllowPrune: true})
	key, _ := NewBackupKey()
	c, err := Dial(testCtx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	store := c.Store("s")
	for i := range 3 {
		src.write(t, "a.txt", strings.Repeat("x", i+1), time.Now().Add(time.Duration(i)*time.Second))
		if _, err := Snapshot(testCtx(t), src.folder, key, store, ""); err != nil {
			t.Fatal(err)
		}
	}
	m, b, err := Prune(testCtx(t), key, store, 1)
	if err != nil || m != 2 || b != 2 {
		t.Fatalf("prune: %d %d %v", m, b, err)
	}
	names, _ := Snapshots(testCtx(t), store)
	if len(names) != 1 {
		t.Fatalf("snapshots left: %v", names)
	}
	src.write(t, "büyük.bin", strings.Repeat("z", 2<<20), time.Now())
	if _, err := Snapshot(testCtx(t), src.folder, key, store, ""); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota: %v", err)
	}
}

func TestBackupStreamTamper(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plain := bytes.Repeat([]byte("veri"), 300000)
	var sealed bytes.Buffer
	if err := sealStream(&sealed, key, bytes.NewReader(plain), int64(len(plain))); err != nil {
		t.Fatal(err)
	}
	if int64(sealed.Len()) != sealedSize(int64(len(plain))) {
		t.Fatal("sealedSize mismatch")
	}
	var out bytes.Buffer
	if err := openStream(&out, key, bytes.NewReader(sealed.Bytes()), int64(len(plain))); err != nil || !bytes.Equal(out.Bytes(), plain) {
		t.Fatalf("round trip: %v", err)
	}
	data := sealed.Bytes()
	for _, bad := range [][]byte{data[:len(data)-100], append(append([]byte(nil), data...), 1)} {
		if openStream(io.Discard, key, bytes.NewReader(bad), int64(len(plain))) == nil {
			t.Fatal("cut or extended stream accepted")
		}
	}
	flip := append([]byte(nil), data...)
	flip[20] ^= 1
	if openStream(io.Discard, key, bytes.NewReader(flip), int64(len(plain))) == nil {
		t.Fatal("tampered stream accepted")
	}
	if _, err := (&BackupKey{}).Export([]byte("kısa")); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func FuzzValidatePath(f *testing.F) {
	for _, s := range []string{"a/b.txt", "../x", "CON", "a\u202e", ".openscale-sync/x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if ValidatePath(p) != nil {
			return
		}
		if strings.Contains(p, "..") && (strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || p == "..") {
			t.Fatalf("accepted %q", p)
		}
		if filepath.IsAbs(p) || strings.ContainsAny(p, "\\\x00:") {
			t.Fatalf("accepted %q", p)
		}
	})
}

func FuzzManifestAndFrames(f *testing.F) {
	key := &BackupKey{}
	m, _ := key.sealManifest(&Manifest{V: 1, Files: []ManifestFile{{Path: "a", Hash: hashOf("a"), Key: strings.Repeat("00", 32), Blob: strings.Repeat("ab", 16)}}})
	f.Add(m)
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = key.openManifest(data)
		var r request
		_ = readFrame(bytes.NewReader(data), &r)
		_, _ = unmarshalIndex(data)
		_ = openStream(io.Discard, make([]byte, 32), bytes.NewReader(data), int64(len(data)))
	})
}
