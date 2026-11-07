package filesend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSanitizeName(t *testing.T) {
	ok := map[string]string{
		"rapor.pdf":            "rapor.pdf",
		"  boşluk.txt  ":       "boşluk.txt",
		"a<b>c:d\"e|f?g*h.txt": "a_b_c_d_e_f_g_h.txt",
		"dosya.txt...":         "dosya.txt",
		"CON":                  "_CON",
		"nul.txt":              "_nul.txt",
		"COM1.log":             "_COM1.log",
		"lpt9":                 "_lpt9",
		"con2.txt":             "con2.txt",
		"zero\u200bwidth.txt":  "zerowidth.txt",
		".bashrc":              ".bashrc",
		"Ünicode çalışma.docx": "Ünicode çalışma.docx",
	}
	for in, want := range ok {
		got, err := SanitizeName(in)
		if err != nil || got != want {
			t.Errorf("SanitizeName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", ".", "..", "...", "../etc/passwd", "..\\windows\\system32", "/etc/passwd",
		"C:\\Windows\\x.exe", "C:x.exe", "a/b.txt", "a\\b.txt", "nul\x00byte",
		"tab\there", "line\nbreak", "gpj\u202eexe.jpg", "x\u2066y", "rtl\u200fmark",
		string([]byte{0xff, 0xfe}), "   ",
	}
	for _, in := range bad {
		if got, err := SanitizeName(in); !errors.Is(err, ErrBadName) {
			t.Errorf("SanitizeName(%q) = %q, %v; want ErrBadName", in, got, err)
		}
	}
	long := string(bytes.Repeat([]byte("ş"), 300)) + ".txt"
	got, err := SanitizeName(long)
	if err != nil || len(got) > maxCleanNameLen || filepath.Ext(got) != ".txt" {
		t.Fatalf("long name = %q (%d), %v", got, len(got), err)
	}
}

func TestIsExecutable(t *testing.T) {
	for _, n := range []string{"setup.EXE", "a.ps1", "run.sh", "x.lnk"} {
		if !IsExecutable(n) {
			t.Errorf("IsExecutable(%q) = false", n)
		}
	}
	for _, n := range []string{"foto.jpg", "rapor.pdf", "noext"} {
		if IsExecutable(n) {
			t.Errorf("IsExecutable(%q) = true", n)
		}
	}
}

type harness struct {
	srv   *Server
	addr  netip.AddrPort
	inbox string
	got   chan Received
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{inbox: filepath.Join(t.TempDir(), "inbox"), got: make(chan Received, 8)}
	cfg.InboxDir = h.inbox
	if cfg.Accept == nil {
		cfg.Accept = func(netip.Addr, string, int64) bool { return true }
	}
	cfg.OnReceived = func(r Received) { h.got <- r }
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
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	h.srv = srv
	h.addr = ln.Addr().(*net.TCPAddr).AddrPort()
	return h
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestSendAndCollision(t *testing.T) {
	var seen []string
	h := newHarness(t, Config{Accept: func(from netip.Addr, name string, size int64) bool {
		if from != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("Accept saw %v", from)
		}
		seen = append(seen, name)
		return true
	}})
	data := randomBytes(t, 3<<20)
	src := writeTemp(t, "rapor.pdf", data)

	var lastDone int64
	res, err := Send(ctx(t), h.addr, src, &SendOptions{Progress: func(done, total int64) { lastDone = done }})
	if err != nil {
		t.Fatal(err)
	}
	if res.SavedName != "rapor.pdf" || res.Resumed != 0 || res.Sent != int64(len(data)) || lastDone != int64(len(data)) {
		t.Fatalf("result = %+v, progress %d", res, lastDone)
	}
	stored, err := os.ReadFile(filepath.Join(h.inbox, "rapor.pdf"))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("stored file mismatch: %v", err)
	}
	rec := <-h.got
	if rec.Name != "rapor.pdf" || rec.Size != int64(len(data)) || rec.Executable {
		t.Fatalf("received = %+v", rec)
	}

	res, err = Send(ctx(t), h.addr, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.SavedName != "rapor (1).pdf" {
		t.Fatalf("collision name = %q", res.SavedName)
	}
	<-h.got
	if len(seen) != 2 {
		t.Fatalf("Accept calls = %d", len(seen))
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(h.inbox, "rapor (1).pdf"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("permissions = %v, %v", fi.Mode().Perm(), err)
		}
	}
}

func TestEmptyFileAndExecutableFlag(t *testing.T) {
	h := newHarness(t, Config{})
	src := writeTemp(t, "kur.exe", nil)
	res, err := Send(ctx(t), h.addr, src, nil)
	if err != nil || res.SavedName != "kur.exe" {
		t.Fatalf("Send = %+v, %v", res, err)
	}
	if rec := <-h.got; !rec.Executable || rec.Size != 0 {
		t.Fatalf("received = %+v", rec)
	}
}

func TestRejectedAndTooLarge(t *testing.T) {
	h := newHarness(t, Config{Accept: func(netip.Addr, string, int64) bool { return false }})
	src := writeTemp(t, "a.txt", []byte("merhaba"))
	if _, err := Send(ctx(t), h.addr, src, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	h2 := newHarness(t, Config{MaxSize: 4})
	if _, err := Send(ctx(t), h2.addr, src, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	entries, _ := os.ReadDir(h.inbox)
	for _, e := range entries {
		if e.Name() != partialDirName {
			t.Fatalf("unexpected inbox entry %q", e.Name())
		}
	}
}

func TestServerRejectsTraversalName(t *testing.T) {
	h := newHarness(t, Config{})
	conn, err := net.Dial("tcp", h.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sum := sha256.Sum256([]byte("x"))
	if err := writeFrame(conn, offer{V: protocolVersion, Name: "../../evil.txt", Size: 1, SHA256: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatal(err)
	}
	var r reply
	if err := readFrame(conn, &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != statusBadName {
		t.Fatalf("status = %q", r.Status)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.inbox), "evil.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("traversal file exists: %v", err)
	}
}

func waitIdle(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.active)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("transfer did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// interrupt starts a transfer of data and drops the connection after n bytes.
func interrupt(t *testing.T, h *harness, name string, data, sentData []byte, n int) {
	t.Helper()
	conn, err := net.Dial("tcp", h.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if err := writeFrame(conn, offer{V: protocolVersion, Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatal(err)
	}
	var r reply
	if err := readFrame(conn, &r); err != nil || r.Status != statusAccept {
		t.Fatalf("reply = %+v, %v", r, err)
	}
	if _, err := conn.Write(sentData[r.Offset:n]); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	waitIdle(t, h.srv)
}

func TestResume(t *testing.T) {
	h := newHarness(t, Config{})
	data := randomBytes(t, 1<<20)
	src := writeTemp(t, "video.mp4", data)
	interrupt(t, h, "video.mp4", data, data, 400_000)

	res, err := Send(ctx(t), h.addr, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resumed != 400_000 || res.Sent != int64(len(data))-400_000 {
		t.Fatalf("result = %+v", res)
	}
	stored, err := os.ReadFile(filepath.Join(h.inbox, "video.mp4"))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("resumed file mismatch: %v", err)
	}
	if rec := <-h.got; rec.Resumed != 400_000 {
		t.Fatalf("received = %+v", rec)
	}
	entries, _ := os.ReadDir(filepath.Join(h.inbox, partialDirName))
	if len(entries) != 0 {
		t.Fatalf("partial files left: %d", len(entries))
	}
}

func TestCorruptPartialIsDeleted(t *testing.T) {
	h := newHarness(t, Config{})
	data := randomBytes(t, 256<<10)
	src := writeTemp(t, "belge.bin", data)
	corrupt := bytes.Clone(data)
	for i := range 1000 {
		corrupt[i] ^= 0xFF
	}
	interrupt(t, h, "belge.bin", data, corrupt, 100_000)

	if _, err := Send(ctx(t), h.addr, src, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity", err)
	}
	waitIdle(t, h.srv)
	if _, err := os.Stat(filepath.Join(h.inbox, "belge.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt file stored: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(h.inbox, partialDirName))
	if len(entries) != 0 {
		t.Fatalf("corrupt partial kept: %d", len(entries))
	}
	// A retry starts from scratch and succeeds.
	res, err := Send(ctx(t), h.addr, src, nil)
	if err != nil || res.Resumed != 0 {
		t.Fatalf("retry = %+v, %v", res, err)
	}
}

func TestPartialCleanup(t *testing.T) {
	// No Serve loop: its start-up cleanup would race with this test.
	srv, err := NewServer(Config{InboxDir: t.TempDir(), PartialTTL: time.Hour, Accept: func(netip.Addr, string, int64) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(srv.inbox, partialDirName, "deadbeefdeadbeefdeadbeefdeadbeef"+partialSuffix)
	if err := os.WriteFile(p, []byte("eski"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	srv.CleanupPartials()
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired partial kept: %v", err)
	}
}

func TestListenAddrValidation(t *testing.T) {
	srv, err := NewServer(Config{
		InboxDir:   t.TempDir(),
		Accept:     func(netip.Addr, string, int64) bool { return true },
		ListenAddr: netip.MustParseAddrPort("[::]:7001"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ListenAndServe(context.Background()); !errors.Is(err, ErrInvalidListenAddr) {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewServer(Config{InboxDir: t.TempDir()}); err == nil {
		t.Fatal("NewServer without Accept succeeded")
	}
}
