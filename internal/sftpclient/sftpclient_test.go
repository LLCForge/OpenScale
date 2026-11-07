package sftpclient_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/sftpclient"
	"github.com/openscale/openscale/internal/sftpclient/sftptest"
	"github.com/openscale/openscale/internal/sshclient"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// pipeClient connects a client to an in-memory server over net.Pipe.
func pipeClient(t *testing.T, dir string, tune func(*sftptest.Server)) *sftpclient.Client {
	t.Helper()
	srv, err := sftptest.NewServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tune != nil {
		tune(srv)
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(b)
		_ = b.Close()
	}()
	c, err := sftpclient.New(ctx(t), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.Close()
		<-done
		_ = srv.Close()
	})
	return c
}

func TestListStatMkdirRemoveRename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := pipeClient(t, dir, nil)
	cx := ctx(t)

	home, err := c.RealPath(cx, ".")
	if err != nil || home != "/" {
		t.Fatalf("RealPath = %q, %v", home, err)
	}
	list, err := c.ReadDir(cx, "/")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range list {
		names = append(names, e.Name)
		if e.Name == "a.txt" && (e.Size != 5 || !e.Regular || e.Dir) {
			t.Fatalf("a.txt = %+v", e)
		}
		if e.Name == "sub" && !e.Dir {
			t.Fatalf("sub = %+v", e)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"a.txt", "sub"}) {
		t.Fatalf("names = %v", names)
	}
	if err := c.Mkdir(cx, "/sub/new"); err != nil {
		t.Fatal(err)
	}
	if fi, err := c.Stat(cx, "/sub/new"); err != nil || !fi.Dir || fi.Name != "new" {
		t.Fatalf("Stat = %+v, %v", fi, err)
	}
	if err := c.Rename(cx, "/a.txt", "/sub/b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat(cx, "/a.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat after rename: %v", err)
	}
	if err := c.Remove(cx, "/sub/b.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveDir(cx, "/sub/new"); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(cx, "/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Remove missing: %v", err)
	}
}

func TestManyEntriesSpanBatches(t *testing.T) {
	dir := t.TempDir()
	for i := range sftptest.DirBatch*2 + 7 {
		name := filepath.Join(dir, "f"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+"-"+itoa(i))
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := pipeClient(t, dir, nil)
	list, err := c.ReadDir(ctx(t), "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != sftptest.DirBatch*2+7 {
		t.Fatalf("got %d entries", len(list))
	}
}

func itoa(i int) string {
	return string([]byte{byte('0' + i/100%10), byte('0' + i/10%10), byte('0' + i%10)})
}

func TestDownloadUploadRoundTrip(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "short-reads"}[short], func(t *testing.T) {
			dir := t.TempDir()
			data := make([]byte, 5*sftpclient.ChunkSize+123)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			c := pipeClient(t, dir, func(s *sftptest.Server) { s.ShortReads = short })
			cx := ctx(t)
			n, err := c.Upload(cx, bytes.NewReader(data), "/up.bin", 0)
			if err != nil || n != int64(len(data)) {
				t.Fatalf("Upload = %d, %v", n, err)
			}
			if _, err := c.Upload(cx, bytes.NewReader(data), "/up.bin", 0); err == nil {
				t.Fatal("Upload over an existing file succeeded")
			}
			var buf bytes.Buffer
			n, err = c.Download(cx, "/up.bin", &buf, 0)
			if err != nil || n != int64(len(data)) || !bytes.Equal(buf.Bytes(), data) {
				t.Fatalf("Download = %d, %v, equal %v", n, err, bytes.Equal(buf.Bytes(), data))
			}
		})
	}
}

func TestLimits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "big"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	c := pipeClient(t, dir, nil)
	cx := ctx(t)
	if _, err := c.Download(cx, "/big", io.Discard, 50); !errors.Is(err, sftpclient.ErrTooLarge) {
		t.Fatalf("Download over limit: %v", err)
	}
	if _, err := c.Download(cx, "/", io.Discard, 0); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("Download of a directory: %v", err)
	}
	if _, err := c.Upload(cx, bytes.NewReader(make([]byte, 100)), "/up", 50); !errors.Is(err, sftpclient.ErrTooLarge) {
		t.Fatalf("Upload over limit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "up")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("partial upload left behind: %v", err)
	}
	if _, err := c.Stat(cx, "bad\x00path"); !errors.Is(err, sftpclient.ErrBadPath) {
		t.Fatalf("NUL path: %v", err)
	}
}

func TestPathHelpers(t *testing.T) {
	good := map[string]string{"/a/b/../c": "/a/c", "/": "/", "/C:/Users": "/C:/Users", "/a//b/": "/a/b"}
	for in, want := range good {
		if got, err := sftpclient.CleanAbs(in); err != nil || got != want {
			t.Errorf("CleanAbs(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "relative", `\a`, "/a\x00", "/a\nb", "/" + strings.Repeat("a", 5000)} {
		if _, err := sftpclient.CleanAbs(in); err == nil {
			t.Errorf("CleanAbs(%q) accepted", in)
		}
	}
	if p, err := sftpclient.Join("/home/u", "f.txt"); err != nil || p != "/home/u/f.txt" {
		t.Errorf("Join = %q, %v", p, err)
	}
	for _, name := range []string{"..", ".", "a/b", `a\b`, "", "x\x00", "x\ny", strings.Repeat("n", 256)} {
		if _, err := sftpclient.Join("/home", name); err == nil {
			t.Errorf("Join accepted %q", name)
		}
	}
}

// hostile is a server that answers INIT and then sends what the test
// gives it.
func hostile(t *testing.T, reply func(w io.Writer)) *sftpclient.Client {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		var hdr [9]byte
		if _, err := io.ReadFull(b, hdr[:]); err != nil {
			return
		}
		v := binary.BigEndian.AppendUint32(nil, 5)
		v = append(v, 2)
		v = binary.BigEndian.AppendUint32(v, 3)
		_, _ = b.Write(v)
		// Read the next request header and body, then misbehave.
		var rh [5]byte
		if _, err := io.ReadFull(b, rh[:]); err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, b, int64(binary.BigEndian.Uint32(rh[:4])-1))
		reply(b)
		_, _ = io.Copy(io.Discard, b)
	}()
	c, err := sftpclient.New(ctx(t), a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestHostileServer(t *testing.T) {
	t.Run("oversized packet", func(t *testing.T) {
		c := hostile(t, func(w io.Writer) {
			h := binary.BigEndian.AppendUint32(nil, sftpclient.MaxPacket+1)
			_, _ = w.Write(append(h, 101))
		})
		if _, err := c.Stat(ctx(t), "/x"); err == nil {
			t.Fatal("oversized packet accepted")
		}
	})
	t.Run("string past end", func(t *testing.T) {
		c := hostile(t, func(w io.Writer) {
			body := binary.BigEndian.AppendUint32(nil, 1) // id
			body = binary.BigEndian.AppendUint32(body, 1) // count
			body = binary.BigEndian.AppendUint32(body, 1<<20)
			p := binary.BigEndian.AppendUint32(nil, uint32(1+len(body)))
			p = append(p, 104)
			_, _ = w.Write(append(p, body...))
		})
		if _, err := c.RealPath(ctx(t), "."); !errors.Is(err, sftpclient.ErrProtocol) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestOverSSHOnLoopback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "remote.txt"), []byte("over ssh"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := sftptest.StartSSH(t, dir, "alice", "s3cret")
	if !srv.Addr.Addr().IsLoopback() {
		t.Fatalf("test server on %v", srv.Addr)
	}
	cx := ctx(t)
	kh := sshclient.OpenKnownHosts(filepath.Join(t.TempDir(), "known.json"))
	cl, err := sshclient.Dial(cx, sshclient.Config{Addr: srv.Addr, HostName: "box:22", User: "alice", KnownHosts: kh,
		Password: func() ([]byte, error) { return []byte("s3cret"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	rw, err := cl.Subsystem("sftp")
	if err != nil {
		t.Fatal(err)
	}
	c, err := sftpclient.New(cx, rw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var buf bytes.Buffer
	if _, err := c.Download(cx, "/remote.txt", &buf, 1<<20); err != nil || buf.String() != "over ssh" {
		t.Fatalf("Download = %q, %v", buf.String(), err)
	}
}
