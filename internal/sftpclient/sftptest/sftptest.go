// Package sftptest is a small SFTP version 3 server for tests of
// internal/sftpclient and the panel's file browser. It serves one folder
// through os.Root, so a request can never leave it, and its SSH listener
// binds only to 127.0.0.1.
package sftptest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	maxPacket = 1 << 20
	// DirBatch is how many entries one READDIR answer carries.
	DirBatch = 50
)

// Server serves the SFTP protocol on one stream.
type Server struct {
	root *os.Root
	// ShortReads halves every READ answer (tests of the client's gap
	// handling).
	ShortReads bool

	mu      sync.Mutex
	next    int
	handles map[string]any
}

type dirHandle struct {
	entries []fs.DirEntry
	pos     int
}

// NewServer serves the folder dir.
func NewServer(dir string) (*Server, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Server{root: r, handles: map[string]any{}}, nil
}

// Close releases the folder.
func (s *Server) Close() error { return s.root.Close() }

func rel(p string) string {
	c := path.Clean("/" + p)
	if c == "/" {
		return "."
	}
	return strings.TrimPrefix(c, "/")
}

// Serve answers requests on rw until it fails or closes.
func (s *Server) Serve(rw io.ReadWriter) error {
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(rw, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		if n < 1 || n > maxPacket {
			return errors.New("sftptest: bad packet length")
		}
		body := make([]byte, n-1)
		if _, err := io.ReadFull(rw, body); err != nil {
			return err
		}
		out := s.handle(hdr[4], body)
		if out == nil {
			continue
		}
		if _, err := rw.Write(out); err != nil {
			return err
		}
	}
}

type rd struct {
	b   []byte
	off int
}

func (r *rd) u32() uint32 {
	if len(r.b)-r.off < 4 {
		r.off = len(r.b) + 1
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *rd) u64() uint64 {
	if len(r.b)-r.off < 8 {
		r.off = len(r.b) + 1
		return 0
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v
}

func (r *rd) str() string {
	n := int(r.u32())
	if r.off > len(r.b) || n > len(r.b)-r.off {
		r.off = len(r.b) + 1
		return ""
	}
	v := string(r.b[r.off : r.off+n])
	r.off += n
	return v
}

func (r *rd) bad() bool { return r.off > len(r.b) }

func pkt(typ byte, id uint32, payload []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(5+len(payload)))
	b = append(b, typ)
	b = binary.BigEndian.AppendUint32(b, id)
	return append(b, payload...)
}

func putStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func statusPkt(id, code uint32, msg string) []byte {
	b := binary.BigEndian.AppendUint32(nil, code)
	b = putStr(b, msg)
	b = putStr(b, "en")
	return pkt(101, id, b)
}

func errStatus(id uint32, err error) []byte {
	switch {
	case err == nil:
		return statusPkt(id, 0, "")
	case errors.Is(err, fs.ErrNotExist):
		return statusPkt(id, 2, "no such file")
	case errors.Is(err, fs.ErrPermission):
		return statusPkt(id, 3, "permission denied")
	}
	return statusPkt(id, 4, "failure")
}

func attrs(fi fs.FileInfo) []byte {
	mode := uint32(fi.Mode().Perm())
	switch {
	case fi.IsDir():
		mode |= 0o040000
	case fi.Mode()&fs.ModeSymlink != 0:
		mode |= 0o120000
	case fi.Mode().IsRegular():
		mode |= 0o100000
	}
	b := binary.BigEndian.AppendUint32(nil, 0x01|0x04|0x08)
	b = binary.BigEndian.AppendUint64(b, uint64(fi.Size()))
	b = binary.BigEndian.AppendUint32(b, mode)
	t := uint32(fi.ModTime().Unix())
	b = binary.BigEndian.AppendUint32(b, t)
	return binary.BigEndian.AppendUint32(b, t)
}

func (s *Server) put(h any) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := fmt.Sprintf("h%d", s.next)
	s.handles[id] = h
	return id
}

func (s *Server) get(id string) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.handles[id]
	return h, ok
}

func (s *Server) handle(typ byte, body []byte) []byte {
	if typ == 1 { // INIT
		b := binary.BigEndian.AppendUint32(nil, 5)
		b = append(b, 2)
		return binary.BigEndian.AppendUint32(b, 3)
	}
	r := rd{b: body}
	id := r.u32()
	switch typ {
	case 3: // OPEN
		p := rel(r.str())
		flags := r.u32()
		if r.bad() {
			return statusPkt(id, 5, "bad message")
		}
		of := 0
		switch {
		case flags&0x03 == 0x03:
			of = os.O_RDWR
		case flags&0x02 != 0:
			of = os.O_WRONLY
		}
		if flags&0x08 != 0 {
			of |= os.O_CREATE
		}
		if flags&0x10 != 0 {
			of |= os.O_TRUNC
		}
		if flags&0x20 != 0 {
			of |= os.O_EXCL
		}
		f, err := s.root.OpenFile(p, of, 0o644)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return statusPkt(id, 4, "file exists")
			}
			return errStatus(id, err)
		}
		return pkt(102, id, putStr(nil, s.put(f)))
	case 4: // CLOSE
		hid := r.str()
		s.mu.Lock()
		h, ok := s.handles[hid]
		delete(s.handles, hid)
		s.mu.Unlock()
		if !ok {
			return statusPkt(id, 4, "bad handle")
		}
		if f, ok := h.(*os.File); ok {
			_ = f.Close()
		}
		return statusPkt(id, 0, "")
	case 5: // READ
		h, ok := s.get(r.str())
		off, n := r.u64(), r.u32()
		f, isFile := h.(*os.File)
		if !ok || !isFile || r.bad() {
			return statusPkt(id, 4, "bad handle")
		}
		if s.ShortReads && n > 1 {
			n /= 2
		}
		buf := make([]byte, min(n, 64<<10))
		k, err := f.ReadAt(buf, int64(off))
		if k == 0 && errors.Is(err, io.EOF) {
			return statusPkt(id, 1, "eof")
		}
		if k == 0 && err != nil {
			return errStatus(id, err)
		}
		b := binary.BigEndian.AppendUint32(nil, uint32(k))
		return pkt(103, id, append(b, buf[:k]...))
	case 6: // WRITE
		h, ok := s.get(r.str())
		off := r.u64()
		data := r.str()
		f, isFile := h.(*os.File)
		if !ok || !isFile || r.bad() {
			return statusPkt(id, 4, "bad handle")
		}
		_, err := f.WriteAt([]byte(data), int64(off))
		return errStatus(id, err)
	case 7, 17: // LSTAT, STAT
		p := rel(r.str())
		var fi fs.FileInfo
		var err error
		if typ == 7 {
			fi, err = s.root.Lstat(p)
		} else {
			fi, err = s.root.Stat(p)
		}
		if err != nil {
			return errStatus(id, err)
		}
		return pkt(105, id, attrs(fi))
	case 11: // OPENDIR
		p := rel(r.str())
		f, err := s.root.Open(p)
		if err != nil {
			return errStatus(id, err)
		}
		entries, err := f.ReadDir(-1)
		_ = f.Close()
		if err != nil {
			return errStatus(id, err)
		}
		return pkt(102, id, putStr(nil, s.put(&dirHandle{entries: entries})))
	case 12: // READDIR
		h, ok := s.get(r.str())
		d, isDir := h.(*dirHandle)
		if !ok || !isDir {
			return statusPkt(id, 4, "bad handle")
		}
		if d.pos >= len(d.entries) {
			return statusPkt(id, 1, "eof")
		}
		end := min(d.pos+DirBatch, len(d.entries))
		batch := d.entries[d.pos:end]
		d.pos = end
		b := binary.BigEndian.AppendUint32(nil, uint32(len(batch)))
		for _, e := range batch {
			fi, err := e.Info()
			if err != nil {
				return errStatus(id, err)
			}
			b = putStr(b, e.Name())
			b = putStr(b, e.Name())
			b = append(b, attrs(fi)...)
		}
		return pkt(104, id, b)
	case 13: // REMOVE
		p := rel(r.str())
		fi, err := s.root.Lstat(p)
		if err == nil && fi.IsDir() {
			return statusPkt(id, 4, "is a directory")
		}
		return errStatus(id, s.root.Remove(p))
	case 14: // MKDIR
		p := rel(r.str())
		err := s.root.Mkdir(p, 0o755)
		if errors.Is(err, fs.ErrExist) {
			return statusPkt(id, 4, "exists")
		}
		return errStatus(id, err)
	case 15: // RMDIR
		p := rel(r.str())
		fi, err := s.root.Lstat(p)
		if err == nil && !fi.IsDir() {
			return statusPkt(id, 4, "not a directory")
		}
		return errStatus(id, s.root.Remove(p))
	case 16: // REALPATH
		p := path.Clean("/" + r.str())
		b := binary.BigEndian.AppendUint32(nil, 1)
		b = putStr(b, p)
		b = putStr(b, p)
		b = binary.BigEndian.AppendUint32(b, 0)
		return pkt(104, id, b)
	case 18: // RENAME
		from, to := rel(r.str()), rel(r.str())
		if _, err := s.root.Lstat(to); err == nil {
			return statusPkt(id, 4, "target exists")
		}
		return errStatus(id, s.root.Rename(from, to))
	}
	return statusPkt(id, 8, "unsupported")
}

// SSHServer is an SSH server on 127.0.0.1 with an "sftp" subsystem.
type SSHServer struct {
	Addr    netip.AddrPort
	HostKey ssh.PublicKey
	ln      net.Listener
	wg      sync.WaitGroup
}

// StartSSH serves dir over SFTP to user with password; it stops when the
// test ends.
func StartSSH(t testing.TB, dir, user, password string) *SSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == user && subtle.ConstantTimeCompare(pw, []byte(password)) == 1 {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &SSHServer{Addr: ln.Addr().(*net.TCPAddr).AddrPort(), HostKey: signer.PublicKey(), ln: ln}
	srv.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.wg.Go(func() { serveConn(c, cfg, dir) })
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		srv.wg.Wait()
	})
	return srv
}

func serveConn(c net.Conn, cfg *ssh.ServerConfig, dir string) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range in {
				if req.Type != "subsystem" || len(req.Payload) < 4 || string(req.Payload[4:]) != "sftp" {
					_ = req.Reply(false, nil)
					continue
				}
				_ = req.Reply(true, nil)
				s, err := NewServer(dir)
				if err != nil {
					return
				}
				_ = s.Serve(ch)
				_ = s.Close()
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				return
			}
		}()
	}
}
