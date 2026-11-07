package p2psend

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/filesend"
)

// DefaultPort is the proposed tunnel port for end-to-end transfers
// (ADR-0204). The trust package owns port constants and the "files"
// service rule; until it adds this port there, the node passes it here.
const DefaultPort uint16 = 4054

const (
	defaultMaxSize       = int64(8) << 30
	defaultMaxConcurrent = 4
	defaultMaxRelays     = 8
	maxConnections       = 32
	// maxPerSource keeps one member (or one relay hop) from taking every
	// connection slot.
	maxPerSource       = 8
	helloTimeout       = 30 * time.Second
	defaultIdleTimeout = 60 * time.Second
	partialDirName     = ".openscale-e2e-partial"
	defaultPartialTTL  = 48 * time.Hour
	replayWindow       = 30 * time.Minute
	maxReplayEntries   = 8192
	// maxReplayPerSource caps the replay entries one authenticated sender
	// (or one relay hop) can hold; the oldest of its own entries goes first.
	maxReplayPerSource = 512
	relayDialTimeout   = 10 * time.Second
	maxCollisions      = 9999
)

// Received describes a file that passed verification and was stored in
// quarantine (#659).
type Received struct {
	From        string
	Name        string
	Path        string
	Size        int64
	Resumed     int64
	Executable  bool
	Stripped    bool
	Quarantined bool
}

// Config configures a Server.
type Config struct {
	// Identity is this device's WireGuard key pair. Required.
	Identity Identity
	// Directory resolves senders and relay hops from the signed document.
	Directory Directory
	// QuarantineDir receives verified files (owner-only). Required.
	QuarantineDir string
	// Ask decides about an offer (Approvals.Ask). Required.
	Ask func(ctx context.Context, o Offer) (bool, error)
	// AllowFile reports whether the signed document's files rule lets the
	// named device send files to this one (trust AllowsFileSend(from,
	// self)). It is checked for the authenticated sender whatever path the
	// stream took (direct or through relays, where the packet filter only
	// sees the last hop) and again after approval. Required.
	AllowFile func(from string) bool
	// OnReceived is called after a file is stored.
	OnReceived func(Received)
	// Relay allows this device to forward onion streams for members.
	Relay bool
	// RelayPort restricts relay targets to this port (the p2psend port of
	// member devices); 0 allows any port (tests).
	RelayPort uint16
	// MaxSize caps one file (default 8 GiB).
	MaxSize int64
	// MaxConcurrent caps simultaneous incoming files (default 4).
	MaxConcurrent int
	// MaxRelays caps simultaneous relayed streams (default 8).
	MaxRelays int
	// IdleTimeout aborts a stalled stream (default 60 s).
	IdleTimeout time.Duration
	// PartialTTL removes interrupted transfers (default 48 h).
	PartialTTL time.Duration
	// Registry, if set, records transfers for the panel.
	Registry *Registry
	// Dial opens relay connections; nil uses net.Dialer.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// Logger receives structured logs without file names; nil discards.
	Logger *slog.Logger
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Server receives end-to-end encrypted files and relays onion streams.
type Server struct {
	cfg        Config
	quarantine string
	partialDir string
	sem        chan struct{}
	relaySem   chan struct{}

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	locks  map[string]bool
	replay replayCache
	closed bool
	wg     sync.WaitGroup
}

// replayCache remembers authenticated ephemeral keys for replayWindow.
// Only keys whose hello or layer passed authentication are stored, each
// source has its own quota and a full cache drops the oldest entry
// instead of refusing everyone.
type replayCache struct {
	byKey map[Key]replayEntry
	bySrc map[string][]Key // insertion order per source
}

type replayEntry struct {
	at  time.Time
	src string
}

func (c *replayCache) remove(e Key) {
	ent, ok := c.byKey[e]
	if !ok {
		return
	}
	delete(c.byKey, e)
	q := c.bySrc[ent.src]
	for i, k := range q {
		if k == e {
			q = append(q[:i:i], q[i+1:]...)
			break
		}
	}
	if len(q) == 0 {
		delete(c.bySrc, ent.src)
	} else {
		c.bySrc[ent.src] = q
	}
}

// NewServer validates cfg and prepares the quarantine directory.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Identity.Public.IsZero() {
		return nil, errors.New("p2psend: identity required")
	}
	if cfg.Directory == nil || cfg.Ask == nil || cfg.AllowFile == nil {
		return nil, errors.New("p2psend: directory, Ask and AllowFile required")
	}
	if cfg.QuarantineDir == "" {
		return nil, errors.New("p2psend: quarantine directory required")
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = defaultMaxSize
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	if cfg.MaxRelays <= 0 {
		cfg.MaxRelays = defaultMaxRelays
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.PartialTTL <= 0 {
		cfg.PartialTTL = defaultPartialTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Dial == nil {
		cfg.Dial = func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", a.String())
		}
	}
	q, err := filepath.Abs(cfg.QuarantineDir)
	if err != nil {
		return nil, err
	}
	partial := filepath.Join(q, partialDirName)
	if err := os.MkdirAll(partial, 0o700); err != nil {
		return nil, fmt.Errorf("karantina klasörü oluşturulamadı: %w", err)
	}
	return &Server{
		cfg: cfg, quarantine: q, partialDir: partial,
		sem:      make(chan struct{}, cfg.MaxConcurrent),
		relaySem: make(chan struct{}, cfg.MaxRelays),
		conns:    map[net.Conn]struct{}{}, locks: map[string]bool{},
		replay: replayCache{byKey: map[Key]replayEntry{}, bySrc: map[string][]Key{}},
	}, nil
}

// QuarantineDir returns the absolute quarantine directory.
func (s *Server) QuarantineDir() string { return s.quarantine }

// Serve accepts connections until ctx ends or ln fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.cleanupPartials()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		s.closeConns()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.wg.Wait()
			return err
		}
		if !s.track(c) {
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= maxConnections {
		return false
	}
	if src, ok := addrOf(c.RemoteAddr()); ok {
		n := 0
		for o := range s.conns {
			if a, ok := addrOf(o.RemoteAddr()); ok && a.Addr() == src.Addr() {
				n++
			}
		}
		if n >= maxPerSource {
			return false
		}
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	_ = c.Close()
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) closeConns() {
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
}

// seen records an authenticated ephemeral key of src and reports whether
// it was used before. Callers pass only keys whose hello or layer already
// authenticated, so unauthenticated input never takes cache space.
func (s *Server) seen(src string, e Key) bool {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &s.replay
	if ent, ok := c.byKey[e]; ok {
		if now.Sub(ent.at) < replayWindow {
			return true
		}
		c.remove(e)
	}
	// One source only ever evicts its own oldest entries.
	for len(c.bySrc[src]) >= maxReplayPerSource {
		c.remove(c.bySrc[src][0])
	}
	if len(c.byKey) >= maxReplayEntries {
		for k, ent := range c.byKey {
			if now.Sub(ent.at) >= replayWindow {
				c.remove(k)
			}
		}
	}
	if len(c.byKey) >= maxReplayEntries {
		var oldest Key
		var at time.Time
		first := true
		for k, ent := range c.byKey {
			if first || ent.at.Before(at) {
				oldest, at, first = k, ent.at, false
			}
		}
		c.remove(oldest)
	}
	c.byKey[e] = replayEntry{at: now, src: src}
	c.bySrc[src] = append(c.bySrc[src], e)
	return false
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	// The preamble must arrive within helloTimeout and is read unbuffered;
	// after it every read gets the idle timeout.
	_ = c.SetDeadline(time.Now().Add(helloTimeout))
	kind, err := readPreamble(c)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	br := bufio.NewReaderSize(idleConn{Conn: c, idle: s.cfg.IdleTimeout}, 4096)
	switch kind {
	case kindFile:
		s.handleFile(ctx, c, br)
	case kindRelay:
		s.handleRelay(ctx, c, br)
	}
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

func (s *Server) handleFile(ctx context.Context, c net.Conn, br *bufio.Reader) {
	hello, err := readFileHello(br)
	if err != nil {
		return
	}
	peer, ok := s.cfg.Directory.ByKey(hello.sender)
	if !ok || hello.sender == s.cfg.Identity.Public {
		s.cfg.Logger.Warn("e2e file from unknown key refused")
		return
	}
	keys, err := receiverSession(s.cfg.Identity, hello.ephemeral, hello.sender)
	if err != nil {
		return
	}
	defer keys.wipe()
	plain, err := open(&keys.header, domainHeader, 0, hello.sealed, []byte(magic))
	if err != nil {
		// SECURITY FIX: CWE-400 the replay cache is written only after the
		// header authenticated, so forged hellos cannot fill it.
		s.cfg.Logger.Warn("e2e header failed authentication")
		return
	}
	// SECURITY FIX: CWE-863 the files rule is enforced for the
	// authenticated sender; on a relayed stream the packet filter only saw
	// the last relay.
	if !s.cfg.AllowFile(peer.Name) {
		clear(plain)
		s.cfg.Logger.Warn("e2e file refused by files rule", "peer", peer.Name)
		_ = (&replyChannel{key: &keys.reply}).write(idleConn{Conn: c, idle: s.cfg.IdleTimeout}, reply{Status: statusRejected})
		return
	}
	if s.seen("k:"+hex.EncodeToString(hello.sender[:]), hello.ephemeral) {
		clear(plain)
		s.cfg.Logger.Warn("e2e hello replay refused", "peer", peer.Name)
		return
	}
	h, err := decodeHeader(plain)
	clear(plain)
	if err != nil {
		return
	}
	replyOut := &replyChannel{key: &keys.reply}
	w := idleConn{Conn: c, idle: s.cfg.IdleTimeout}
	if err := h.validate(s.cfg.MaxSize); err != nil {
		st := statusError
		if errors.Is(err, ErrTooLarge) {
			st = statusTooLarge
		}
		_ = replyOut.write(w, reply{Status: st})
		return
	}
	name, err := filesend.SanitizeName(h.Name)
	if err != nil {
		_ = replyOut.write(w, reply{Status: statusBadName})
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		_ = replyOut.write(w, reply{Status: statusBusy})
		return
	}
	key := partialKey(hello.sender, h)
	if !s.lock(key) {
		_ = replyOut.write(w, reply{Status: statusBusy})
		return
	}
	defer s.unlock(key)
	partPath := filepath.Join(s.partialDir, key+".part")
	part, have, err := openPartial(partPath)
	if err != nil {
		_ = replyOut.write(w, reply{Status: statusError})
		return
	}
	defer func() {
		if part != nil {
			_ = part.Close()
		}
	}()
	total := numChunks(h.Size)
	offset := uint64(have / ChunkSize)
	if offset >= total {
		offset = total - 1
	}
	offer := Offer{From: peer.Name, Name: name, Size: h.Size, Executable: filesend.IsExecutable(name),
		Resume: offset > 0, Stripped: h.Stripped}
	reg := s.cfg.Registry.start(TransferView{Peer: peer.Name, Name: name, Size: h.Size, State: StateWaiting})
	accepted, err := s.cfg.Ask(ctx, offer)
	if err != nil || !accepted || !s.stillAllowed(hello.sender, peer.Name) {
		_ = replyOut.write(w, reply{Status: statusRejected})
		reg.finish(ErrRejected)
		return
	}
	if err := part.Truncate(int64(offset) * ChunkSize); err != nil {
		_ = replyOut.write(w, reply{Status: statusError})
		reg.finish(err)
		return
	}
	if _, err := part.Seek(int64(offset)*ChunkSize, io.SeekStart); err != nil {
		_ = replyOut.write(w, reply{Status: statusError})
		reg.finish(err)
		return
	}
	if err := replyOut.write(w, reply{Status: statusAccept, Offset: offset}); err != nil {
		reg.finish(err)
		return
	}
	resumed := int64(offset) * ChunkSize
	reg.set(func(v *TransferView) { v.State = StateReceiving; v.Resumed = resumed })
	id, _ := hex.DecodeString(h.ID)
	rec := make([]byte, RecordSize)
	in := br
	written := resumed
	for i := offset; i < total; i++ {
		if _, err := io.ReadFull(in, rec); err != nil {
			reg.finish(err)
			return // keep the partial file for a resume
		}
		final := i == total-1
		p, err := open(&keys.data, domainData, i, rec, chunkAD(id, final))
		if err != nil {
			_ = replyOut.write(w, reply{Status: statusIntegrity})
			_ = part.Close()
			part = nil
			_ = os.Remove(partPath)
			reg.finish(ErrIntegrity)
			return
		}
		n := chunkLen(h.Size, i)
		if _, err := part.Write(p[:n]); err != nil {
			clear(p)
			_ = replyOut.write(w, reply{Status: statusError})
			reg.finish(err)
			return
		}
		clear(p)
		written += int64(n)
		reg.progress(written)
	}
	if err := part.Sync(); err != nil {
		_ = replyOut.write(w, reply{Status: statusError})
		reg.finish(err)
		return
	}
	digest, err := fileDigest(part)
	_ = part.Close()
	part = nil
	if err != nil || digest != h.SHA256 {
		_ = os.Remove(partPath)
		_ = replyOut.write(w, reply{Status: statusIntegrity})
		reg.finish(ErrIntegrity)
		return
	}
	// SECURITY FIX: CWE-863 a transfer can outlive the rule: the packet
	// filter sees only the last relay, so it does not stop a relayed stream
	// when the sender loses its rule or membership. Re-check before the file
	// becomes visible and drop the data so a later resume cannot reuse it.
	if !s.stillAllowed(hello.sender, peer.Name) {
		_ = os.Remove(partPath)
		s.cfg.Logger.Warn("e2e file dropped: files rule removed during transfer", "peer", peer.Name)
		_ = replyOut.write(w, reply{Status: statusRejected})
		reg.finish(ErrRejected)
		return
	}
	final, err := s.place(partPath, name)
	if err != nil {
		_ = replyOut.write(w, reply{Status: statusError})
		reg.finish(err)
		return
	}
	quarantined := filesend.MarkQuarantine(final, "openscale:"+peer.Name) == nil
	_ = replyOut.write(w, reply{Status: statusOK, Name: filepath.Base(final)})
	reg.set(func(v *TransferView) {
		v.Name = filepath.Base(final)
		v.Quarantined = quarantined
		v.Stripped = h.Stripped
	})
	reg.finish(nil)
	s.cfg.Logger.Info("e2e file received", "peer", peer.Name, "bytes", h.Size, "resumed", resumed)
	if s.cfg.OnReceived != nil {
		s.cfg.OnReceived(Received{From: peer.Name, Name: filepath.Base(final), Path: final, Size: h.Size,
			Resumed: resumed, Executable: offer.Executable, Stripped: h.Stripped, Quarantined: quarantined})
	}
}

// stillAllowed re-checks membership and the files rule after approval: the
// signed document may have changed while the offer waited.
func (s *Server) stillAllowed(sender Key, name string) bool {
	p, ok := s.cfg.Directory.ByKey(sender)
	return ok && p.Name == name && s.cfg.AllowFile(name)
}

func partialKey(sender Key, h header) string {
	sum := sha256.Sum256([]byte(hex.EncodeToString(sender[:]) + "|" + h.ID + "|" + h.SHA256 + "|" + strconv.FormatInt(h.Size, 10)))
	return hex.EncodeToString(sum[:16])
}

func (s *Server) lock(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks[k] {
		return false
	}
	s.locks[k] = true
	return true
}

func (s *Server) unlock(k string) {
	s.mu.Lock()
	delete(s.locks, k)
	s.mu.Unlock()
}

func openPartial(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, errors.New("partial file is not regular")
	}
	return f, st.Size(), nil
}

func fileDigest(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// place moves a verified file into quarantine under a unique name.
func (s *Server) place(partPath, name string) (string, error) {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 0; i <= maxCollisions; i++ {
		cand := name
		if i > 0 {
			cand = fmt.Sprintf("%s (%d)%s", base, i, ext)
		}
		dst := filepath.Join(s.quarantine, cand)
		if _, err := os.Lstat(dst); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		// Link-free exclusive creation guards against a race with another
		// transfer choosing the same name.
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return "", err
		}
		_ = f.Close()
		if err := os.Rename(partPath, dst); err != nil {
			_ = os.Remove(dst)
			return "", err
		}
		return dst, nil
	}
	return "", errors.New("çok fazla aynı adlı dosya")
}

func (s *Server) cleanupPartials() {
	entries, err := os.ReadDir(s.partialDir)
	if err != nil {
		return
	}
	now := s.cfg.Now()
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if now.Sub(info.ModTime()) > s.cfg.PartialTTL {
			_ = os.Remove(filepath.Join(s.partialDir, e.Name()))
		}
	}
}

// handleRelay forwards an onion stream to the next hop.
func (s *Server) handleRelay(ctx context.Context, c net.Conn, br *bufio.Reader) {
	if !s.cfg.Relay {
		return
	}
	remote, ok := addrOf(c.RemoteAddr())
	if !ok {
		return
	}
	if _, ok := s.cfg.Directory.ByAddr(remote.Addr()); !ok {
		s.cfg.Logger.Warn("relay request from non-member refused")
		return
	}
	e, ct, err := readLayer(br)
	if err != nil {
		return
	}
	p, err := peelLayer(s.cfg.Identity, e, ct)
	if err != nil {
		return
	}
	// SECURITY FIX: CWE-400 replay entries are stored after the layer
	// authenticated and are counted per previous hop.
	if s.seen("a:"+remote.Addr().String(), e) {
		return
	}
	if _, ok := s.cfg.Directory.ByAddr(p.next.Addr()); !ok {
		s.cfg.Logger.Warn("relay target is not a member")
		return
	}
	if s.cfg.RelayPort != 0 && p.next.Port() != s.cfg.RelayPort {
		return
	}
	select {
	case s.relaySem <- struct{}{}:
		defer func() { <-s.relaySem }()
	default:
		return
	}
	dctx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	next, err := s.cfg.Dial(dctx, p.next)
	cancel()
	if err != nil {
		return
	}
	defer next.Close()
	if len(p.inner) > 0 {
		if _, err := next.Write(p.inner); err != nil {
			return
		}
	}
	// Bytes in both directions are bounded by the largest file plus
	// protocol overhead.
	limit := s.cfg.MaxSize + s.cfg.MaxSize/ChunkSize*16 + 1<<20
	a := idleConn{Conn: c, idle: s.cfg.IdleTimeout}
	b := idleConn{Conn: next, idle: s.cfg.IdleTimeout}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, io.LimitReader(br, limit))
		closeWrite(next)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, io.LimitReader(b, 1<<20))
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func addrOf(a net.Addr) (netip.AddrPort, bool) {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := t.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
