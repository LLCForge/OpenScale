// Package filesend transfers files between OpenScale devices over a TCP
// connection inside the tunnel.
//
// The sender offers a file name, size and SHA-256 digest. The receiver asks
// its Accept callback, then answers with the offset to resume from (bytes it
// already holds from an interrupted transfer of the same file by the same
// peer). The sender streams the remaining bytes; the receiver verifies the
// digest of the complete file, deletes it on mismatch and otherwise moves it
// into the inbox under a unique, sanitized name.
//
// Wire protocol: control messages are frames of a 4-byte big-endian length
// followed by JSON (at most 4 KiB). File bytes are sent raw after the
// "accept" reply. The receiver never closes before the sender, which avoids
// TCP resets discarding the final reply.
package filesend

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion = 1
	maxFrameLen     = 4 << 10
	partialDirName  = ".openscale-partial"
	partialSuffix   = ".part"
	maxCollisions   = 9999

	defaultMaxSize       = int64(8) << 30 // 8 GiB
	defaultMaxConcurrent = 4
	maxConnections       = 32
	defaultPartialTTL    = 48 * time.Hour
	defaultIdleTimeout   = 60 * time.Second
	headerTimeout        = 30 * time.Second
	acceptWaitTimeout    = 5 * time.Minute
	finalReplyTimeout    = 10 * time.Minute
	lingerTimeout        = 5 * time.Second
	dialTimeout          = 10 * time.Second
)

// Status values exchanged in replies.
const (
	statusAccept    = "accept"
	statusOK        = "ok"
	statusRejected  = "rejected"
	statusTooLarge  = "too_large"
	statusBusy      = "busy"
	statusBadName   = "bad_name"
	statusBadOffer  = "bad_offer"
	statusIntegrity = "integrity"
	statusError     = "error"
)

var (
	// ErrRejected means the receiver declined the file.
	ErrRejected = errors.New("alıcı dosyayı kabul etmedi")
	// ErrTooLarge means the file exceeds the receiver's size limit.
	ErrTooLarge = errors.New("dosya alıcının boyut sınırını aşıyor")
	// ErrBusy means the receiver is handling too many transfers.
	ErrBusy = errors.New("alıcı şu anda meşgul, daha sonra yeniden deneyin")
	// ErrIntegrity means the received bytes did not match the digest; the
	// receiver deleted them and a retry starts from the beginning.
	ErrIntegrity = errors.New("bütünlük doğrulaması başarısız, dosya silindi")
	// ErrRemote is returned for other receiver-side failures.
	ErrRemote = errors.New("alıcı tarafında hata oluştu")
	// ErrProtocol is returned for malformed protocol messages.
	ErrProtocol = errors.New("geçersiz aktarım protokolü mesajı")
	// ErrInvalidListenAddr is returned for a missing or wildcard listen address.
	ErrInvalidListenAddr = errors.New("dinleme adresi belirli bir tünel adresi olmalı")
)

type offer struct {
	V      int    `json:"v"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type reply struct {
	Status string `json:"status"`
	Offset int64  `json:"offset,omitempty"`
	Name   string `json:"name,omitempty"`
}

// Received describes a file stored in the inbox.
type Received struct {
	From       netip.Addr
	Name       string // final base name inside the inbox
	Path       string // absolute path of the stored file
	Size       int64
	Resumed    int64 // bytes reused from an earlier interrupted transfer
	Executable bool  // the extension may run code when opened (#133)
	// Quarantined reports that the file carries the operating system's
	// quarantine mark (MarkQuarantine). It is false on file systems that
	// cannot store the mark; the file is still delivered.
	Quarantined bool
}

// Config configures a Server.
type Config struct {
	// ListenAddr is the device's tunnel address and port; wildcard
	// addresses are rejected.
	ListenAddr netip.AddrPort
	// InboxDir receives completed files; it is created with owner-only
	// permissions. Interrupted transfers are kept in a hidden
	// subdirectory until they complete or expire.
	InboxDir string
	// Accept decides whether to take a file from a peer (identified by its
	// tunnel source address). name is already sanitized. Required.
	Accept func(from netip.Addr, name string, size int64) bool
	// OnReceived, if set, is called after a file is verified and stored.
	OnReceived func(Received)
	// MaxSize caps a single file (default 8 GiB).
	MaxSize int64
	// MaxConcurrent caps simultaneous transfers (default 4).
	MaxConcurrent int
	// PartialTTL removes interrupted transfers older than this (default 48h).
	PartialTTL time.Duration
	// IdleTimeout aborts a transfer that makes no progress (default 60s).
	IdleTimeout time.Duration
	// Logger receives structured logs; nil discards them.
	Logger *slog.Logger
}

// Server receives files.
type Server struct {
	cfg        Config
	inbox      string
	partialDir string
	log        *slog.Logger
	slots      chan struct{}
	mark       func(path, origin string) error

	mu      sync.Mutex
	ln      net.Listener
	conns   map[net.Conn]struct{}
	active  map[string]bool // partial keys being written
	closed  bool
	wg      sync.WaitGroup
	placeMu sync.Mutex // serializes choosing final names
}

// NewServer validates cfg and prepares the inbox.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Accept == nil {
		return nil, errors.New("filesend: Accept geri çağrısı zorunlu")
	}
	if cfg.InboxDir == "" {
		return nil, errors.New("filesend: gelen kutusu dizini zorunlu")
	}
	inbox, err := filepath.Abs(cfg.InboxDir)
	if err != nil {
		return nil, fmt.Errorf("filesend: gelen kutusu yolu: %w", err)
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = defaultMaxSize
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	if cfg.PartialTTL <= 0 {
		cfg.PartialTTL = defaultPartialTTL
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	partialDir := filepath.Join(inbox, partialDirName)
	if err := os.MkdirAll(partialDir, 0o700); err != nil {
		return nil, fmt.Errorf("filesend: gelen kutusu oluşturulamadı: %w", err)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg:        cfg,
		inbox:      inbox,
		partialDir: partialDir,
		log:        log,
		slots:      make(chan struct{}, cfg.MaxConcurrent),
		mark:       MarkQuarantine,
		conns:      make(map[net.Conn]struct{}),
		active:     make(map[string]bool),
	}, nil
}

// ValidateListenAddr rejects invalid and wildcard listen addresses.
func ValidateListenAddr(a netip.AddrPort) error {
	if !a.IsValid() || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
		return ErrInvalidListenAddr
	}
	return nil
}

// ListenAndServe listens on cfg.ListenAddr and serves until ctx ends or
// Close is called.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := ValidateListenAddr(s.cfg.ListenAddr); err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr.String())
	if err != nil {
		return fmt.Errorf("filesend: dinlenemedi: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections from ln until ctx ends or Close is called. It
// takes ownership of ln.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return net.ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	s.cleanupPartials()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
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
			s.handle(c)
		}()
	}
}

// Close stops the listener, aborts transfers (their partial data is kept
// for resuming) and waits for handlers to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}
	s.closed = true
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= maxConnections {
		return false
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

func (s *Server) lockKey(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[key] {
		return false
	}
	s.active[key] = true
	return true
}

func (s *Server) unlockKey(key string) {
	s.mu.Lock()
	delete(s.active, key)
	s.mu.Unlock()
}

func (s *Server) handle(c net.Conn) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	from := ta.AddrPort().Addr().Unmap()

	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	var o offer
	if err := readFrame(c, &o); err != nil {
		return
	}
	if o.V != protocolVersion || o.Size < 0 || !validDigest(o.SHA256) {
		s.finish(c, reply{Status: statusBadOffer})
		return
	}
	name, err := SanitizeName(o.Name)
	if err != nil {
		s.log.Info("dosya reddedildi: güvensiz ad")
		s.finish(c, reply{Status: statusBadName})
		return
	}
	if o.Size > s.cfg.MaxSize {
		s.finish(c, reply{Status: statusTooLarge})
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.finish(c, reply{Status: statusBusy})
		return
	}
	// The Accept callback may wait for the owner's decision.
	_ = c.SetDeadline(time.Time{})
	if !s.cfg.Accept(from, name, o.Size) {
		s.log.Info("dosya reddedildi: alıcı kabul etmedi", "size", o.Size)
		_ = c.SetDeadline(time.Now().Add(headerTimeout))
		s.finish(c, reply{Status: statusRejected})
		return
	}

	key := partialKey(from, o)
	if !s.lockKey(key) {
		_ = c.SetDeadline(time.Now().Add(headerTimeout))
		s.finish(c, reply{Status: statusBusy})
		return
	}
	defer s.unlockKey(key)

	partPath := filepath.Join(s.partialDir, key+partialSuffix)
	f, offset, err := openPartial(partPath, o.Size)
	if err != nil {
		s.log.Error("geçici dosya açılamadı", "err", err)
		_ = c.SetDeadline(time.Now().Add(headerTimeout))
		s.finish(c, reply{Status: statusError})
		return
	}
	keepPartial := true
	defer func() {
		_ = f.Close()
		if !keepPartial {
			_ = os.Remove(partPath)
		}
	}()

	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	if err := writeFrame(c, reply{Status: statusAccept, Offset: offset}); err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	remaining := o.Size - offset
	if _, err := io.CopyN(f, &idleReader{c: c, idle: s.cfg.IdleTimeout}, remaining); err != nil {
		// Keep what arrived so the sender can resume later.
		_ = f.Sync()
		if !errors.Is(err, io.EOF) && !isNetErr(err) {
			s.log.Error("dosya yazılamadı", "err", err)
			_ = c.SetDeadline(time.Now().Add(headerTimeout))
			s.finish(c, reply{Status: statusError})
		}
		return
	}
	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	if err := f.Sync(); err != nil {
		s.finish(c, reply{Status: statusError})
		return
	}
	sum, err := fileDigest(f)
	if err != nil {
		s.finish(c, reply{Status: statusError})
		return
	}
	if sum != strings.ToLower(o.SHA256) {
		keepPartial = false
		s.log.Warn("bütünlük doğrulaması başarısız, dosya silindi")
		s.finish(c, reply{Status: statusIntegrity})
		return
	}
	if err := f.Close(); err != nil {
		s.finish(c, reply{Status: statusError})
		return
	}
	finalPath, err := s.place(partPath, name)
	if err != nil {
		s.log.Error("dosya gelen kutusuna taşınamadı", "err", err)
		s.finish(c, reply{Status: statusError})
		return
	}
	keepPartial = false
	// SECURITY FIX: CWE-693 every platform labels the file as coming from
	// another device (Mark-of-the-Web, com.apple.quarantine, Linux xattrs),
	// not only Windows.
	quarantined := s.mark(finalPath, "openscale:"+from.String()) == nil
	if !quarantined {
		s.log.Warn("alınan dosyaya karantina işareti konamadı")
	}
	finalName := filepath.Base(finalPath)
	s.log.Info("dosya alındı", "name", finalName, "size", o.Size)
	s.finish(c, reply{Status: statusOK, Name: finalName})
	if s.cfg.OnReceived != nil {
		s.cfg.OnReceived(Received{
			From: from, Name: finalName, Path: finalPath, Size: o.Size,
			Resumed: offset, Executable: IsExecutable(finalName), Quarantined: quarantined,
		})
	}
}

// finish sends the final reply and waits for the sender to close first.
func (s *Server) finish(c net.Conn, r reply) {
	_ = c.SetWriteDeadline(time.Now().Add(headerTimeout))
	if err := writeFrame(c, r); err != nil {
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(lingerTimeout))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 1<<20))
}

// partialKey binds an interrupted transfer to the sending device and the
// exact file, so one peer can never append to another peer's data.
func partialKey(from netip.Addr, o offer) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%s", from.String(), o.Name, o.Size, strings.ToLower(o.SHA256))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func openPartial(path string, size int64) (*os.File, int64, error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("geçici yol normal bir dosya değil")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	offset := fi.Size()
	if offset > size {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, 0, err
		}
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, offset, nil
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

// place moves the verified partial file into the inbox under name, adding
// " (n)" before the extension when the name is taken.
func (s *Server) place(partPath, name string) (string, error) {
	s.placeMu.Lock()
	defer s.placeMu.Unlock()
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if stem == "" {
		stem, ext = name, ""
	}
	for i := 0; i <= maxCollisions; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		dst := filepath.Join(s.inbox, candidate)
		// Reserve the name atomically, then replace the empty placeholder.
		ph, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_ = ph.Close()
		if err := os.Rename(partPath, dst); err != nil {
			_ = os.Remove(dst)
			return "", err
		}
		return dst, nil
	}
	return "", errors.New("uygun bir dosya adı bulunamadı")
}

// cleanupPartials removes interrupted transfers older than PartialTTL.
func (s *Server) cleanupPartials() {
	entries, err := os.ReadDir(s.partialDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-s.cfg.PartialTTL)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), partialSuffix) {
			continue
		}
		key := strings.TrimSuffix(e.Name(), partialSuffix)
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if !s.lockKey(key) {
			continue
		}
		_ = os.Remove(filepath.Join(s.partialDir, e.Name()))
		s.unlockKey(key)
	}
}

// CleanupPartials removes expired interrupted transfers; the service may
// call it periodically.
func (s *Server) CleanupPartials() { s.cleanupPartials() }

type idleReader struct {
	c    net.Conn
	idle time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(r.idle))
	return r.c.Read(p)
}

func isNetErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, net.ErrClosed)
}

func validDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrameLen {
		return ErrProtocol
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrameLen {
		return ErrProtocol
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrProtocol
	}
	return nil
}

// SendOptions customizes Send.
type SendOptions struct {
	// Name overrides the offered file name (default: the path's base name).
	Name string
	// Progress, if set, is called as bytes are sent; done includes the
	// resumed offset.
	Progress func(done, total int64)
	// TempDir receives the owner-only stripped copy SendWithoutMetadata
	// sends; empty uses the source file's folder. The system temporary
	// directory is never used (ADR-0008).
	TempDir string
}

// SendResult describes a completed transfer.
type SendResult struct {
	// SavedName is the name the receiver stored the file under.
	SavedName string
	// Resumed is the number of bytes the receiver already had.
	Resumed int64
	// Sent is the number of bytes sent in this attempt.
	Sent int64
}

// Send offers the file at path to the receiver at addr and transfers it,
// resuming an earlier interrupted attempt when possible.
func Send(ctx context.Context, addr netip.AddrPort, path string, opts *SendOptions) (SendResult, error) {
	if opts == nil {
		opts = &SendOptions{}
	}
	f, err := os.Open(path)
	if err != nil {
		return SendResult{}, fmt.Errorf("dosya açılamadı: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return SendResult{}, fmt.Errorf("dosya okunamadı: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return SendResult{}, errors.New("yalnızca normal dosyalar gönderilebilir")
	}
	name := opts.Name
	if name == "" {
		name = filepath.Base(path)
	}
	if _, err := SanitizeName(name); err != nil {
		return SendResult{}, err
	}
	sum, err := fileDigest(f)
	if err != nil {
		return SendResult{}, fmt.Errorf("dosya özeti hesaplanamadı: %w", err)
	}
	size := fi.Size()

	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return SendResult{}, fmt.Errorf("alıcıya bağlanılamadı: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(headerTimeout))
	if err := writeFrame(conn, offer{V: protocolVersion, Name: name, Size: size, SHA256: sum}); err != nil {
		return SendResult{}, ctxErr(ctx, fmt.Errorf("teklif gönderilemedi: %w", err))
	}
	_ = conn.SetDeadline(time.Now().Add(acceptWaitTimeout))
	var r reply
	if err := readFrame(conn, &r); err != nil {
		return SendResult{}, ctxErr(ctx, fmt.Errorf("alıcı yanıt vermedi: %w", err))
	}
	if r.Status != statusAccept {
		return SendResult{}, statusErr(r.Status)
	}
	if r.Offset < 0 || r.Offset > size {
		return SendResult{}, ErrProtocol
	}
	if _, err := f.Seek(r.Offset, io.SeekStart); err != nil {
		return SendResult{}, err
	}
	_ = conn.SetDeadline(time.Time{})
	var src io.Reader = io.LimitReader(f, size-r.Offset)
	if opts.Progress != nil {
		src = &progressReader{r: src, done: r.Offset, total: size, fn: opts.Progress}
	}
	sent, err := io.Copy(&idleWriter{c: conn, idle: defaultIdleTimeout}, src)
	if err != nil {
		return SendResult{Resumed: r.Offset, Sent: sent}, ctxErr(ctx, fmt.Errorf("aktarım kesildi: %w", err))
	}
	if sent != size-r.Offset {
		return SendResult{Resumed: r.Offset, Sent: sent}, errors.New("dosya gönderim sırasında değişti")
	}
	// The receiver re-reads the whole file to verify it; allow time for that.
	_ = conn.SetReadDeadline(time.Now().Add(finalReplyTimeout))
	var final reply
	if err := readFrame(conn, &final); err != nil {
		return SendResult{Resumed: r.Offset, Sent: sent}, ctxErr(ctx, fmt.Errorf("alıcı sonucu bildirmedi: %w", err))
	}
	if final.Status != statusOK {
		return SendResult{Resumed: r.Offset, Sent: sent}, statusErr(final.Status)
	}
	return SendResult{SavedName: final.Name, Resumed: r.Offset, Sent: sent}, nil
}

func statusErr(status string) error {
	switch status {
	case statusRejected:
		return ErrRejected
	case statusTooLarge:
		return ErrTooLarge
	case statusBusy:
		return ErrBusy
	case statusBadName:
		return ErrBadName
	case statusIntegrity:
		return ErrIntegrity
	case statusBadOffer:
		return ErrProtocol
	default:
		return ErrRemote
	}
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type idleWriter struct {
	c    net.Conn
	idle time.Duration
}

func (w *idleWriter) Write(p []byte) (int, error) {
	_ = w.c.SetWriteDeadline(time.Now().Add(w.idle))
	return w.c.Write(p)
}

type progressReader struct {
	r     io.Reader
	done  int64
	total int64
	fn    func(done, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.done += int64(n)
		p.fn(p.done, p.total)
	}
	return n, err
}
