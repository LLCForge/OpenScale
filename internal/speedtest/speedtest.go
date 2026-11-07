// Package speedtest measures TCP throughput between two OpenScale devices
// inside the tunnel. A test runs for a fixed duration in one direction:
// download (server sends) or upload (client sends). The server runs at most
// one test at a time and enforces duration and byte limits.
//
// Wire protocol (all integers big endian):
//
//	request  (client -> server): "OSST" | version u8 | direction u8 | duration_ms u32
//	response (server -> client): status u8
//	download: server streams bytes until the duration ends, then closes
//	upload:   client streams frames (len u32 | payload), ends with len 0;
//	          server replies bytes u64 | nanos u64
package speedtest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Direction selects which side sends data.
type Direction uint8

const (
	// Download measures server -> client throughput.
	Download Direction = 1
	// Upload measures client -> server throughput.
	Upload Direction = 2
)

func (d Direction) String() string {
	switch d {
	case Download:
		return "indirme"
	case Upload:
		return "yükleme"
	default:
		return "bilinmeyen"
	}
}

const (
	protocolVersion = 1
	requestLen      = 10
	resultLen       = 16
	bufSize         = 64 << 10
	maxConns        = 16
	frameHdrLen     = 4

	statusOK       = 0
	statusBusy     = 1
	statusBad      = 2
	statusDenied   = 3
	statusTooLong  = 4
	headerTimeout  = 5 * time.Second
	resultGrace    = 3 * time.Second
	dialTimeout    = 10 * time.Second
	minDuration    = 100 * time.Millisecond
	hardMaxDur     = 60 * time.Second
	defaultMaxDur  = 10 * time.Second
	defaultMaxSize = int64(4) << 30 // 4 GiB per test
	// DefaultDuration is the recommended test length.
	DefaultDuration = 5 * time.Second
)

var magic = [4]byte{'O', 'S', 'S', 'T'}

var (
	// ErrBusy means the server is already running a test.
	ErrBusy = errors.New("karşı cihaz şu anda başka bir hız testi yürütüyor")
	// ErrDenied means the server refused this peer.
	ErrDenied = errors.New("karşı cihaz hız testine izin vermedi")
	// ErrBadRequest means the server rejected the request parameters.
	ErrBadRequest = errors.New("karşı cihaz hız testi isteğini geçersiz buldu")
	// ErrTooLong means the requested duration exceeds the server's limit.
	ErrTooLong = errors.New("istenen test süresi karşı cihazın sınırını aşıyor")
	// ErrInvalidListenAddr is returned for a missing or wildcard listen address.
	ErrInvalidListenAddr = errors.New("dinleme adresi belirli bir tünel adresi olmalı")
	// ErrLimitReached means the server stopped the test at its byte limit.
	ErrLimitReached = errors.New("test karşı cihazın veri sınırında durduruldu")
)

// Result is the outcome of one test.
type Result struct {
	Direction Direction
	Bytes     int64
	Elapsed   time.Duration
}

// BitsPerSecond returns the measured throughput.
func (r Result) BitsPerSecond() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Bytes) * 8 / r.Elapsed.Seconds()
}

// Mbps returns the measured throughput in megabits per second.
func (r Result) Mbps() float64 { return r.BitsPerSecond() / 1e6 }

// Config configures a Server.
type Config struct {
	// ListenAddr is the device's tunnel address and port. It must be a
	// specific address; wildcard addresses are rejected.
	ListenAddr netip.AddrPort
	// Allow decides whether a peer (by tunnel source address) may run a
	// test. It is required; the caller maps the address to a device and
	// checks the signed document's rules.
	Allow func(from netip.Addr) bool
	// MaxDuration caps a single test (default 10s, at most 60s).
	MaxDuration time.Duration
	// MaxBytes caps the bytes transferred in a single test (default 4 GiB).
	MaxBytes int64
	// Logger receives structured logs; nil discards them.
	Logger *slog.Logger
}

// Server answers speed test requests.
type Server struct {
	cfg  Config
	log  *slog.Logger
	busy atomic.Bool
	buf  []byte

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// NewServer validates cfg and returns a server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Allow == nil {
		return nil, errors.New("speedtest: Allow geri çağrısı zorunlu")
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = defaultMaxDur
	}
	if cfg.MaxDuration > hardMaxDur {
		cfg.MaxDuration = hardMaxDur
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxSize
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	buf := make([]byte, bufSize)
	// Random payload keeps any compression on the path from inflating results.
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("speedtest: rastgele veri üretilemedi: %w", err)
	}
	return &Server{cfg: cfg, log: log, buf: buf, conns: make(map[net.Conn]struct{})}, nil
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
		return fmt.Errorf("speedtest: dinlenemedi: %w", err)
	}
	return s.Serve(ctx, ln)
}

// ValidateListenAddr rejects invalid and wildcard listen addresses.
func ValidateListenAddr(a netip.AddrPort) error {
	if !a.IsValid() || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
		return ErrInvalidListenAddr
	}
	return nil
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

// Close stops the listener, aborts running tests and waits for them.
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
	if s.closed || len(s.conns) >= maxConns {
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

func remoteAddr(c net.Conn) (netip.Addr, bool) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	return ta.AddrPort().Addr().Unmap(), true
}

func (s *Server) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(headerTimeout))
	var req [requestLen]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	from, ok := remoteAddr(c)
	if !ok || !s.cfg.Allow(from) {
		s.log.Info("hız testi reddedildi: izin yok")
		s.log.Debug("hız testi reddedildi", "from", from.String())
		reply(c, statusDenied)
		return
	}
	dir := Direction(req[5])
	dur := time.Duration(binary.BigEndian.Uint32(req[6:])) * time.Millisecond
	if [4]byte(req[:4]) != magic || req[4] != protocolVersion || (dir != Download && dir != Upload) || dur < minDuration {
		reply(c, statusBad)
		return
	}
	if dur > s.cfg.MaxDuration {
		reply(c, statusTooLong)
		return
	}
	if !s.busy.CompareAndSwap(false, true) {
		reply(c, statusBusy)
		return
	}
	defer s.busy.Store(false)
	if _, err := c.Write([]byte{statusOK}); err != nil {
		return
	}
	switch dir {
	case Download:
		s.serveDownload(c, dur)
	case Upload:
		s.serveUpload(c, dur)
	}
}

func (s *Server) serveDownload(c net.Conn, dur time.Duration) {
	end := time.Now().Add(dur)
	_ = c.SetDeadline(end.Add(resultGrace))
	var sent int64
	for time.Now().Before(end) && sent < s.cfg.MaxBytes {
		chunk := s.buf
		if rem := s.cfg.MaxBytes - sent; rem < int64(len(chunk)) {
			chunk = chunk[:rem]
		}
		n, err := c.Write(chunk)
		sent += int64(n)
		if err != nil {
			return
		}
	}
	lingerClose(c)
}

// reply sends a final status byte and closes gracefully.
func reply(c net.Conn, status byte) {
	_, _ = c.Write([]byte{status})
	lingerClose(c)
}

// lingerClose half-closes c and waits briefly for the peer to close first.
// Closing a socket that still has unread or in-flight data makes some
// stacks (notably Windows) send a reset that discards the final reply.
func lingerClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(resultGrace))
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 1<<20))
}

func (s *Server) serveUpload(c net.Conn, dur time.Duration) {
	deadline := time.Now().Add(dur + resultGrace)
	_ = c.SetReadDeadline(deadline)
	buf := make([]byte, bufSize)
	var got int64
	var start time.Time
	for {
		var hdr [frameHdrLen]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		if start.IsZero() {
			start = time.Now()
		}
		n := int64(binary.BigEndian.Uint32(hdr[:]))
		if n == 0 {
			break
		}
		if n > bufSize || got+n > s.cfg.MaxBytes {
			// Protocol violation or byte limit: stop without a result.
			return
		}
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return
		}
		got += n
	}
	var elapsed time.Duration
	if !start.IsZero() {
		elapsed = time.Since(start)
	}
	var res [resultLen]byte
	binary.BigEndian.PutUint64(res[:8], uint64(got))
	binary.BigEndian.PutUint64(res[8:], uint64(elapsed))
	_ = c.SetWriteDeadline(time.Now().Add(resultGrace))
	_, _ = c.Write(res[:])
	lingerClose(c)
}

// Run performs one test against addr. duration is clamped to at least
// 100ms; zero selects DefaultDuration.
func Run(ctx context.Context, addr netip.AddrPort, dir Direction, duration time.Duration) (Result, error) {
	if dir != Download && dir != Upload {
		return Result{}, ErrBadRequest
	}
	if duration == 0 {
		duration = DefaultDuration
	}
	if duration < minDuration || duration > hardMaxDur {
		return Result{}, ErrBadRequest
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return Result{}, fmt.Errorf("karşı cihaza bağlanılamadı: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var req [requestLen]byte
	copy(req[:4], magic[:])
	req[4] = protocolVersion
	req[5] = byte(dir)
	binary.BigEndian.PutUint32(req[6:], uint32(duration/time.Millisecond))
	_ = conn.SetDeadline(time.Now().Add(headerTimeout))
	if _, err := conn.Write(req[:]); err != nil {
		return Result{}, ctxErr(ctx, fmt.Errorf("istek gönderilemedi: %w", err))
	}
	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return Result{}, ctxErr(ctx, fmt.Errorf("yanıt alınamadı: %w", err))
	}
	switch status[0] {
	case statusOK:
	case statusBusy:
		return Result{}, ErrBusy
	case statusDenied:
		return Result{}, ErrDenied
	case statusTooLong:
		return Result{}, ErrTooLong
	default:
		return Result{}, ErrBadRequest
	}
	if dir == Download {
		return runDownload(ctx, conn, duration)
	}
	return runUpload(ctx, conn, duration)
}

func runDownload(ctx context.Context, conn net.Conn, duration time.Duration) (Result, error) {
	_ = conn.SetDeadline(time.Now().Add(duration + 2*resultGrace))
	buf := make([]byte, bufSize)
	var got int64
	var start time.Time
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if start.IsZero() {
				start = time.Now()
			}
			got += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Result{}, ctxErr(ctx, fmt.Errorf("veri alınamadı: %w", err))
		}
	}
	res := Result{Direction: Download, Bytes: got}
	if !start.IsZero() {
		res.Elapsed = time.Since(start)
	}
	return res, nil
}

func runUpload(ctx context.Context, conn net.Conn, duration time.Duration) (Result, error) {
	// Each frame is a 4-byte payload length followed by the payload; a
	// zero-length frame ends the upload. Framing lets the client keep its
	// write side open, so the server never closes first with data in flight.
	frame := make([]byte, frameHdrLen+bufSize)
	if _, err := rand.Read(frame[frameHdrLen:]); err != nil {
		return Result{}, err
	}
	binary.BigEndian.PutUint32(frame[:frameHdrLen], bufSize)
	end := time.Now().Add(duration)
	_ = conn.SetWriteDeadline(end.Add(resultGrace))
	var sent int64
	for time.Now().Before(end) {
		if _, err := conn.Write(frame); err != nil {
			return Result{Direction: Upload, Bytes: sent}, ctxErr(ctx, ErrLimitReached)
		}
		sent += bufSize
	}
	if _, err := conn.Write(make([]byte, frameHdrLen)); err != nil {
		return Result{Direction: Upload, Bytes: sent}, ctxErr(ctx, ErrLimitReached)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * resultGrace))
	var res [resultLen]byte
	if _, err := io.ReadFull(conn, res[:]); err != nil {
		return Result{}, ctxErr(ctx, fmt.Errorf("sonuç alınamadı: %w", err))
	}
	return Result{
		Direction: Upload,
		Bytes:     int64(binary.BigEndian.Uint64(res[:8])),
		Elapsed:   time.Duration(binary.BigEndian.Uint64(res[8:])),
	}, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
