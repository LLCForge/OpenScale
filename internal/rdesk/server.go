package rdesk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"image"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// Decision is the answer of an AuthorizeFunc.
type Decision struct {
	// Allowed grants the requested mode.
	Allowed bool
	// Unattended lets the session start without Consent.
	Unattended bool
	// Peer names the remote device for the consent prompt, the indicator
	// and the logs (the device name, not its address).
	Peer string
	// Reason is logged when access is denied.
	Reason string
	// Files lets a control session browse and fetch files from
	// Config.FileRoots (a files rule from the viewer, ADR-0146 #435).
	Files bool
	// Channels names the parts of the session this rule grants (#670,
	// g5_channels.go); zero keeps the older rules.
	Channels Channels
}

// AuthorizeFunc decides whether the device at remote (its tunnel address)
// may open a session of the given mode. It is called again after consent
// and on every Revalidate.
type AuthorizeFunc func(remote netip.Addr, mode Mode) Decision

// ConsentRequest describes a session waiting for on-screen approval.
type ConsentRequest struct {
	Peer   string
	Mode   Mode
	Remote netip.Addr
	// Code is the end-to-end verification code (#130); the prompt shows it
	// so the person can compare it with the viewer's. Empty for legacy
	// version 1 sessions.
	Code string
	// Recording tells the prompt that the session will be recorded (#128).
	Recording bool
}

// ConsentFunc asks the person at the device to approve a session (#116).
// It must return false when ctx ends; a nil ConsentFunc refuses every
// attended session.
type ConsentFunc func(ctx context.Context, req ConsentRequest) bool

// EventKind tells a session start from its end.
type EventKind uint8

// Session events.
const (
	EventStart EventKind = 1
	EventEnd   EventKind = 2
	// EventChange reports a change of clipboard sharing or local lock
	// during a session.
	EventChange EventKind = 3
)

// SessionEvent is passed to the indicator when a session starts or ends.
type SessionEvent struct {
	Kind       EventKind
	ID         uint64
	Peer       string
	Mode       Mode
	Unattended bool
	Time       time.Time
	// Reason says why a session ended.
	Reason string
	// Code is the end-to-end verification code (#130).
	Code string
	// Recording is true while the session is being recorded (#128); the
	// indicator must say so.
	Recording bool
	// Clipboard is true while clipboard sharing is on (#122).
	Clipboard bool
	// LocalLock is the current screen blanking and input lock (#119).
	LocalLock LockState
}

// IndicatorFunc shows that a session is running (#117) and records it
// locally. It is called synchronously before the first frame and after
// the session ends, so it must return quickly.
type IndicatorFunc func(SessionEvent)

const (
	defaultMaxSessions      = 2
	defaultMaxFPS           = 15
	maxMaxFPS               = 30
	defaultIdleTimeout      = 15 * time.Minute
	defaultHandshakeTimeout = 10 * time.Second
	defaultConsentTimeout   = 30 * time.Second
	maxConsentTimeout       = 2 * time.Minute
	readTimeout             = 60 * time.Second
	writeTimeout            = 30 * time.Second
	ackTimeout              = 30 * time.Second
	monitorPoll             = 2 * time.Second
	clipboardPoll           = time.Second
	frameWindow             = 2
	captureRetry            = time.Second
	captureFailLimit        = 2 * time.Minute
	maxHelloBytes           = 64
)

// Config configures a Server.
type Config struct {
	// ListenAddr is the device's tunnel address and port. Wildcard
	// addresses are rejected so the server is never exposed outside the
	// tunnel.
	ListenAddr netip.AddrPort
	// Authorize is required; see AuthorizeFunc.
	Authorize AuthorizeFunc
	// Consent asks for on-screen approval of attended sessions.
	Consent ConsentFunc
	// ConsentTimeout bounds the wait for approval (default 30s, at most
	// 2m). No answer means refusal.
	ConsentTimeout time.Duration
	// Indicator is required; see IndicatorFunc.
	Indicator IndicatorFunc
	// NewCapturer opens the screen for one session (default
	// NewScreenCapturer).
	NewCapturer func() (Capturer, error)
	// NewInjector opens input injection for one control session (default
	// NewInputInjector).
	NewInjector func() (Injector, error)
	// NewClipboard opens the clipboard for one control session (default
	// NewSystemClipboard). A failure only disables clipboard sharing.
	NewClipboard func() (Clipboard, error)
	// MaxSessions caps simultaneous sessions (default 2); at most one of
	// them may control.
	MaxSessions int
	// MaxFPS caps the frame rate (default 15, at most 30).
	MaxFPS int
	// IdleTimeout ends a session after this long without user activity
	// from the client: input, monitor or quality changes, or explicit
	// activity messages (default 15m).
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the wait for the client's hello (default
	// 10s).
	HandshakeTimeout time.Duration
	// Logger receives structured logs; nil discards them. Tunnel
	// addresses are only logged at debug level (ADR-0008).
	Logger *slog.Logger

	// AllowLegacyV1 accepts version 1 clients, which have no end-to-end
	// layer (#130). Off by default.
	AllowLegacyV1 bool
	// DisableClipboard refuses clipboard sharing even when a control
	// session asks for it (#122). Sharing is off by default per session
	// and turned on by the viewer.
	DisableClipboard bool
	// Recording records every session encrypted on this device (#128).
	// nil (the default) records nothing.
	Recording *RecordingConfig
	// NewLocalLock opens screen blanking and local input lock for a
	// control session that asks for it (#119). nil refuses such requests.
	NewLocalLock func() (LocalLock, error)
	// Power restarts the device for a control session that asks for it
	// (#129). nil refuses such requests.
	Power PowerFunc

	// Annotate shows viewers' marks on the screen (#425, protocol
	// version 3). nil ignores them.
	Annotate AnnotateFunc
	// FileRoots are the folders a control session with Decision.Files may
	// browse and fetch from (#435). Empty (the default) refuses every
	// file request.
	FileRoots []FileRoot

	// OSLogin asks every session for an account of this device before it
	// starts (ADR-0198, g5_login.go). nil skips the step.
	OSLogin *OSLoginConfig
	// StrictChannels makes a Decision without Channels grant only the
	// screen and input (#670).
	StrictChannels bool
	// NewFrame shows the "remotely connected" frame of a session (#671,
	// g5_frame.go); nil shows none.
	NewFrame func(FrameInfo) (SessionFrame, error)
	// RequireFrame refuses a session whose frame cannot be shown.
	RequireFrame bool
	// Summary receives the summary of every finished session (#667,
	// g5_summary.go). It must return quickly.
	Summary func(SessionSummary)
}

// Server is a remote desktop server bound to the tunnel.
type Server struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	sessions map[*session]struct{}
	control  int
	closed   bool
	wg       sync.WaitGroup
	nextID   atomic.Uint64
	// defaultDevices: the config left screen and input to the platform.
	defaultDevices bool

	// G5 additions (ADR-0198, ADR-0200).
	guardOnce sync.Once
	guard     *LoginGuard
	verifyMu  sync.Mutex
	kill      killState
}

// New validates cfg and returns a server.
func New(cfg Config) (*Server, error) {
	if cfg.Authorize == nil {
		return nil, errors.New("rdesk: Authorize geri çağrısı zorunlu")
	}
	if cfg.Indicator == nil {
		return nil, errors.New("rdesk: oturum göstergesi (Indicator) zorunlu")
	}
	// Both defaults: the platform may open screen and input together
	// (the Wayland portal session carries both, ADR-0236).
	defaultDevices := cfg.NewCapturer == nil && cfg.NewInjector == nil
	if cfg.NewCapturer == nil {
		cfg.NewCapturer = NewScreenCapturer
	}
	if cfg.NewInjector == nil {
		cfg.NewInjector = NewInputInjector
	}
	if cfg.NewClipboard == nil {
		cfg.NewClipboard = NewSystemClipboard
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultMaxSessions
	}
	if cfg.MaxFPS <= 0 {
		cfg.MaxFPS = defaultMaxFPS
	}
	cfg.MaxFPS = min(max(cfg.MaxFPS, minFPS), maxMaxFPS)
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.ConsentTimeout <= 0 {
		cfg.ConsentTimeout = defaultConsentTimeout
	}
	cfg.ConsentTimeout = min(cfg.ConsentTimeout, maxConsentTimeout)
	if err := cfg.Recording.validate(); err != nil {
		return nil, err
	}
	if err := validateFileRoots(cfg.FileRoots); err != nil {
		return nil, err
	}
	if err := cfg.OSLogin.validate(); err != nil {
		return nil, err
	}
	cfg.FileRoots = slices.Clone(cfg.FileRoots)
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, log: log, conns: make(map[net.Conn]struct{}), sessions: make(map[*session]struct{}), defaultDevices: defaultDevices}, nil
}

// ValidateListenAddr rejects invalid and wildcard listen addresses.
func ValidateListenAddr(a netip.AddrPort) error {
	if !a.IsValid() || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Port() == 0 {
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
		return fmt.Errorf("rdesk: dinlenemedi: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections from ln until ctx ends or Close is called. It
// takes ownership of ln. The listener's address must not be a wildcard.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		if err := ValidateListenAddr(ta.AddrPort()); err != nil {
			_ = ln.Close()
			return err
		}
	}
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
		if !s.trackConn(c) {
			s.log.Warn("uzak masaüstü bağlantısı reddedildi: bağlantı sınırı")
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(c)
			s.handleConn(ctx, c)
		}()
	}
}

// Close stops the listener, ends every session and waits for them.
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
	for sess := range s.sessions {
		sess.end(byeShutdown, "sunucu kapanıyor")
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// Revalidate re-runs Authorize for every session and ends those that are
// no longer allowed, and unattended sessions that would now need consent.
// Call it whenever the signed network document changes.
func (s *Server) Revalidate() int {
	s.mu.Lock()
	list := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		list = append(list, sess)
	}
	s.mu.Unlock()
	n := 0
	for _, sess := range list {
		if !s.stillAllowed(sess) {
			s.log.Info("uzak masaüstü oturumu kapatıldı: izin geri alındı", "peer", sess.peer, "mode", sess.mode.String())
			sess.end(byeRevoked, "izin geri alındı")
			n++
		}
	}
	return n
}

func (s *Server) stillAllowed(sess *session) bool {
	d := s.cfg.Authorize(sess.remote, sess.mode)
	if !s.decisionPermits(d, sess.mode) {
		return false
	}
	return sess.consented || d.Unattended
}

// ActiveSessions returns the number of running sessions.
func (s *Server) ActiveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) trackConn(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= s.cfg.MaxSessions+4 {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrackConn(c net.Conn) {
	_ = c.Close()
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// register adds a session within the limits.
func (s *Server) register(sess *session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.sessions) >= s.cfg.MaxSessions || (sess.mode == ModeControl && s.control > 0) {
		return false
	}
	s.sessions[sess] = struct{}{}
	if sess.mode == ModeControl {
		s.control++
	}
	return true
}

func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sess]; !ok {
		return
	}
	delete(s.sessions, sess)
	if sess.mode == ModeControl {
		s.control--
	}
}

func remoteAddr(c net.Conn) (netip.Addr, bool) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	return ta.AddrPort().Addr().Unmap(), true
}

func writeRaw(c net.Conn, msg []byte) {
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(msg)
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	remote, ok := remoteAddr(c)
	if !ok {
		return
	}
	_ = c.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	br := bufio.NewReaderSize(c, 64<<10)
	t, p, err := readMsg(br, maxHelloBytes)
	if err != nil || t != msgHello {
		writeRaw(c, encodeWelcome(statusBadRequest, "geçersiz başlangıç"))
		return
	}
	h, clientPub, err := decodeHelloAny(p)
	if err != nil || !s.versionAllowed(h.version) {
		writeRaw(c, encodeWelcome(statusBadRequest, fmt.Sprintf("desteklenen protokol sürümü %d", ProtocolVersionE2E)))
		return
	}
	if until, blocked := s.KillBlockedUntil(); blocked {
		// The person at the device used the kill shortcut (#672).
		writeRaw(c, encodeWelcome(statusDenied, fmt.Sprintf("yerel kullanıcı uzak oturumları kesti; %d dakika sonra yeniden deneyin", minutesUntil(until))))
		return
	}
	d := s.cfg.Authorize(remote, h.mode)
	if !s.decisionPermits(d, h.mode) {
		s.log.Info("uzak masaüstü reddedildi", "peer", d.Peer, "mode", h.mode.String(), "reason", d.Reason)
		s.log.Debug("uzak masaüstü reddedildi", "from", remote.String(), "mode", h.mode.String())
		writeRaw(c, encodeWelcome(statusDenied, ""))
		return
	}
	sess := &session{
		srv: s, conn: c, br: br, w: &wire{br: br}, remote: remote, peer: d.Peer, mode: h.mode, version: h.version,
		wake: make(chan struct{}, 1), monitorSel: h.monitor,
		hintFPS: h.maxFPS, hintScale: h.scale, pressed: make(map[uint16]bool),
	}
	sess.ctx, sess.cancel = context.WithCancel(ctx)
	defer sess.cancel()
	if h.version >= ProtocolVersionE2E {
		// Everything after the kex message is sealed (#130).
		kex, keys, err := serverKex(p, clientPub)
		if err != nil {
			writeRaw(c, encodeWelcome(statusBadRequest, "anahtar değişimi başarısız"))
			return
		}
		writeRaw(c, kex)
		sess.w.rx, sess.w.tx, sess.code = keys.c2s, keys.s2c, keys.code
	}
	if s.cfg.OSLogin != nil {
		// The account check comes after the rule and inside the sealed
		// layer, before anyone is asked or counted (ADR-0198).
		if sess.code == "" {
			writeRaw(c, encodeWelcome(statusDenied, "işletim sistemi girişi uçtan uca şifreleme gerektirir"))
			return
		}
		if !s.osLogin(sess) {
			return
		}
	}
	if !s.register(sess) {
		sess.writeRaw(encodeWelcome(statusBusy, s.busyReason(sess))) // #853, f3_viewers.go
		return
	}
	defer s.unregister(sess)
	_ = c.SetDeadline(time.Time{})

	if !d.Unattended {
		if !s.askConsent(sess) {
			s.log.Info("uzak masaüstü onaylanmadı", "peer", sess.peer, "mode", sess.mode.String())
			sess.writeRaw(encodeWelcome(statusRefused, ""))
			return
		}
		sess.consented = true
	}
	// Rules may have changed while waiting; this also covers a Revalidate
	// that ran before the session was registered.
	if !s.stillAllowed(sess) {
		sess.writeRaw(encodeWelcome(statusDenied, ""))
		return
	}
	if sess.ctx.Err() != nil {
		return
	}
	if err := sess.open(); err != nil {
		s.log.Warn("uzak masaüstü açılamadı", "peer", sess.peer, "err", err)
		sess.writeRaw(encodeWelcome(statusUnsupported, ""))
		sess.closeDevices()
		return
	}
	defer sess.closeDevices()

	frame, ok := sess.openFrame()
	if !ok {
		// Unattended access is never silent when the owner requires the
		// frame (#671).
		sess.writeRaw(encodeWelcome(statusUnsupported, "uzaktan bağlı çerçevesi gösterilemedi"))
		return
	}
	if frame != nil {
		defer frame.Close()
		s.addFrame(sess, frame) // #853: every frame names every viewer (f3_viewers.go)
		defer s.removeFrame(sess)
	}

	sess.id = s.nextID.Add(1)
	start := time.Now()
	if s.cfg.Recording != nil {
		// The owner asked for recording; a session that cannot be
		// recorded does not start (#128).
		rec, err := s.cfg.Recording.start(sess, start)
		if err != nil {
			s.log.Error("uzak masaüstü kaydı başlatılamadı; oturum açılmadı", "peer", sess.peer, "err", err)
			sess.writeRaw(encodeWelcome(statusUnsupported, "kayıt başlatılamadı"))
			return
		}
		sess.rec = rec
		defer sess.rec.close()
	}
	s.cfg.Indicator(sess.event(EventStart, start, ""))
	s.log.Info("uzak masaüstü oturumu açıldı", "id", sess.id, "peer", sess.peer, "mode", sess.mode.String(), "unattended", !sess.consented, "e2e", sess.code != "", "recording", sess.rec != nil)
	s.log.Debug("uzak masaüstü oturumu açıldı", "id", sess.id, "from", remote.String())
	reason := sess.run()
	end := time.Now()
	s.cfg.Indicator(sess.event(EventEnd, end, reason))
	if s.cfg.Summary != nil {
		s.cfg.Summary(sess.summary(start, end, reason))
	}
	s.log.Info("uzak masaüstü oturumu kapandı", "id", sess.id, "peer", sess.peer, "duration", time.Since(start).Round(time.Second).String(), "reason", reason)
}

func (s *Server) askConsent(sess *session) bool {
	if s.cfg.Consent == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(sess.ctx, s.cfg.ConsentTimeout)
	defer cancel()
	// A client that hangs up while waiting cancels the prompt. The
	// watcher only peeks, so anything the client sent stays buffered for
	// the session; it is stopped with a read deadline before the session
	// reads from the same buffer.
	_ = sess.conn.SetReadDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := sess.br.Peek(1); err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				cancel()
			}
		}
	}()
	ok := s.cfg.Consent(cctx, ConsentRequest{Peer: sess.peer, Mode: sess.mode, Remote: sess.remote, Code: sess.code, Recording: s.cfg.Recording != nil})
	ok = ok && cctx.Err() == nil
	_ = sess.conn.SetReadDeadline(time.Now())
	<-done
	_ = sess.conn.SetReadDeadline(time.Time{})
	return ok && cctx.Err() == nil
}

// --- session ---

type sentFrame struct {
	seq   uint32
	start time.Time
	bytes int
}

type ackSample struct {
	bytes   int
	elapsed time.Duration
}

type session struct {
	srv       *Server
	conn      net.Conn
	br        *bufio.Reader
	w         *wire
	code      string    // end-to-end verification code (#130)
	rec       *recorder // nil unless recording (#128)
	remote    netip.Addr
	peer      string
	mode      Mode
	consented bool
	id        uint64
	version   uint8 // hello version; 3 enables the ADR-0146 messages

	ctx    context.Context
	cancel context.CancelFunc

	wmu      sync.Mutex
	lastSend atomic.Int64 // unix nanoseconds of the last write

	capt Capturer
	inj  Injector
	clip Clipboard

	endOnce sync.Once
	endMsg  string

	wake chan struct{}

	mu           sync.Mutex
	monitors     []Monitor
	monitorSel   int
	view         image.Rectangle
	scale        int
	refresh      bool
	hintFPS      int
	hintScale    int
	hintChanged  bool
	inflight     []sentFrame
	acks         []ackSample
	lastActivity time.Time
	clipSet      string
	pressed      map[uint16]bool
	buttons      uint8
	lastPos      image.Point

	// ext holds the P24 additions (clipboard opt-in, local lock); they are
	// only touched from the read goroutine and after it ends.
	ext sessionExt
	// v3 holds the protocol version 3 state (ADR-0146).
	v3 sessionV3
	// osUser is the account that signed in (ADR-0198); "" without it.
	osUser string
	// sum collects the session summary (#667).
	sum summaryState
	// bg tracks goroutines started from the read goroutine.
	bg sync.WaitGroup
}

func (sess *session) open() error {
	var (
		c       Capturer
		inj     Injector
		handled bool
		err     error
	)
	if open := platformDevices; sess.srv.defaultDevices && open != nil {
		c, inj, handled, err = open(sess.mode == ModeControl)
		if err != nil {
			return err
		}
	}
	if !handled {
		if c, err = sess.srv.cfg.NewCapturer(); err != nil {
			return err
		}
	}
	sess.capt = c
	if handled {
		switch {
		case sess.mode == ModeControl && inj == nil:
			return fmt.Errorf("%w: girdi oturumu açılmadı", ErrUnsupported)
		case sess.mode == ModeControl:
			sess.inj = inj
		case inj != nil:
			_ = inj.Close()
		}
	}
	mons, err := c.Monitors()
	if err != nil || len(mons) == 0 {
		return fmt.Errorf("monitörler okunamadı: %w", errors.Join(err, ErrUnsupported))
	}
	sess.monitors = mons
	if sess.monitorSel != MonitorAll && (sess.monitorSel < 0 || sess.monitorSel >= len(mons)) {
		sess.monitorSel = primaryIndex(mons)
	}
	if sess.mode == ModeControl && !handled {
		inj, err := sess.srv.cfg.NewInjector()
		if err != nil {
			return err
		}
		sess.inj = inj
		// The clipboard is opened only when the viewer turns sharing on
		// (#122, sessionExt.setClipboard).
	}
	return nil
}

func (sess *session) closeDevices() {
	sess.finishV3()
	sess.ext.release()
	if sess.inj != nil {
		sess.releaseInput()
		_ = sess.inj.Close()
	}
	if sess.clip != nil {
		_ = sess.clip.Close()
	}
	if sess.capt != nil {
		_ = sess.capt.Close()
	}
}

// releaseInput lifts every key and button the client left pressed, so a
// dropped connection never leaves a modifier stuck.
func (sess *session) releaseInput() {
	sess.mu.Lock()
	keys := make([]uint16, 0, len(sess.pressed))
	for k := range sess.pressed {
		keys = append(keys, k)
	}
	clear(sess.pressed)
	buttons, pos := sess.buttons, sess.lastPos
	sess.buttons = 0
	sess.mu.Unlock()
	for _, k := range keys {
		_ = sess.inj.Key(k, false)
	}
	if buttons != 0 {
		_ = sess.inj.Pointer(pos.X, pos.Y, 0)
	}
}

func primaryIndex(ms []Monitor) int {
	for i, m := range ms {
		if m.Primary {
			return i
		}
	}
	return 0
}

func viewRect(ms []Monitor, sel int) image.Rectangle {
	if sel == MonitorAll {
		var u image.Rectangle
		for _, m := range ms {
			u = u.Union(m.Bounds)
		}
		return u
	}
	return ms[sel].Bounds
}

// fitScale returns the smallest scale >= want that keeps the view within
// the protocol's size limits, or 0 when none does.
func fitScale(view image.Rectangle, want int) int {
	for s := max(want, 1); s <= 4; s *= 2 {
		w, h := (view.Dx()+s-1)/s, (view.Dy()+s-1)/s
		if w <= maxDim && h <= maxDim && w*h <= maxPixels {
			return s
		}
	}
	return 0
}

func (sess *session) send(msgs ...[]byte) (int, error) {
	sess.wmu.Lock()
	defer sess.wmu.Unlock()
	n := 0
	for _, m := range msgs {
		if sess.rec != nil {
			if err := sess.rec.record(m); err != nil {
				return n, fmt.Errorf("kayıt yazılamadı: %w", err)
			}
		}
		_ = sess.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		k, err := sess.conn.Write(sess.w.seal(m))
		n += k
		if err != nil {
			return n, err
		}
	}
	sess.lastSend.Store(time.Now().UnixNano())
	return n, nil
}

// end stops the session with a bye message (best effort; skipped when a
// frame write holds the connection).
func (sess *session) end(code uint8, reason string) {
	sess.finish(code, reason, false)
}

// finish ends the session once. A graceful end always sends the bye and
// drains the connection before closing it; only the read goroutine may ask
// for it, because the drain reads from the connection.
func (sess *session) finish(code uint8, reason string, graceful bool) {
	sess.endOnce.Do(func() {
		sess.mu.Lock()
		sess.endMsg = reason
		sess.mu.Unlock()
		locked := sess.wmu.TryLock()
		sendBye := locked
		if !locked && graceful {
			// The cancel stops the frame loop after the write in progress.
			sess.cancel()
			sendBye = sess.lockAfterWrite()
			locked = true
		}
		if locked {
			if sendBye {
				_ = sess.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = sess.conn.Write(sess.w.seal(encodeBye(code, reason)))
			}
			sess.wmu.Unlock()
		}
		sess.cancel()
		if graceful {
			drainBeforeClose(sess.conn, endDrainTimeout)
		}
		_ = sess.conn.Close()
	})
}

// lockAfterWrite takes the write lock from the write in progress. A peer that
// stopped reading could hold that write for writeTimeout while Close, which
// keeps the server lock, waits on endOnce; so the write is cut at endWriteStall
// (repeatedly set, because send can overwrite the deadline). It reports whether
// the stream is still whole: a cut write leaves no room for a bye.
func (sess *session) lockAfterWrite() bool {
	deadline := time.Now().Add(endWriteStall)
	for !sess.wmu.TryLock() {
		_ = sess.conn.SetWriteDeadline(deadline)
		time.Sleep(10 * time.Millisecond)
	}
	return time.Now().Before(deadline)
}

func (sess *session) touch() {
	sess.mu.Lock()
	sess.lastActivity = time.Now()
	sess.mu.Unlock()
}

func (sess *session) poke() {
	select {
	case sess.wake <- struct{}{}:
	default:
	}
}

// run serves the session until it ends and returns the reason.
func (sess *session) run() string {
	sess.touch()
	sess.ext.started.Store(true)
	notice := ""
	if sess.rec != nil {
		notice = welcomeRecording
	}
	if _, err := sess.send(encodeWelcome(statusOK, notice), encodeMonitors(sess.monitors)); err != nil {
		return "bağlantı koptu"
	}
	var wg sync.WaitGroup
	wg.Go(sess.readLoop)
	err := sess.frameLoop()
	if err != nil && sess.ctx.Err() == nil {
		sess.end(byeError, "oturum hatası")
	} else {
		sess.end(byeNormal, "")
	}
	wg.Wait()
	sess.bg.Wait()
	sess.mu.Lock()
	msg := sess.endMsg
	sess.mu.Unlock()
	if msg == "" {
		if err != nil {
			msg = err.Error()
		} else {
			msg = "bağlantı kapandı"
		}
	}
	return msg
}

func (sess *session) frameLoop() error {
	cfg := &sess.srv.cfg
	q := newQuality(cfg.MaxFPS, 0)
	sess.mu.Lock()
	q.setLimits(sess.hintFPS, sess.hintScale, cfg.MaxFPS)
	sess.mu.Unlock()
	var enc tileEncoder
	var capBuf, scBuf [2]*image.RGBA
	var prev *image.RGBA
	idx := 0
	var seq uint32
	var curView image.Rectangle
	curScale, curSel := 0, -2
	var lastFrame, failSince time.Time
	nextMonCheck := time.Now().Add(monitorPoll)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-sess.ctx.Done():
			return nil
		case <-timer.C:
		case <-sess.wake:
		}
		now := time.Now()
		sess.mu.Lock()
		idle := now.Sub(sess.lastActivity)
		var oldest time.Time
		if len(sess.inflight) > 0 {
			oldest = sess.inflight[0].start
		}
		acks := sess.acks
		sess.acks = nil
		sel, refresh := sess.monitorSel, sess.refresh
		sess.refresh = false
		hintChanged, hintFPS, hintScale := sess.hintChanged, sess.hintFPS, sess.hintScale
		sess.hintChanged = false
		inflight := len(sess.inflight)
		sess.mu.Unlock()

		if idle > cfg.IdleTimeout {
			sess.end(byeIdle, "boşta kaldı")
			return nil
		}
		if !oldest.IsZero() && now.Sub(oldest) > ackTimeout {
			sess.end(byeError, "istemci yanıt vermiyor")
			return nil
		}
		for _, a := range acks {
			if q.observe(a.bytes, a.elapsed) {
				refresh = true
			}
		}
		if hintChanged && q.setLimits(hintFPS, hintScale, cfg.MaxFPS) {
			refresh = true
		}
		if now.After(nextMonCheck) {
			nextMonCheck = now.Add(monitorPoll)
			if mons, err := sess.capt.Monitors(); err == nil && len(mons) > 0 && !slices.Equal(mons, sess.monitorsSnapshot()) {
				sess.mu.Lock()
				sess.monitors = mons
				if sess.monitorSel != MonitorAll && sess.monitorSel >= len(mons) {
					sess.monitorSel = primaryIndex(mons)
				}
				sel = sess.monitorSel
				sess.mu.Unlock()
				if _, err := sess.send(encodeMonitors(mons)); err != nil {
					return err
				}
				refresh = true
				curSel = -2
			}
		}
		if now.Sub(time.Unix(0, sess.lastSend.Load())) > pingInterval {
			if _, err := sess.send(encodeMsg(msgKeepalive, nil)); err != nil {
				return err
			}
		}
		if inflight >= frameWindow {
			timer.Reset(q.budget())
			continue
		}
		if wait := lastFrame.Add(q.budget()).Sub(now); wait > 0 {
			timer.Reset(wait)
			continue
		}

		mons := sess.monitorsSnapshot()
		view := viewRect(mons, sel)
		scale := fitScale(view, q.scale)
		if scale == 0 {
			return errors.New("ekran protokol sınırından büyük")
		}
		if view != curView || scale != curScale || sel != curSel {
			curView, curScale, curSel = view, scale, sel
			sess.mu.Lock()
			sess.view, sess.scale = view, scale
			sess.mu.Unlock()
			dk := Desktop{Width: (view.Dx() + scale - 1) / scale, Height: (view.Dy() + scale - 1) / scale, Scale: scale, Monitor: sel, TileSize: TileSize, FPS: q.fps}
			if _, err := sess.send(dk.encode()); err != nil {
				return err
			}
			refresh = true
		}
		if refresh {
			prev = nil
		}
		lastFrame = now
		frame, err := sess.capt.Capture(view, capBuf[idx])
		if err != nil {
			// The screen is unreadable while it is locked, on the secure
			// desktop (UAC) or while a remote session is minimized. Keep
			// the session and retry; give up after captureFailLimit.
			if failSince.IsZero() {
				failSince = now
				sess.srv.log.Info("ekran şu anda okunamıyor; yeniden denenecek", "peer", sess.peer, "err", err)
			}
			if now.Sub(failSince) > captureFailLimit {
				return fmt.Errorf("ekran yakalanamadı: %w", err)
			}
			timer.Reset(captureRetry)
			continue
		}
		failSince = time.Time{}
		capBuf[idx] = frame
		img := frame
		if scale > 1 {
			scBuf[idx] = downscale(frame, scale, scBuf[idx])
			img = scBuf[idx]
		}
		rects := changedTiles(prev, img, TileSize)
		prev = img
		idx ^= 1
		if len(rects) == 0 {
			timer.Reset(q.budget())
			continue
		}
		if sess.ctx.Err() != nil {
			return nil
		}
		enc.setLevel(q.level)
		msgs, err := enc.encode(seq, img, rects)
		if err != nil {
			return err
		}
		msgs = append(msgs, encodeSeq(msgFrameEnd, seq))
		start := time.Now()
		n, err := sess.send(msgs...)
		if err != nil {
			return err
		}
		sess.mu.Lock()
		sess.inflight = append(sess.inflight, sentFrame{seq: seq, start: start, bytes: n})
		sess.mu.Unlock()
		seq++
		timer.Reset(q.budget())
	}
}

func (sess *session) monitorsSnapshot() []Monitor {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return slices.Clone(sess.monitors)
}

func (sess *session) readLoop() {
	defer sess.cancel()
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(readTimeout))
		t, p, err := sess.w.read(maxClientMsg)
		if err != nil {
			return
		}
		if err := sess.handle(t, p); err != nil {
			sess.srv.log.Info("uzak masaüstü oturumu kapatıldı: geçersiz istemci iletisi", "peer", sess.peer, "err", err)
			sess.end(byeProtocol, "geçersiz ileti")
			return
		}
	}
}

func (sess *session) handle(t msgType, p []byte) error {
	switch t {
	case msgPing:
		return nil
	case msgAck:
		seq, err := decodeSeq(p)
		if err != nil {
			return err
		}
		now := time.Now()
		sess.mu.Lock()
		for len(sess.inflight) > 0 && int32(seq-sess.inflight[0].seq) >= 0 {
			f := sess.inflight[0]
			sess.inflight = sess.inflight[1:]
			if f.seq == seq {
				sess.acks = append(sess.acks, ackSample{bytes: f.bytes, elapsed: now.Sub(f.start)})
			}
		}
		sess.mu.Unlock()
		sess.poke()
		return nil
	case msgActivity:
		sess.touch()
		return nil
	case msgRefresh:
		sess.mu.Lock()
		sess.refresh = true
		sess.mu.Unlock()
		sess.poke()
		return nil
	case msgSelectMonitor:
		if len(p) != 1 {
			return ErrProtocol
		}
		sel := monitorFromByte(p[0])
		sess.mu.Lock()
		if sel == MonitorAll || sel < len(sess.monitors) {
			sess.monitorSel = sel
		}
		sess.lastActivity = time.Now()
		sess.mu.Unlock()
		sess.poke()
		return nil
	case msgQuality:
		fps, scale, err := decodeQuality(p)
		if err != nil {
			return err
		}
		sess.mu.Lock()
		sess.hintFPS, sess.hintScale, sess.hintChanged = fps, scale, true
		sess.lastActivity = time.Now()
		sess.mu.Unlock()
		sess.poke()
		return nil
	case msgPointer, msgWheel, msgKey, msgText, msgClipboard:
		if sess.mode != ModeControl || sess.inj == nil {
			// A view session never injects input (#118).
			return fmt.Errorf("%w: izleme oturumunda girdi", ErrProtocol)
		}
		sess.touch()
		return sess.input(t, p)
	case msgClipboardMode, msgLocalLock, msgPower:
		if sess.mode != ModeControl || sess.inj == nil {
			return fmt.Errorf("%w: izleme oturumunda denetim iletisi", ErrProtocol)
		}
		sess.touch()
		return sess.handleExt(t, p)
	case msgEcho, msgAnnotate, msgFileList, msgFileGet, msgFileCancel:
		if sess.version < ProtocolVersionExt {
			return fmt.Errorf("%w: sürüm 3 iletisi", ErrProtocol)
		}
		return sess.handleV3(t, p)
	}
	return fmt.Errorf("%w: bilinmeyen ileti %#x", ErrProtocol, uint8(t))
}

// input injects one input message of a control session.
func (sess *session) input(t msgType, p []byte) error {
	switch t {
	case msgPointer:
		e, err := decodePointer(p)
		if err != nil {
			return err
		}
		sess.mu.Lock()
		view, scale := sess.view, max(sess.scale, 1)
		if view.Empty() {
			sess.mu.Unlock()
			return nil
		}
		x, y := mapPoint(view, scale, e.x, e.y)
		sess.buttons, sess.lastPos = e.buttons, image.Pt(x, y)
		sess.mu.Unlock()
		_ = sess.inj.Pointer(x, y, e.buttons)
	case msgWheel:
		dx, dy, err := decodeWheel(p)
		if err != nil {
			return err
		}
		_ = sess.inj.Wheel(dx, dy)
	case msgKey:
		usage, down, err := decodeKey(p)
		if err != nil {
			return err
		}
		sess.mu.Lock()
		if down {
			if len(sess.pressed) >= 32 && !sess.pressed[usage] {
				sess.mu.Unlock()
				return fmt.Errorf("%w: çok fazla basılı tuş", ErrProtocol)
			}
			sess.pressed[usage] = true
		} else {
			delete(sess.pressed, usage)
		}
		sess.mu.Unlock()
		_ = sess.inj.Key(usage, down)
	case msgText:
		s, err := decodeText(p, maxTextBytes)
		if err != nil {
			return err
		}
		if s = sanitizeText(s); s != "" {
			_ = sess.inj.Text(s)
		}
	case msgClipboard:
		s, err := decodeText(p, maxClipboardBytes)
		if err != nil {
			return err
		}
		if !sess.ext.clipOn.Load() {
			// Sharing is off until the viewer turns it on (#122).
			return fmt.Errorf("%w: pano paylaşımı kapalı", ErrProtocol)
		}
		if sess.clip != nil {
			sess.mu.Lock()
			sess.clipSet = s
			sess.mu.Unlock()
			_ = sess.clip.WriteText(s)
		}
	}
	return nil
}

// mapPoint converts a client canvas point to virtual desktop
// coordinates, clamped to the view.
func mapPoint(view image.Rectangle, scale, x, y int) (int, int) {
	vx := view.Min.X + x*scale + scale/2
	vy := view.Min.Y + y*scale + scale/2
	return clampInt(vx, view.Min.X, view.Max.X-1), clampInt(vy, view.Min.Y, view.Max.Y-1)
}

// sanitizeText drops control characters except tab and newline from typed
// text.
func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' {
			return r
		}
		if r == '\r' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// clipboardLoop shares local clipboard changes with a control session.
func (sess *session) clipboardLoop() {
	t := time.NewTicker(clipboardPoll)
	defer t.Stop()
	last, err := sess.clip.Sequence()
	if err != nil {
		return
	}
	for {
		select {
		case <-sess.ctx.Done():
			return
		case <-t.C:
		}
		seq, err := sess.clip.Sequence()
		if err != nil || seq == last {
			continue
		}
		last = seq
		if !sess.ext.clipOn.Load() {
			// Changes made while sharing is off are never sent (#122).
			continue
		}
		text, err := sess.clip.ReadText()
		if err != nil || text == "" || len(text) > maxClipboardBytes {
			continue
		}
		sess.mu.Lock()
		echo := text == sess.clipSet
		sess.mu.Unlock()
		if echo {
			continue
		}
		if _, err := sess.send(encodeMsg(msgClipboard, []byte(text))); err != nil {
			return
		}
	}
}
