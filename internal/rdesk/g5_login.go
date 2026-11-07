package rdesk

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// Operating system sign-in for remote desktop sessions (ADR-0198).
//
// Protocol version 4 adds one optional step between the key exchange and
// the welcome: when the device asks for it (Config.OSLogin), the server
// sends loginRequired and the viewer answers with the user name and
// password of an account on the device. Both travel only inside the
// sealed end-to-end layer (#130), which itself runs inside the tunnel.
// The device checks them with its own operating system (Windows
// LogonUserW with LOGON32_LOGON_NETWORK, macOS PAM backed by Open
// Directory), never stores them and never logs them. The signed rdesk
// rule is checked before this step, so a password alone never opens a
// session. Wrong passwords are slowed down and, after a few in a row,
// the source device is blocked for a while (#665, LoginGuard).

// ProtocolVersionLogin is the hello version with the operating system
// sign-in step. It is version 3 plus loginRequired, login and
// loginResult.
const ProtocolVersionLogin = 4

// Login messages.
const (
	// msgLogin carries a user name and password (client to server).
	msgLogin msgType = 0x15
	// msgLoginRequired asks the viewer for an account (server to client).
	msgLoginRequired msgType = 0x8f
	// msgLoginResult answers one login message (server to client).
	msgLoginResult msgType = 0x90
)

// Login result codes.
const (
	loginOK      uint8 = 0
	loginWrong   uint8 = 1
	loginBlocked uint8 = 2
	loginFailed  uint8 = 3
)

// Limits of the login step.
const (
	maxLoginUser     = 255
	maxLoginPassword = 512
	maxLoginMsg      = 1 + maxLoginUser + 2 + maxLoginPassword
	// loginTimeout bounds the whole sign-in step, including typing.
	loginTimeout = 3 * time.Minute
)

var (
	// ErrOSLoginFailed is returned by an OSVerifier for a wrong user name
	// or password, or an account that may not sign in.
	ErrOSLoginFailed = errors.New("rdesk: kullanıcı adı veya parola yanlış")
	// ErrOSLoginUnavailable is returned by an OSVerifier that cannot
	// check passwords on this system.
	ErrOSLoginUnavailable = errors.New("rdesk: bu sistemde işletim sistemi girişi doğrulanamıyor")
	// ErrLoginRequired is returned by Dial when the device asks for an
	// operating system account and DialOptions.Credentials is nil.
	ErrLoginRequired = errors.New("rdesk: hedef cihaz işletim sistemi hesabıyla giriş istiyor")
	// ErrLoginBlocked is returned by Dial when the device blocked this
	// device after too many wrong passwords.
	ErrLoginBlocked = errors.New("rdesk: çok fazla hatalı parola; bu cihaz geçici olarak engellendi")
	// ErrLoginRejected is returned by Dial when the viewer gave up after a
	// wrong password.
	ErrLoginRejected = errors.New("rdesk: işletim sistemi girişi başarısız")
)

// OSVerifier checks an operating system account on this device. The
// password slice is wiped by the caller after Verify returns; Verify must
// not keep it.
type OSVerifier interface {
	Verify(ctx context.Context, user string, password []byte) error
}

// OSVerifierFunc adapts a function to OSVerifier.
type OSVerifierFunc func(ctx context.Context, user string, password []byte) error

// Verify calls f.
func (f OSVerifierFunc) Verify(ctx context.Context, user string, password []byte) error {
	return f(ctx, user, password)
}

// OSLoginConfig turns on the sign-in step for every session.
type OSLoginConfig struct {
	// Verifier checks the account; NewSystemVerifier is the default.
	Verifier OSVerifier
	// Guard slows down and blocks wrong passwords (#665); nil uses a
	// guard with the default limits.
	Guard *LoginGuard
	// Hint is shown on the viewer's sign-in prompt, e.g. "Windows hesabı".
	Hint string
	// AllowUser, when set, must also accept the user name (for example
	// only members of a local group). It runs after a correct password.
	AllowUser func(user string) bool
}

func (c *OSLoginConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.Verifier == nil {
		return errors.New("rdesk: işletim sistemi girişi için doğrulayıcı zorunlu")
	}
	if len(c.Hint) > maxReasonBytes {
		return errors.New("rdesk: giriş ipucu çok uzun")
	}
	return nil
}

// LoginRequest is passed to DialOptions.Credentials.
type LoginRequest struct {
	// Hint is the device's description of the account it wants.
	Hint string
	// Code is the session's end-to-end verification code (#130).
	Code string
	// Retry is true after a wrong password; Reason says why.
	Retry  bool
	Reason string
}

// LoginCredentials is an operating system account on the device.
// Password is wiped by Dial after it is sent.
type LoginCredentials struct {
	User     string
	Password []byte
}

// CredentialsFunc asks the person at the viewer for an account; it returns
// an error to give up.
type CredentialsFunc func(ctx context.Context, req LoginRequest) (LoginCredentials, error)

// --- guard (#665) ---

// LoginGuardConfig sets the limits of a LoginGuard. Zero fields take the
// defaults: 5 failures within 15 minutes block the source for 15 minutes;
// each failure waits 1s, 2s, 4s... up to 16s before it is answered.
type LoginGuardConfig struct {
	MaxFailures int
	Window      time.Duration
	Block       time.Duration
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	// MaxSources bounds the tracked sources (default 1024).
	MaxSources int
	// OnBlock is called (without locks held) when a source is blocked, so
	// the service can tell the owner (#665).
	OnBlock func(BlockEvent)
	// Now overrides time.Now (tests).
	Now func() time.Time
}

// BlockEvent describes a source blocked by a LoginGuard.
type BlockEvent struct {
	// Source is the guard key, a device name or tunnel address.
	Source   string
	Failures int
	Until    time.Time
}

// LoginGuard counts wrong passwords per source. It is safe for concurrent
// use and can be shared by several servers.
type LoginGuard struct {
	cfg     LoginGuardConfig
	mu      sync.Mutex
	sources map[string]*guardEntry
}

type guardEntry struct {
	failures []time.Time
	blocked  time.Time
}

// NewLoginGuard returns a guard with cfg's limits.
func NewLoginGuard(cfg LoginGuardConfig) *LoginGuard {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.Block <= 0 {
		cfg.Block = 15 * time.Minute
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = time.Second
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 16 * time.Second
	}
	if cfg.MaxDelay < cfg.BaseDelay {
		cfg.MaxDelay = cfg.BaseDelay
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = 1024
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &LoginGuard{cfg: cfg, sources: make(map[string]*guardEntry)}
}

// Blocked reports whether source is blocked now and until when.
func (g *LoginGuard) Blocked(source string) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	e, ok := g.sources[source]
	if !ok || !now.Before(e.blocked) {
		return time.Time{}, false
	}
	return e.blocked, true
}

// Failure records a wrong password from source. It returns how long to
// wait before answering and, when this failure blocks the source, the end
// of the block.
func (g *LoginGuard) Failure(source string) (time.Duration, time.Time) {
	g.mu.Lock()
	now := g.cfg.Now()
	e, ok := g.sources[source]
	if !ok {
		g.pruneLocked(now)
		e = &guardEntry{}
		g.sources[source] = e
	}
	cutoff := now.Add(-g.cfg.Window)
	kept := e.failures[:0]
	for _, t := range e.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.failures = append(kept, now)
	n := len(e.failures)
	delay := g.cfg.BaseDelay
	for i := 1; i < n && delay < g.cfg.MaxDelay; i++ {
		delay *= 2
	}
	delay = min(delay, g.cfg.MaxDelay)
	var until time.Time
	if n >= g.cfg.MaxFailures {
		until = now.Add(g.cfg.Block)
		e.blocked = until
		e.failures = e.failures[:0]
	}
	onBlock := g.cfg.OnBlock
	g.mu.Unlock()
	if !until.IsZero() && onBlock != nil {
		onBlock(BlockEvent{Source: source, Failures: n, Until: until})
	}
	return delay, until
}

// Success forgets source's recent failures (not an active block).
func (g *LoginGuard) Success(source string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.sources[source]; ok && !g.cfg.Now().Before(e.blocked) {
		delete(g.sources, source)
	}
}

// BlockFor blocks source for d regardless of failures (the kill shortcut,
// #672, uses it for every source).
func (g *LoginGuard) BlockFor(source string, d time.Duration) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	e, ok := g.sources[source]
	if !ok {
		g.pruneLocked(now)
		e = &guardEntry{}
		g.sources[source] = e
	}
	until := now.Add(d)
	if until.After(e.blocked) {
		e.blocked = until
	}
	return e.blocked
}

// pruneLocked drops expired entries; when the table is still full the
// entry with the oldest activity goes, but never an active block.
func (g *LoginGuard) pruneLocked(now time.Time) {
	if len(g.sources) < g.cfg.MaxSources {
		return
	}
	cutoff := now.Add(-g.cfg.Window)
	for k, e := range g.sources {
		if !now.Before(e.blocked) && (len(e.failures) == 0 || !e.failures[len(e.failures)-1].After(cutoff)) {
			delete(g.sources, k)
		}
	}
	for len(g.sources) >= g.cfg.MaxSources {
		victim, oldest := "", time.Time{}
		for k, e := range g.sources {
			if now.Before(e.blocked) {
				continue
			}
			last := time.Time{}
			if len(e.failures) > 0 {
				last = e.failures[len(e.failures)-1]
			}
			if victim == "" || last.Before(oldest) {
				victim, oldest = k, last
			}
		}
		if victim == "" {
			return
		}
		delete(g.sources, victim)
	}
}

// --- wire ---

func encodeLoginRequired(hint string) []byte {
	return encodeMsg(msgLoginRequired, appendStr8([]byte{0}, hint, maxReasonBytes))
}

func decodeLoginRequired(p []byte) (string, error) {
	d := dec{b: p}
	if d.u8() != 0 {
		return "", ErrProtocol
	}
	hint := d.str8(maxReasonBytes)
	return hint, d.end()
}

// encodeLogin builds the login message; the caller wipes the result.
func encodeLogin(user string, password []byte) ([]byte, error) {
	if user == "" || len(user) > maxLoginUser || !utf8.ValidString(user) || len(password) > maxLoginPassword {
		return nil, errors.New("rdesk: kullanıcı adı veya parola çok uzun ya da boş")
	}
	p := make([]byte, 0, 1+len(user)+2+len(password))
	p = append(p, byte(len(user)))
	p = append(p, user...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(password)))
	p = append(p, password...)
	msg := encodeMsg(msgLogin, p)
	wipeBytes(p)
	return msg, nil
}

// decodeLogin returns the user and a copy of the password, which the
// caller wipes.
func decodeLogin(p []byte) (string, []byte, error) {
	if len(p) < 1 {
		return "", nil, ErrProtocol
	}
	ul := int(p[0])
	if ul == 0 || len(p) < 1+ul+2 {
		return "", nil, ErrProtocol
	}
	user := string(p[1 : 1+ul])
	pl := int(binary.BigEndian.Uint16(p[1+ul:]))
	if pl > maxLoginPassword || len(p) != 1+ul+2+pl || !utf8.ValidString(user) || !validLoginUser(user) {
		return "", nil, ErrProtocol
	}
	pw := append([]byte(nil), p[1+ul+2:]...)
	return user, pw, nil
}

// validLoginUser refuses control characters in an account name; the
// verifier gets nothing a log line or a system call could misread.
func validLoginUser(u string) bool {
	for _, r := range u {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func encodeLoginResult(code uint8, retryAfter time.Duration, reason string) []byte {
	secs := min(max(int64(retryAfter/time.Second), 0), 0xffff)
	p := binary.BigEndian.AppendUint16([]byte{code}, uint16(secs))
	return encodeMsg(msgLoginResult, appendStr8(p, reason, maxReasonBytes))
}

func decodeLoginResult(p []byte) (uint8, time.Duration, string, error) {
	d := dec{b: p}
	code := d.u8()
	secs := d.u16()
	reason := d.str8(maxReasonBytes)
	if err := d.end(); err != nil {
		return 0, 0, "", err
	}
	return code, time.Duration(secs) * time.Second, reason, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- server ---

// guard returns the configured guard (created once).
func (s *Server) loginGuard() *LoginGuard {
	s.guardOnce.Do(func() {
		if s.cfg.OSLogin != nil && s.cfg.OSLogin.Guard != nil {
			s.guard = s.cfg.OSLogin.Guard
		} else {
			s.guard = NewLoginGuard(LoginGuardConfig{})
		}
	})
	return s.guard
}

// guardKey identifies the source; the tunnel address stands for the device.
func (sess *session) guardKey() string { return sess.remote.String() }

// osLogin runs the sign-in step. It returns false after answering the
// client when the session must not continue.
func (s *Server) osLogin(sess *session) bool {
	ol := s.cfg.OSLogin
	g := s.loginGuard()
	key := sess.guardKey()
	if until, blocked := g.Blocked(key); blocked {
		s.log.Info("uzak masaüstü girişi engelli kaynaktan reddedildi", "peer", sess.peer)
		sess.writeRaw(encodeWelcome(statusDenied, blockedReason(until)))
		return false
	}
	if sess.version < ProtocolVersionLogin {
		sess.writeRaw(encodeWelcome(statusDenied, "bu cihaz işletim sistemi hesabıyla giriş istiyor; görüntüleyiciyi güncelleyin"))
		return false
	}
	_ = sess.conn.SetDeadline(time.Now().Add(loginTimeout))
	defer func() { _ = sess.conn.SetDeadline(time.Time{}) }()
	sess.writeRaw(encodeLoginRequired(ol.Hint))
	for {
		t, p, err := sess.w.read(maxLoginMsg)
		if err != nil || t != msgLogin {
			return false
		}
		user, pw, err := decodeLogin(p)
		wipeBytes(p)
		if err != nil {
			return false
		}
		if until, blocked := g.Blocked(key); blocked {
			wipeBytes(pw)
			sess.writeRaw(encodeLoginResult(loginBlocked, time.Until(until), blockedReason(until)))
			return false
		}
		s.verifyMu.Lock()
		err = ol.Verifier.Verify(sess.ctx, user, pw)
		s.verifyMu.Unlock()
		wipeBytes(pw)
		if err == nil && ol.AllowUser != nil && !ol.AllowUser(user) {
			err = ErrOSLoginFailed
		}
		switch {
		case err == nil:
			g.Success(key)
			sess.osUser = user
			s.log.Info("uzak masaüstü işletim sistemi girişi başarılı", "peer", sess.peer)
			sess.writeRaw(encodeLoginResult(loginOK, 0, ""))
			return true
		case !errors.Is(err, ErrOSLoginFailed):
			s.log.Warn("uzak masaüstü işletim sistemi girişi doğrulanamadı", "peer", sess.peer, "err", err)
			sess.writeRaw(encodeLoginResult(loginFailed, 0, "bu cihaz parolayı şu anda doğrulayamıyor"))
			return false
		}
		delay, until := g.Failure(key)
		s.log.Warn("uzak masaüstü: hatalı işletim sistemi parolası", "peer", sess.peer)
		// The answer waits: a guesser learns nothing faster than this.
		select {
		case <-time.After(delay):
		case <-sess.ctx.Done():
			return false
		}
		if !until.IsZero() {
			s.log.Warn("uzak masaüstü: kaynak cihaz hatalı parolalar nedeniyle engellendi", "peer", sess.peer, "until", until.UTC().Format(time.RFC3339))
			sess.writeRaw(encodeLoginResult(loginBlocked, time.Until(until), blockedReason(until)))
			return false
		}
		sess.writeRaw(encodeLoginResult(loginWrong, 0, "kullanıcı adı veya parola yanlış"))
	}
}

func blockedReason(until time.Time) string {
	return fmt.Sprintf("çok fazla hatalı deneme; %d dakika sonra yeniden deneyin", minutesUntil(until))
}

func minutesUntil(until time.Time) int {
	return max(int((time.Until(until)+time.Minute-1)/time.Minute), 1)
}

// --- client ---

// clientLogin answers loginRequired (payload p) and returns the next
// message after a successful sign-in.
func clientLogin(ctx context.Context, w *wire, conn interface{ Write([]byte) (int, error) }, opts DialOptions, code string, p []byte) (msgType, []byte, error) {
	hint, err := decodeLoginRequired(p)
	if err != nil {
		return 0, nil, err
	}
	if code == "" || w.tx == nil {
		// A password never leaves without the end-to-end layer.
		return 0, nil, fmt.Errorf("%w: giriş isteği şifresiz geldi", ErrProtocol)
	}
	if opts.Credentials == nil {
		return 0, nil, ErrLoginRequired
	}
	req := LoginRequest{Hint: hint, Code: code}
	for {
		cred, err := opts.Credentials(ctx, req)
		if err != nil {
			wipeBytes(cred.Password)
			return 0, nil, fmt.Errorf("%w: %w", ErrLoginRejected, err)
		}
		msg, err := encodeLogin(cred.User, cred.Password)
		wipeBytes(cred.Password)
		if err != nil {
			return 0, nil, err
		}
		sealed := w.seal(msg)
		_, err = conn.Write(sealed)
		wipeBytes(msg)
		if err != nil {
			return 0, nil, fmt.Errorf("rdesk: giriş gönderilemedi: %w", err)
		}
		t, rp, err := w.read(maxServerMsg)
		if err != nil {
			return 0, nil, fmt.Errorf("rdesk: sunucu yanıt vermedi: %w", err)
		}
		if t != msgLoginResult {
			return 0, nil, ErrProtocol
		}
		res, _, reason, err := decodeLoginResult(rp)
		if err != nil {
			return 0, nil, err
		}
		switch res {
		case loginOK:
			return w.read(maxServerMsg)
		case loginWrong:
			req.Retry, req.Reason = true, reason
			continue
		case loginBlocked:
			return 0, nil, fmt.Errorf("%w: %s", ErrLoginBlocked, reason)
		default:
			return 0, nil, fmt.Errorf("%w: %s", ErrLoginRejected, reason)
		}
	}
}
