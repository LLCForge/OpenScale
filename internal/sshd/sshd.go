// Package sshd is OpenScale's embedded SSH server core.
//
// It listens only on the device's tunnel address. Clients do not present SSH
// keys or passwords: identity comes from the tunnel itself, because a
// WireGuard peer can only send from the tunnel addresses assigned to it in
// the signed network document. On every authentication attempt the server
// calls the caller's Authorize callback with the tunnel source address and
// the requested local account; the "none" and "keyboard-interactive"
// methods succeed only when Authorize allows it.
//
// Supported: command execution, interactive shells (with a PTY on Linux and
// a ConPTY on Windows 10 1809+, otherwise without one) and local port
// forwarding (direct-tcpip) when AuthorizeForward allows the destination.
// Not supported: SFTP (would need a dependency outside ADR-0002), remote
// port forwarding, agent forwarding and X11 forwarding.
package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuthorizeFunc decides whether the device at remoteAddr (its tunnel
// address) may log in as localUser. reason is logged when access is denied.
type AuthorizeFunc func(remoteAddr netip.Addr, localUser string) (allowed bool, reason string)

// AuthorizeForwardFunc decides whether an authenticated session may open a
// local port forward (ssh -L) to dst.
type AuthorizeForwardFunc func(remoteAddr netip.Addr, localUser string, dst netip.AddrPort) (allowed bool, reason string)

const (
	defaultAuthTimeout    = 30 * time.Second
	defaultIdleTimeout    = 15 * time.Minute
	defaultMaxConnections = 8
	defaultMaxChannels    = 4
	maxAuthTries          = 3
	serverVersion         = "SSH-2.0-OpenScale"
)

var (
	// ErrInvalidListenAddr is returned for a missing or wildcard listen address.
	ErrInvalidListenAddr = errors.New("dinleme adresi belirli bir tünel adresi olmalı")
	errDenied            = errors.New("erişim reddedildi")
)

// Config configures a Server.
type Config struct {
	// ListenAddr is the device's tunnel address and port. Wildcard
	// addresses are rejected so the server is never exposed outside the
	// tunnel.
	ListenAddr netip.AddrPort
	// HostKeyPath is where the Ed25519 host key is kept; it is generated on
	// first start with owner-only permissions. Ignored when HostKey is set.
	HostKeyPath string
	// HostKey overrides HostKeyPath with an already loaded key.
	HostKey ssh.Signer
	// Authorize is required; see AuthorizeFunc.
	Authorize AuthorizeFunc
	// AuthorizeForward enables local port forwarding; nil disables it.
	AuthorizeForward AuthorizeForwardFunc
	// AuthTimeout bounds the handshake and authentication (default 30s).
	AuthTimeout time.Duration
	// IdleTimeout closes a connection with no traffic in either direction
	// (default 15m).
	IdleTimeout time.Duration
	// MaxConnections caps simultaneous connections, including ones still
	// authenticating (default 8).
	MaxConnections int
	// MaxChannelsPerConn caps sessions plus forwards per connection
	// (default 4).
	MaxChannelsPerConn int

	// UserCAs are the authorities whose short-lived user certificates
	// may sign in (#668, g5_cert.go). The tunnel rule is still required.
	UserCAs []ssh.PublicKey
	// RequireCertificate accepts only such certificates; the tunnel
	// address alone is no longer enough.
	RequireCertificate bool
	// MaxCertLifetime is the longest certificate validity accepted
	// (default MaxCertLifetime, ten minutes).
	MaxCertLifetime time.Duration
	// CertRevoked, when set, refuses revoked certificates.
	CertRevoked func(*ssh.Certificate) bool
	// Commands, when it reports restricted, limits the sessions of user
	// from remote to exactly these commands: no shell, no forwarding
	// (#669).
	Commands func(remote netip.Addr, user string) (commands []string, restricted bool)
	// Clock overrides time.Now for certificate checks (tests).
	Clock func() time.Time
	// Logger receives structured logs; nil discards them. Tunnel addresses
	// are only logged at debug level (ADR-0008).
	Logger *slog.Logger
}

// Server is an SSH server bound to the tunnel.
type Server struct {
	cfg    Config
	log    *slog.Logger
	sshCfg *ssh.ServerConfig
	hostPK ssh.PublicKey

	mu     sync.Mutex
	ln     net.Listener
	conns  map[*serverConn]struct{}
	closed bool
	wg     sync.WaitGroup
	kill   killState
}

type serverConn struct {
	raw     *activityConn
	sc      *ssh.ServerConn // nil until authenticated
	remote  netip.Addr
	user    string
	acct    *account
	restr   connRestriction
	chans   atomic.Int32
	done    chan struct{} // closed when the connection ends
	closeMu sync.Mutex
}

func (c *serverConn) close() {
	_ = c.raw.Close()
}

// New validates cfg, loads or creates the host key and returns a server.
func New(cfg Config) (*Server, error) {
	if cfg.Authorize == nil {
		return nil, errors.New("sshd: Authorize geri çağrısı zorunlu")
	}
	signer := cfg.HostKey
	if signer == nil {
		if cfg.HostKeyPath == "" {
			return nil, errors.New("sshd: host anahtarı yolu zorunlu")
		}
		var err error
		signer, err = LoadOrCreateHostKey(cfg.HostKeyPath)
		if err != nil {
			return nil, err
		}
	}
	if cfg.AuthTimeout <= 0 {
		cfg.AuthTimeout = defaultAuthTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConnections
	}
	if cfg.MaxChannelsPerConn <= 0 {
		cfg.MaxChannelsPerConn = defaultMaxChannels
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, log: log, hostPK: signer.PublicKey(), conns: make(map[*serverConn]struct{})}

	sc := &ssh.ServerConfig{
		NoClientAuth:  true,
		MaxAuthTries:  maxAuthTries,
		ServerVersion: serverVersion,
	}
	sc.KeyExchanges = []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519}
	sc.Ciphers = []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM}
	sc.MACs = []string{ssh.HMACSHA256ETM}
	if cfg.RequireCertificate && len(cfg.UserCAs) == 0 {
		return nil, errors.New("sshd: sertifika zorunluyken en az bir yetkili (UserCAs) gerekli")
	}
	if len(cfg.UserCAs) > 0 {
		sc.PublicKeyCallback = s.authenticateCert
	}
	if cfg.RequireCertificate {
		// Only a certificate signs in (#668).
		sc.NoClientAuth = false
	} else {
		sc.NoClientAuthCallback = s.authenticate
		sc.KeyboardInteractiveCallback = func(meta ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return s.authenticate(meta)
		}
	}
	sc.AddHostKey(signer)
	s.sshCfg = sc
	return s, nil
}

// HostKey returns the server's public host key, for showing its
// fingerprint to the owner (ssh.FingerprintSHA256).
func (s *Server) HostKey() ssh.PublicKey { return s.hostPK }

func tcpAddr(a net.Addr) (netip.Addr, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	return ta.AddrPort().Addr().Unmap(), true
}

// authenticate runs Authorize for an authentication attempt. Any method
// that reaches it carries no secret; the tunnel source address is the
// credential.
func (s *Server) authenticate(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
	remote, ok := tcpAddr(meta.RemoteAddr())
	if !ok {
		return nil, errDenied
	}
	user := meta.User()
	if !validUserName(user) {
		s.log.Info("SSH girişi reddedildi: geçersiz kullanıcı adı")
		return nil, errDenied
	}
	allowed, reason := s.cfg.Authorize(remote, user)
	if !allowed {
		s.log.Info("SSH girişi reddedildi", "user", user, "reason", reason)
		s.log.Debug("SSH girişi reddedildi", "from", remote.String(), "user", user)
		return nil, errDenied
	}
	if _, err := resolveAccount(user); err != nil {
		s.log.Info("SSH girişi reddedildi: yerel hesap kullanılamıyor", "user", user, "err", err)
		return nil, errDenied
	}
	return &ssh.Permissions{}, nil
}

// validUserName accepts conservative POSIX/Windows account names.
func validUserName(u string) bool {
	if u == "" || len(u) > 64 || u[0] == '-' || u[0] == '.' {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.':
		case c == '$' && i == len(u)-1:
		default:
			return false
		}
	}
	return true
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
		return fmt.Errorf("sshd: dinlenemedi: %w", err)
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
	for {
		raw, err := ln.Accept()
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
		if s.killBlocked() {
			_ = raw.Close()
			continue
		}
		c := &serverConn{raw: newActivityConn(raw), done: make(chan struct{})}
		if !s.track(c) {
			s.log.Warn("SSH bağlantısı reddedildi: eşzamanlı bağlantı sınırı")
			_ = raw.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			s.handleConn(c)
		}()
	}
}

// Close stops the listener, closes every connection (terminating their
// processes) and waits for handlers to finish.
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
		c.close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// Revalidate re-runs Authorize for every authenticated connection and
// closes those that are no longer allowed. Call it whenever the signed
// network document (and therefore the rules) changes.
func (s *Server) Revalidate() int {
	s.mu.Lock()
	conns := make([]*serverConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	closed := 0
	for _, c := range conns {
		c.closeMu.Lock()
		authed := c.sc != nil
		remote, user := c.remote, c.user
		c.closeMu.Unlock()
		if !authed {
			continue
		}
		if ok, reason := s.cfg.Authorize(remote, user); !ok {
			s.log.Info("SSH oturumu kapatıldı: izin geri alındı", "user", user, "reason", reason)
			c.close()
			closed++
		}
	}
	return closed
}

// authenticatedCount returns the number of registered, authenticated
// connections.
func (s *Server) authenticatedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for c := range s.conns {
		c.closeMu.Lock()
		if c.sc != nil {
			n++
		}
		c.closeMu.Unlock()
	}
	return n
}

// ActiveConnections returns the number of open connections.
func (s *Server) ActiveConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) track(c *serverConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= s.cfg.MaxConnections {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c *serverConn) {
	c.close()
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) handleConn(c *serverConn) {
	remote, ok := tcpAddr(c.raw.RemoteAddr())
	if !ok {
		return
	}
	_ = c.raw.SetDeadline(time.Now().Add(s.cfg.AuthTimeout))
	sc, chans, reqs, err := ssh.NewServerConn(c.raw, s.sshCfg)
	if err != nil {
		s.log.Debug("SSH el sıkışması başarısız", "from", remote.String(), "err", err)
		return
	}
	defer sc.Close()
	_ = c.raw.SetDeadline(time.Time{})

	acct, err := resolveAccount(sc.User())
	if err != nil {
		return
	}
	if s.killBlocked() {
		// The person at the device used the kill shortcut (#672).
		return
	}
	c.closeMu.Lock()
	c.sc, c.remote, c.user, c.acct = sc, remote, sc.User(), acct
	c.restr = s.restrictionFor(remote, sc.User(), sc.Permissions)
	c.closeMu.Unlock()
	// Re-check after registering: a Revalidate that ran between
	// authentication and registration could not see this connection.
	if ok, _ := s.cfg.Authorize(remote, c.user); !ok {
		return
	}
	s.log.Info("SSH oturumu açıldı", "user", c.user)
	s.log.Debug("SSH oturumu açıldı", "from", remote.String(), "user", c.user)

	stopIdle := c.raw.watchIdle(s.cfg.IdleTimeout, func() {
		s.log.Info("SSH bağlantısı boşta kaldığı için kapatıldı", "user", c.user)
	})
	defer stopIdle()

	// Global requests: remote forwarding (tcpip-forward) and others are refused.
	go ssh.DiscardRequests(reqs)

	var chWG sync.WaitGroup
	for nc := range chans {
		if int(c.chans.Load()) >= s.cfg.MaxChannelsPerConn {
			_ = nc.Reject(ssh.ResourceShortage, "kanal sınırına ulaşıldı")
			continue
		}
		switch nc.ChannelType() {
		case "session":
			c.chans.Add(1)
			chWG.Add(1)
			go func() {
				defer chWG.Done()
				defer c.chans.Add(-1)
				s.handleSession(c, nc)
			}()
		case "direct-tcpip":
			c.chans.Add(1)
			chWG.Add(1)
			go func() {
				defer chWG.Done()
				defer c.chans.Add(-1)
				s.handleDirectTCPIP(c, nc)
			}()
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "desteklenmeyen kanal türü")
		}
	}
	close(c.done)
	chWG.Wait()
	s.log.Info("SSH oturumu kapandı", "user", c.user)
}

// activityConn records the time of the last successful read or write so
// idle connections can be closed regardless of direction.
type activityConn struct {
	net.Conn
	last atomic.Int64
}

func newActivityConn(c net.Conn) *activityConn {
	a := &activityConn{Conn: c}
	a.touch()
	return a
}

func (a *activityConn) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *activityConn) Read(p []byte) (int, error) {
	n, err := a.Conn.Read(p)
	if n > 0 {
		a.touch()
	}
	return n, err
}

func (a *activityConn) Write(p []byte) (int, error) {
	n, err := a.Conn.Write(p)
	if n > 0 {
		a.touch()
	}
	return n, err
}

// watchIdle closes the connection after idle without traffic. The returned
// function stops the watcher.
func (a *activityConn) watchIdle(idle time.Duration, onIdle func()) func() {
	a.touch()
	interval := idle / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				if now.Sub(time.Unix(0, a.last.Load())) >= idle {
					onIdle()
					_ = a.Close()
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
