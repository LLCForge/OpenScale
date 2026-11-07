// Package sshclient opens a terminal on another device's own OpenSSH
// server through the tunnel (ADR-0203). It is the Linux counterpart of
// the remote desktop: the owner types the target account's user name and
// password, which travel only inside SSH inside the tunnel and are wiped
// from this process's buffers once the sign-in ends. The target's host
// key is pinned on first use (KnownHosts) and a changed key stops the
// connection. Host certificates from a trusted authority and the short
// user certificates of #668 are also accepted. Only golang.org/x/crypto
// is used (ADR-0002).
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTimeout = 20 * time.Second
	maxPassword    = 1024
	maxUser        = 64
	clientVersion  = "SSH-2.0-OpenScale-Terminal"
)

var (
	// ErrAuth is returned when the target refuses the user name and
	// password (or certificate).
	ErrAuth = errors.New("sshclient: kullanıcı adı veya parola kabul edilmedi")
	// ErrInvalidTarget is returned for a missing or unroutable address.
	ErrInvalidTarget = errors.New("sshclient: hedef adres geçersiz")
)

// Config configures one connection.
type Config struct {
	// Addr is the target's tunnel address and SSH port (usually 22).
	Addr netip.AddrPort
	// HostName is the name the host key is pinned under; empty uses Addr.
	HostName string
	// User is the account on the target.
	User string
	// Password returns the password; the returned slice is wiped after
	// the sign-in. nil skips password authentication.
	Password func() ([]byte, error)
	// Certificate, when set, signs in with a short-lived user
	// certificate (ssh.NewCertSigner) before trying the password.
	Certificate ssh.Signer
	// KnownHosts pins the host key; required.
	KnownHosts *KnownHosts
	// HostCAs accepts host certificates signed by these authorities.
	HostCAs []ssh.PublicKey
	// Timeout bounds the connection and sign-in (default 20s).
	Timeout time.Duration
	// Dial overrides the TCP dialer (tests use loopback listeners).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client is one signed-in SSH connection.
type Client struct {
	c    *ssh.Client
	Host HostKeyInfo
}

func validTarget(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast()
}

func validUser(u string) bool {
	if u == "" || len(u) > maxUser || u[0] == '-' {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.', c == '@':
		case c == '$' && i == len(u)-1:
		default:
			return false
		}
	}
	return true
}

// secret holds the password for the sign-in. The x/crypto/ssh callbacks
// take strings; the string shares the buffer, which is wiped afterwards,
// so no immutable copy of the password stays in this process.
type secret struct {
	mu  sync.Mutex
	buf []byte
}

func (s *secret) get(fetch func() ([]byte, error)) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf == nil {
		b, err := fetch()
		if err != nil {
			return "", err
		}
		if len(b) == 0 || len(b) > maxPassword {
			wipe(b)
			return "", errors.New("sshclient: parola boş veya çok uzun")
		}
		s.buf = b
	}
	return unsafe.String(&s.buf[0], len(s.buf)), nil
}

func (s *secret) wipe() {
	s.mu.Lock()
	wipe(s.buf)
	s.buf = nil
	s.mu.Unlock()
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// hostKeyCallback pins (or checks) the key and records what happened.
func (cfg *Config) hostKeyCallback(host string, info *HostKeyInfo) ssh.HostKeyCallback {
	tofu := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		hi, err := cfg.KnownHosts.Check(host, key)
		*info = hi
		return err
	}
	if len(cfg.HostCAs) == 0 {
		return tofu
	}
	cas := cfg.HostCAs
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			m := auth.Marshal()
			return slices.ContainsFunc(cas, func(ca ssh.PublicKey) bool { return bytes.Equal(ca.Marshal(), m) })
		},
		HostKeyFallback: tofu,
	}
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		if err := checker.CheckHostKey(addr, remote, key); err != nil {
			return err
		}
		if _, ok := key.(*ssh.Certificate); ok {
			*info = HostKeyInfo{Host: host, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), Status: HostKeyCertified}
		}
		return nil
	}
}

// Dial connects and signs in.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if !validTarget(cfg.Addr) {
		return nil, ErrInvalidTarget
	}
	if !validUser(cfg.User) {
		return nil, errors.New("sshclient: geçersiz kullanıcı adı")
	}
	if cfg.KnownHosts == nil {
		return nil, errors.New("sshclient: bilinen sunucular deposu zorunlu")
	}
	if cfg.Password == nil && cfg.Certificate == nil {
		return nil, errors.New("sshclient: parola veya sertifika gerekli")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host := cfg.HostName
	if host == "" {
		host = cfg.Addr.String()
	}
	var sec secret
	defer sec.wipe()
	var auth []ssh.AuthMethod
	if cfg.Certificate != nil {
		auth = append(auth, ssh.PublicKeys(cfg.Certificate))
	}
	if cfg.Password != nil {
		auth = append(auth,
			ssh.PasswordCallback(func() (string, error) { return sec.get(cfg.Password) }),
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					if echos[i] {
						// Only hidden prompts get the password.
						continue
					}
					pw, err := sec.get(cfg.Password)
					if err != nil {
						return nil, err
					}
					answers[i] = pw
				}
				return answers, nil
			}), 2))
	}
	var info HostKeyInfo
	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: cfg.hostKeyCallback(host, &info),
		ClientVersion:   clientVersion,
		Timeout:         timeout,
	}
	sshCfg.KeyExchanges = []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519, "curve25519-sha256@libssh.org", ssh.KeyExchangeECDHP256, ssh.KeyExchangeDH14SHA256}
	sshCfg.Ciphers = []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM, ssh.CipherAES256CTR}
	dial := cfg.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", cfg.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("sshclient: bağlanılamadı: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr.String(), sshCfg)
	stopped := stop()
	if err != nil {
		_ = conn.Close()
		var changed *HostKeyChangedError
		switch {
		case errors.As(err, &changed):
			return nil, changed
		case !stopped || ctx.Err() != nil:
			return nil, fmt.Errorf("sshclient: zaman aşımı: %w", errors.Join(ctx.Err(), err))
		case isAuthError(err):
			return nil, ErrAuth
		}
		return nil, fmt.Errorf("sshclient: el sıkışma başarısız: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &Client{c: ssh.NewClient(c, chans, reqs), Host: info}, nil
}

func isAuthError(err error) bool {
	var se *ssh.ServerAuthError
	if errors.As(err, &se) {
		return true
	}
	return bytes.Contains([]byte(err.Error()), []byte("unable to authenticate"))
}

// Close ends the connection.
func (c *Client) Close() error { return c.c.Close() }

// Shell is an interactive terminal on the target.
type Shell struct {
	sess  *ssh.Session
	stdin io.WriteCloser
	out   *io.PipeReader
	outW  *io.PipeWriter
	err   error
	done  chan struct{}
}

// Shell opens a login shell with a pseudo terminal of cols x rows.
func (c *Client) Shell(term string, cols, rows int) (*Shell, error) {
	cols, rows = clampDim(cols, 80), clampDim(rows, 24)
	if term == "" || len(term) > 32 {
		term = "xterm-256color"
	}
	sess, err := c.c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshclient: oturum açılamadı: %w", err)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := sess.RequestPty(term, rows, cols, modes); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshclient: terminal istenemedi: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	pr, pw := io.Pipe()
	sess.Stdout, sess.Stderr = pw, pw
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("sshclient: kabuk başlatılamadı: %w", err)
	}
	sh := &Shell{sess: sess, stdin: stdin, out: pr, outW: pw, done: make(chan struct{})}
	go func() {
		sh.err = sess.Wait()
		_ = pw.Close()
		close(sh.done)
	}()
	return sh, nil
}

func clampDim(v, def int) int {
	if v <= 0 {
		return def
	}
	return min(v, 1000)
}

// Write sends keystrokes to the terminal.
func (s *Shell) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Read reads terminal output (stdout and stderr together).
func (s *Shell) Read(p []byte) (int, error) { return s.out.Read(p) }

// Resize changes the terminal size.
func (s *Shell) Resize(cols, rows int) error {
	return s.sess.WindowChange(clampDim(rows, 24), clampDim(cols, 80))
}

// Done is closed when the shell ends.
func (s *Shell) Done() <-chan struct{} { return s.done }

// Err is the shell's exit error after Done.
func (s *Shell) Err() error { return s.err }

// Close ends the shell.
func (s *Shell) Close() error {
	_ = s.stdin.Close()
	err := s.sess.Close()
	_ = s.out.Close()
	return err
}
