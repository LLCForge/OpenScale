package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// sniffListener accepts TLS and plain HTTP on one port: a connection whose
// first byte is a TLS handshake record (0x16) becomes a TLS server
// connection when a certificate is available, anything else stays plain.
// Connections from sources that admit refuses are closed before any byte
// is read, and at most maxConns connections wait for their first byte.
type sniffListener struct {
	inner   net.Listener
	tlsCfg  *tls.Config
	haveTLS func() bool
	admit   func(net.Conn) bool
	out     chan net.Conn
	done    chan struct{}
	once    sync.Once
	sem     chan struct{}
	errMu   sync.Mutex
	err     error
}

func newSniffListener(ctx context.Context, inner net.Listener, cfg *tls.Config, haveTLS func() bool, admit func(net.Conn) bool) *sniffListener {
	l := &sniffListener{
		inner:   inner,
		tlsCfg:  cfg,
		haveTLS: haveTLS,
		admit:   admit,
		out:     make(chan net.Conn),
		done:    make(chan struct{}),
		sem:     make(chan struct{}, maxConns),
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-l.done:
		}
	}()
	go l.acceptLoop()
	return l
}

func (l *sniffListener) acceptLoop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			l.errMu.Lock()
			l.err = err
			l.errMu.Unlock()
			_ = l.Close()
			return
		}
		if l.admit != nil && !l.admit(c) {
			_ = c.Close()
			continue
		}
		select {
		case l.sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go l.classify(c)
	}
}

func (l *sniffListener) classify(c net.Conn) {
	defer func() { <-l.sem }()
	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var conn net.Conn = &peekedConn{Conn: c, r: br}
	if first[0] == 0x16 && l.haveTLS() {
		conn = tls.Server(conn, l.tlsCfg)
	}
	select {
	case l.out <- conn:
	case <-l.done:
		_ = c.Close()
	}
}

// Accept returns the next classified connection.
func (l *sniffListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.out:
		return c, nil
	case <-l.done:
		l.errMu.Lock()
		defer l.errMu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

// Close stops accepting.
func (l *sniffListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.inner.Close()
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
	})
	return err
}

// Addr is the inner listener's address.
func (l *sniffListener) Addr() net.Addr { return l.inner.Addr() }

// peekedConn reads the peeked bytes first.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes a TCP connection.
func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
