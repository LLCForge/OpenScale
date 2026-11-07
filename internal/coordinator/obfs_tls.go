package coordinator

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/obfs"
)

// Transport disguise on the coordinator (ADR-0186, #612, #613).
//
//   - ObfsBind wraps the UDP bind so devices may send disguised datagrams
//     ("auto": the coordinator answers in the form it was spoken to and
//     keeps serving devices that send plain WireGuard).
//   - ServeObfsTLS accepts the TCP transport (ADR-0032) behind a real TLS
//     handshake on its own listener (normally :443). After the handshake a
//     client must open with the transport preamble; anything else gets an
//     ordinary HTTP 404 and is closed, so an active prober sees a web
//     server. The same connection limits apply as on the plain listener.

// obfsHandshakeTimeout bounds the TLS handshake and the preamble.
const obfsHandshakeTimeout = 10 * time.Second

// ObfsBind wraps inner (nil: DefaultBind) with the disguise in auto mode
// for the network networkID. Pass the result as Config.Bind.
func ObfsBind(inner conn.Bind, networkID string, padding obfs.Padding) (*obfs.Bind, error) {
	if inner == nil {
		inner = DefaultBind()
	}
	key, err := obfs.DeriveKey(networkID)
	if err != nil {
		return nil, err
	}
	return obfs.NewBind(inner, obfs.Options{Mode: obfs.ModeAuto, Key: key, Padding: padding})
}

// ErrNoTCPTransport is returned by ServeObfsTLS when the server runs
// without the TCP transport (Config.TCPListen empty).
var ErrNoTCPTransport = errors.New("TLS gizleme için koordinatörde TCP aktarımı (TCPListen) açık olmalı")

// ServeObfsTLS serves the TLS-camouflaged TCP transport on ln until ctx
// ends. It waits for Run to bring the device up.
func (s *Server) ServeObfsTLS(ctx context.Context, ln net.Listener, cfg *tls.Config) error {
	defer ln.Close()
	select {
	case <-s.ready:
	case <-ctx.Done():
		return nil
	}
	if s.tcp == nil {
		return ErrNoTCPTransport
	}
	if cfg == nil || len(cfg.Certificates) == 0 {
		return errors.New("TLS gizleme sertifikası yok")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	s.logger.Info("TLS camouflaged transport listening", "address", ln.Addr().String())
	var tempDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			tempDelay = min(max(2*tempDelay, 5*time.Millisecond), time.Second)
			select {
			case <-time.After(tempDelay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		tempDelay = 0
		// The limits are applied to the raw connection first, so a flood
		// of handshakes from one address is cut before any TLS work.
		sc := &swapConn{}
		sc.set(c)
		tc := s.tcp.admit(sc)
		if tc == nil {
			_ = c.Close()
			continue
		}
		go s.serveObfsConn(ctx, tc, cfg)
	}
}

func (s *Server) serveObfsConn(ctx context.Context, tc *tcpConn, cfg *tls.Config) {
	sc := tc.c.(*swapConn)
	sess, err := obfs.Handshake(sc.get(), cfg, obfsHandshakeTimeout)
	if err != nil {
		s.tcp.drop(tc)
		return
	}
	// A device may open with an SPA knock inside TLS (#614); handle reads it.
	stream, ok := obfs.DemuxKnock(sess, control.TCPMagic, obfsHandshakeTimeout)
	if !ok {
		s.tcp.drop(tc)
		return
	}
	sc.set(stream)
	s.tcp.handle(ctx, tc)
}

// swapConn lets the TLS stream replace the raw connection after the
// limits were applied, without a data race with closeAll.
type swapConn struct {
	p atomic.Pointer[net.Conn]
}

func (c *swapConn) set(x net.Conn) { c.p.Store(&x) }
func (c *swapConn) get() net.Conn  { return *c.p.Load() }

func (c *swapConn) Read(b []byte) (int, error)         { return c.get().Read(b) }
func (c *swapConn) Write(b []byte) (int, error)        { return c.get().Write(b) }
func (c *swapConn) Close() error                       { return c.get().Close() }
func (c *swapConn) LocalAddr() net.Addr                { return c.get().LocalAddr() }
func (c *swapConn) RemoteAddr() net.Addr               { return c.get().RemoteAddr() }
func (c *swapConn) SetDeadline(t time.Time) error      { return c.get().SetDeadline(t) }
func (c *swapConn) SetReadDeadline(t time.Time) error  { return c.get().SetReadDeadline(t) }
func (c *swapConn) SetWriteDeadline(t time.Time) error { return c.get().SetWriteDeadline(t) }
