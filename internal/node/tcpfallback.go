package node

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/openscale/openscale/internal/control"
)

// TCP fallback transport (ADR-0032, F-010, #60). When the coordinator cannot
// be reached over UDP (hotel and corporate networks that block UDP), the
// device carries its WireGuard datagrams for the coordinator over one TCP
// connection, by default to port 443 of the coordinator's host. WireGuard
// still encrypts and authenticates every datagram; the stream adds no
// cryptography of its own (no TLS, R-20). Peers are then reached through
// the coordinator's relay (ADR-0017), whose packets travel inside the
// coordinator tunnel and therefore over the same TCP connection.
//
// To WireGuard nothing changes: datagrams for the coordinator's UDP
// endpoint are written to the stream, and frames from the stream arrive as
// if they came from that endpoint. While TCP is in use the device asks,
// from its WireGuard socket, whether UDP works again (control.UDPEcho*);
// the first answer moves it back to UDP.

const (
	// tcpDialTimeout bounds connecting and the preamble exchange.
	tcpDialTimeout = 10 * time.Second
	// tcpWriteTimeout bounds one write; a stuck stream is closed.
	tcpWriteTimeout = 10 * time.Second
	// tcpIdleTimeout closes a stream that carried nothing (WireGuard sends
	// a keepalive every 25 seconds).
	tcpIdleTimeout = 3 * time.Minute
	// Redial backoff after a failed or closed connection.
	tcpRedialFirst = time.Second
	tcpRedialMax   = time.Minute
	// UDP echo while on TCP: first after tcpEchoFirst, then doubling.
	tcpEchoFirst = 10 * time.Second
	tcpEchoMax   = 5 * time.Minute
	// tcpEchoWait: a reply later than this does not count.
	tcpEchoWait = 5 * time.Second
	// tcpFallbackFails: failed syncs in a row, with nothing received from
	// the coordinator over UDP meanwhile, before TCP is tried.
	tcpFallbackFails = 2
	tcpInQueue       = 1024
)

// tcpFallback wraps the UDP bind and owns the TCP stream.
type tcpFallback struct {
	conn.Bind
	logger *slog.Logger
	now    func() time.Time
	// dial opens a stream to the coordinator (preamble exchanged); onUp is
	// called when a stream is ready, onUDP when UDP works again.
	dial  func(ctx context.Context) (net.Conn, error)
	onUp  func()
	onUDP func()

	coord   atomic.Pointer[netip.AddrPort]
	coordEP atomic.Pointer[conn.Endpoint]
	active  atomic.Bool
	// mark and ifIndex4/6 mirror what the exit router asked of the UDP
	// sockets, so the stream bypasses the tunnel the same way.
	mark     atomic.Uint32
	ifIndex4 atomic.Uint32
	ifIndex6 atomic.Uint32

	// echoFirst is tcpEchoFirst (tests shorten it).
	echoFirst time.Duration
	// forced keeps every coordinator datagram on the stream, never falls
	// back to UDP and sends no UDP at all (Tor, ADR-0044). Set before Run.
	forced bool
	// camo, when set, wraps a fresh stream in the TLS camouflage before
	// the preamble (g3_obfs.go, #613). Set before Run.
	camo func(net.Conn) (net.Conn, error)
	// knock, when set, returns an SPA knock sent before the preamble;
	// noKnock remembers that the last knocked exchange failed (w3_spa.go,
	// #614). Set before Run.
	knock   func() []byte
	noKnock atomic.Bool

	mu        sync.Mutex
	stream    net.Conn
	wanted    bool
	in        chan []byte
	closed    chan struct{}
	echoNonce [control.UDPEchoNonce]byte
	echoSent  time.Time
	wake      chan struct{}
}

func newTCPFallback(base conn.Bind, logger *slog.Logger, now func() time.Time) *tcpFallback {
	return &tcpFallback{Bind: base, logger: logger, now: now, echoFirst: tcpEchoFirst, wake: make(chan struct{}, 1)}
}

// setCoordinator records the coordinator's UDP endpoint.
func (t *tcpFallback) setCoordinator(ap netip.AddrPort) {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if cur := t.coord.Load(); cur != nil && *cur == ap {
		return
	}
	t.coord.Store(&ap)
	if ep, err := t.Bind.ParseEndpoint(ap.String()); err == nil {
		t.coordEP.Store(&ep)
	}
}

// Active reports whether coordinator traffic goes over TCP.
func (t *tcpFallback) Active() bool { return t.active.Load() }

// want asks for (or stops asking for) the TCP transport.
func (t *tcpFallback) want(on bool) {
	t.mu.Lock()
	changed := t.wanted != on
	t.wanted = on
	t.mu.Unlock()
	if changed {
		t.signal()
	}
}

func (t *tcpFallback) signal() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *tcpFallback) isCoordinator(ep conn.Endpoint) bool {
	c := t.coord.Load()
	if c == nil || ep == nil {
		return false
	}
	ap, err := netip.ParseAddrPort(ep.DstToString())
	return err == nil && ap.Port() == c.Port() && ap.Addr().Unmap() == c.Addr()
}

func (t *tcpFallback) Send(bufs [][]byte, ep conn.Endpoint) error {
	if t.forced && !t.isCoordinator(ep) {
		return nil // Tor: no UDP may leave this device (ADR-0044)
	}
	if !t.active.Load() || !t.isCoordinator(ep) {
		return t.Bind.Send(bufs, ep)
	}
	var out []byte
	for _, b := range bufs {
		var err error
		if out, err = control.AppendFrame(out, b); err != nil {
			return err
		}
	}
	t.mu.Lock()
	s := t.stream
	t.mu.Unlock()
	if s == nil {
		if t.forced {
			return nil
		}
		// No stream (yet): keep trying UDP too, it may work again.
		return t.Bind.Send(bufs, ep)
	}
	_ = s.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
	if _, err := s.Write(out); err != nil {
		_ = s.Close() // the reader notices and the stream is redialled
		return nil
	}
	return nil
}

func (t *tcpFallback) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := t.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = t.echoFilter(fn)
	}
	in, closed := make(chan []byte, tcpInQueue), make(chan struct{})
	t.mu.Lock()
	t.in, t.closed = in, closed
	t.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			select {
			case f := <-in:
				ep := t.coordEP.Load()
				if ep == nil {
					continue
				}
				sizes[0] = copy(packets[0], f)
				eps[0] = *ep
				return 1, nil
			case <-closed:
				return 0, net.ErrClosed
			}
		}
	}
	return append(fns, recv), actual, nil
}

func (t *tcpFallback) Close() error {
	t.mu.Lock()
	if t.closed != nil {
		close(t.closed)
		t.closed, t.in = nil, nil
	}
	t.mu.Unlock()
	return t.Bind.Close()
}

// SetMark records the mark for the stream and passes it on.
func (t *tcpFallback) SetMark(mark uint32) error {
	t.mark.Store(mark)
	return t.Bind.SetMark(mark)
}

// BindSocketToInterface4 and 6 record the interface for the stream and pass
// the binding on when the UDP bind supports it.
func (t *tcpFallback) BindSocketToInterface4(index uint32, blackhole bool) error {
	t.ifIndex4.Store(index)
	if x, ok := t.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface4(index, blackhole)
	}
	return nil
}

func (t *tcpFallback) BindSocketToInterface6(index uint32, blackhole bool) error {
	t.ifIndex6.Store(index)
	if x, ok := t.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface6(index, blackhole)
	}
	return nil
}

// echoFilter takes UDP echo replies out of the receive path; a reply that
// matches the outstanding request from the coordinator means UDP works.
func (t *tcpFallback) echoFilter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for i := 0; i < n; i++ {
			data := packets[i][:sizes[i]]
			if control.IsUDPEcho(data, control.UDPEchoReply) {
				t.echoReply(data, eps[i])
				continue
			}
			if kept != i {
				sizes[kept] = copy(packets[kept], packets[i][:sizes[i]])
				eps[kept] = eps[i]
			}
			kept++
		}
		return kept, err
	}
}

func (t *tcpFallback) echoReply(data []byte, from conn.Endpoint) {
	if !t.isCoordinator(from) {
		return
	}
	t.mu.Lock()
	ok := t.wanted && !t.echoSent.IsZero() && t.now().Sub(t.echoSent) <= tcpEchoWait &&
		string(data[len(control.UDPEchoReply):]) == string(t.echoNonce[:])
	if ok {
		t.wanted = false
		t.echoSent = time.Time{}
	}
	t.mu.Unlock()
	if !ok {
		return
	}
	t.logger.Info("UDP to the coordinator works again; leaving the TCP transport")
	t.signal()
}

// sendEcho asks the coordinator, over UDP, whether UDP works.
func (t *tcpFallback) sendEcho() {
	ep := t.coordEP.Load()
	if ep == nil {
		return
	}
	pkt := make([]byte, control.UDPEchoLen)
	copy(pkt, control.UDPEchoRequest)
	t.mu.Lock()
	if _, err := rand.Read(t.echoNonce[:]); err != nil {
		t.mu.Unlock()
		return
	}
	copy(pkt[len(control.UDPEchoRequest):], t.echoNonce[:])
	t.echoSent = t.now()
	t.mu.Unlock()
	_ = t.Bind.Send([][]byte{pkt}, *ep)
}

// run keeps a stream open while TCP is wanted, until ctx ends.
func (t *tcpFallback) run(ctx context.Context) {
	defer t.closeStream()
	redial := tcpRedialFirst
	echoWait := t.echoFirst
	var nextEcho time.Time
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		t.mu.Lock()
		wanted, stream := t.wanted, t.stream
		t.mu.Unlock()
		wait := time.Hour
		switch {
		case !wanted:
			if t.active.Swap(false) {
				t.closeStream()
				if t.onUDP != nil {
					t.onUDP()
				}
			}
			redial, echoWait, nextEcho = tcpRedialFirst, t.echoFirst, time.Time{}
		case stream == nil:
			if !t.active.Swap(true) {
				t.logger.Info("coordinator unreachable over UDP; trying the TCP transport")
			}
			s, err := t.dial(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				t.logger.Debug("tcp transport", "error", err.Error())
				wait = redial
				redial = min(2*redial, tcpRedialMax)
				break
			}
			t.mu.Lock()
			t.stream = s
			t.mu.Unlock()
			go t.readLoop(s)
			redial = tcpRedialFirst
			if nextEcho.IsZero() {
				nextEcho = t.now().Add(echoWait)
			}
			t.logger.Info("coordinator reached over the TCP transport")
			if t.onUp != nil {
				t.onUp()
			}
			wait = 0
		default:
			if t.forced {
				break // no UDP echo: the stream is the only path
			}
			now := t.now()
			if !now.Before(nextEcho) {
				t.sendEcho()
				echoWait = min(2*echoWait, tcpEchoMax)
				nextEcho = now.Add(echoWait)
			}
			wait = nextEcho.Sub(now)
		}
		if wait == 0 {
			continue
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-t.wake:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

// readLoop hands frames from the stream to WireGuard until it fails.
func (t *tcpFallback) readLoop(s net.Conn) {
	defer func() {
		t.mu.Lock()
		if t.stream == s {
			t.stream = nil
		}
		t.mu.Unlock()
		_ = s.Close()
		t.signal()
	}()
	buf := make([]byte, control.TCPMaxFrame)
	for {
		_ = s.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		msg, err := control.ReadFrame(s, buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				t.logger.Debug("tcp transport read", "error", err.Error())
			}
			return
		}
		t.mu.Lock()
		in := t.in
		t.mu.Unlock()
		if in == nil {
			continue
		}
		select {
		case in <- append([]byte(nil), msg...):
		default:
		}
	}
}

func (t *tcpFallback) closeStream() {
	t.mu.Lock()
	s := t.stream
	t.stream = nil
	t.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
}

// dialStream connects to addr, bypassing the tunnel like the UDP sockets,
// and exchanges the preamble.
func (t *tcpFallback) dialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	idx := t.ifIndex4.Load()
	if addr.Addr().Is6() && !addr.Addr().Is4In6() {
		idx = t.ifIndex6.Load()
	}
	d := net.Dialer{Timeout: tcpDialTimeout, Control: func(network, _ string, c syscall.RawConn) error {
		return tcpSocketControl(network, c, t.mark.Load(), idx)
	}}
	cctx, cancel := context.WithTimeout(ctx, tcpDialTimeout)
	defer cancel()
	s, err := d.DialContext(cctx, "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	if t.camo != nil {
		if s, err = t.camo(s); err != nil {
			return nil, fmt.Errorf("%s: TLS: %w", addr, err)
		}
	}
	_ = s.SetDeadline(time.Now().Add(tcpDialTimeout))
	if err := t.preamble(s); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("%s: %w", addr, err)
	}
	_ = s.SetDeadline(time.Time{})
	return s, nil
}

// dialCoordinatorTCP opens a stream to the coordinator's TCP transport.
func (e *Engine) dialCoordinatorTCP(ctx context.Context) (net.Conn, error) {
	target := e.cfg.TCPFallback
	if target == "" {
		doc := e.cfg.Store.Document()
		if doc.Coordinator == nil {
			return nil, errors.New("no coordinator")
		}
		host, _, err := net.SplitHostPort(doc.Coordinator.Endpoint)
		if err != nil {
			return nil, err
		}
		target = net.JoinHostPort(host, strconv.Itoa(control.DefaultTCPPort))
	}
	ap, err := e.resolveEndpoint(ctx, target)
	if err != nil {
		return nil, err
	}
	return e.tcp.dialStream(ctx, ap)
}

// kickCoordinator starts a handshake with the coordinator at once (the
// transport underneath changed).
func (e *Engine) kickCoordinator() {
	doc := e.cfg.Store.Document()
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil || doc.Coordinator == nil {
		return
	}
	if p := dev.LookupPeer(device.NoisePublicKey(doc.Coordinator.WireGuardKey)); p != nil {
		_ = p.SendHandshakeInitiation(false)
	}
}

// updateTransport turns the TCP transport on when syncs keep failing while
// nothing at all arrives from the coordinator over UDP, and off when syncs
// work again without a stream (UDP came back while TCP could not connect).
func (e *Engine) updateTransport(syncErr error) {
	if e.tcp == nil {
		return
	}
	var rx uint64
	if st, err := e.wgStatus(); err == nil {
		if c := e.cfg.Store.Document().Coordinator; c != nil {
			rx = st.Peers[c.WireGuardKey].RxBytes
		}
	}
	active := e.tcp.Active()
	e.mu.Lock()
	defer e.mu.Unlock()
	if syncErr == nil {
		e.udpFails, e.coordRx = 0, rx
		if active && !e.tcp.forced && !e.tcp.hasStream() {
			e.tcp.want(false)
		}
		return
	}
	if active {
		return
	}
	if e.udpFails == 0 || rx != e.coordRx {
		e.udpFails, e.coordRx = 1, rx
	} else {
		e.udpFails++
	}
	if e.udpFails >= tcpFallbackFails {
		e.tcp.want(true)
	}
}

// CoordinatorOverTCP reports whether the coordinator is reached over the
// TCP transport right now (ADR-0032).
func (e *Engine) CoordinatorOverTCP() bool {
	return e.tcp != nil && e.tcp.Active() && e.tcp.hasStream()
}

func (t *tcpFallback) hasStream() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stream != nil
}
