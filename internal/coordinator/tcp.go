package coordinator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/obfs"
)

// TCP fallback transport (ADR-0032). Devices on networks that block UDP
// carry their WireGuard datagrams to the coordinator over TCP, framed as
// control.AppendFrame describes. To WireGuard every TCP connection is just
// another endpoint: it authenticates each datagram itself, and its roaming
// sends the answers back on the connection the device used last. No TLS:
// WireGuard already encrypts everything (R-20).
//
// The listener is off unless Config.TCPListen is set. Every connection is
// bounded: a total and per-address connection limit, a frame size limit,
// a deadline for the preamble, an idle timeout and a write timeout.

// TCP transport defaults and bounds.
const (
	DefaultTCPMaxConns      = 256
	MaxTCPMaxConns          = 4096
	DefaultTCPMaxConnsPerIP = 8
	// tcpPreambleTimeout: the client must send its preamble this fast.
	tcpPreambleTimeout = 10 * time.Second
	// tcpIdleTimeout closes a connection that carried nothing; devices send
	// a WireGuard keepalive every 25 seconds.
	tcpIdleTimeout  = 3 * time.Minute
	tcpWriteTimeout = 10 * time.Second
	tcpWriteQueue   = 256
	tcpInQueue      = 1024
	tcpEndpointPfx  = "tcp-"
	// UDP echo replies are rate-limited (no amplification: same size).
	echoRate  = 100
	echoBurst = 200
)

// tcpEndpoint is a device connected over TCP.
type tcpEndpoint struct {
	id     uint64
	remote netip.AddrPort
}

func (e *tcpEndpoint) ClearSrc()           {}
func (e *tcpEndpoint) SrcToString() string { return "" }

// DstToString is not an address, so the coordinator never hands it to
// other devices as an endpoint (they reach this device through the relay).
func (e *tcpEndpoint) DstToString() string {
	return tcpEndpointPfx + strconv.FormatUint(e.id, 10)
}
func (e *tcpEndpoint) DstToBytes() []byte {
	b, _ := e.remote.MarshalBinary()
	return b
}
func (e *tcpEndpoint) DstIP() netip.Addr { return e.remote.Addr() }
func (e *tcpEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

type tcpFrame struct {
	ep   *tcpEndpoint
	data []byte
}

type tcpConn struct {
	ep  *tcpEndpoint
	c   net.Conn
	out chan []byte
}

// tcpBind adds TCP connections and the UDP echo to the coordinator's UDP
// bind.
type tcpBind struct {
	conn.Bind
	logger   *slog.Logger
	maxConns int
	perIP    int
	now      func() time.Time

	mu     sync.Mutex
	conns  map[uint64]*tcpConn
	byIP   map[netip.Addr]int
	nextID uint64
	in     chan tcpFrame
	closed chan struct{}

	// knock, when set, must accept the connection's first bytes before the
	// preamble (port hiding, g2_spa.go, #614).
	// It gets the connection and the 61 knock bytes already read.
	knock func(net.Conn, []byte) bool

	echoMu     sync.Mutex
	echoTokens float64
	echoAt     time.Time
}

func newTCPBind(base conn.Bind, logger *slog.Logger, maxConns, perIP int) *tcpBind {
	return &tcpBind{Bind: base, logger: logger, maxConns: maxConns, perIP: perIP, now: time.Now,
		conns: map[uint64]*tcpConn{}, byIP: map[netip.Addr]int{}, echoTokens: echoBurst}
}

// validTCPLimits checks configured limits; zero means default.
func validTCPLimits(maxConns, perIP int) error {
	if maxConns < 0 || maxConns > MaxTCPMaxConns {
		return fmt.Errorf("TCP bağlantı sınırı 1 ile %d arasında olmalı", MaxTCPMaxConns)
	}
	if perIP < 0 || perIP > MaxTCPMaxConns {
		return fmt.Errorf("adres başına TCP bağlantı sınırı 1 ile %d arasında olmalı", MaxTCPMaxConns)
	}
	return nil
}

func (b *tcpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = b.echoFilter(fn)
	}
	in, closed := make(chan tcpFrame, tcpInQueue), make(chan struct{})
	b.mu.Lock()
	b.in, b.closed = in, closed
	b.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case f := <-in:
			sizes[0] = copy(packets[0], f.data)
			eps[0] = f.ep
			return 1, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	}
	return append(fns, recv), actual, nil
}

func (b *tcpBind) Close() error {
	b.mu.Lock()
	if b.closed != nil {
		close(b.closed)
		b.closed, b.in = nil, nil
	}
	b.mu.Unlock()
	return b.Bind.Close()
}

func (b *tcpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	te, ok := ep.(*tcpEndpoint)
	if !ok {
		return b.Bind.Send(bufs, ep)
	}
	b.mu.Lock()
	c := b.conns[te.id]
	b.mu.Unlock()
	if c == nil {
		// The connection is gone; the device reconnects and WireGuard
		// roams to the new one. Dropped quietly, like a lost datagram.
		return nil
	}
	for _, buf := range bufs {
		frame, err := control.AppendFrame(nil, buf)
		if err != nil {
			continue
		}
		select {
		case c.out <- frame:
		default:
			// Queue full (slow reader): drop; WireGuard and TCP above
			// recover, and the coordinator never blocks on one device.
		}
	}
	return nil
}

func (b *tcpBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if strings.HasPrefix(s, tcpEndpointPfx) {
		return nil, errors.New("a TCP endpoint cannot be configured")
	}
	return b.Bind.ParseEndpoint(s)
}

// echoFilter answers UDP echo requests (ADR-0032) and hides them from
// WireGuard. Kept packets are moved to the front by copying, as WireGuard
// pairs each buffer with its own backing array.
func (b *tcpBind) echoFilter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for i := 0; i < n; i++ {
			data := packets[i][:sizes[i]]
			if control.IsUDPEcho(data, control.UDPEchoRequest) {
				if eps[i] != nil && b.takeEcho() {
					reply := make([]byte, control.UDPEchoLen)
					copy(reply, control.UDPEchoReply)
					copy(reply[len(control.UDPEchoReply):], data[len(control.UDPEchoRequest):])
					_ = b.Bind.Send([][]byte{reply}, eps[i])
				}
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

func (b *tcpBind) takeEcho() bool {
	b.echoMu.Lock()
	defer b.echoMu.Unlock()
	now := b.now()
	if !b.echoAt.IsZero() {
		b.echoTokens = min(echoBurst, b.echoTokens+now.Sub(b.echoAt).Seconds()*echoRate)
	}
	b.echoAt = now
	if b.echoTokens < 1 {
		return false
	}
	b.echoTokens--
	return true
}

// serve accepts connections until ctx ends or the listener fails.
func (b *tcpBind) serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var tempDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				b.closeAll()
				return
			}
			// Out of file descriptors and the like: back off, never spin.
			tempDelay = min(max(2*tempDelay, 5*time.Millisecond), time.Second)
			b.logger.Warn("tcp transport accept", "error", err.Error())
			select {
			case <-time.After(tempDelay):
			case <-ctx.Done():
			}
			continue
		}
		tempDelay = 0
		tc := b.admit(c)
		if tc == nil {
			_ = c.Close()
			continue
		}
		go b.handle(ctx, tc)
	}
}

// admit applies the connection limits.
func (b *tcpBind) admit(c net.Conn) *tcpConn {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return nil
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.conns) >= b.maxConns || b.byIP[ap.Addr()] >= b.perIP {
		return nil
	}
	b.nextID++
	tc := &tcpConn{ep: &tcpEndpoint{id: b.nextID, remote: ap}, c: c, out: make(chan []byte, tcpWriteQueue)}
	b.conns[tc.ep.id] = tc
	b.byIP[ap.Addr()]++
	return tc
}

func (b *tcpBind) drop(tc *tcpConn) {
	b.mu.Lock()
	if b.conns[tc.ep.id] == tc {
		delete(b.conns, tc.ep.id)
		if b.byIP[tc.ep.remote.Addr()]--; b.byIP[tc.ep.remote.Addr()] <= 0 {
			delete(b.byIP, tc.ep.remote.Addr())
		}
	}
	b.mu.Unlock()
	_ = tc.c.Close()
}

func (b *tcpBind) closeAll() {
	b.mu.Lock()
	conns := make([]*tcpConn, 0, len(b.conns))
	for _, tc := range b.conns {
		conns = append(conns, tc)
	}
	b.mu.Unlock()
	for _, tc := range conns {
		b.drop(tc)
	}
}

// handle runs one connection: preamble, then frames in both directions.
func (b *tcpBind) handle(ctx context.Context, tc *tcpConn) {
	defer b.drop(tc)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = tc.c.SetDeadline(time.Now().Add(tcpPreambleTimeout))
	r, ok := b.readKnock(tc.c)
	if !ok {
		return // silent: no preamble for a connection without a knock
	}
	if err := control.ReadMagic(r); err != nil {
		return
	}
	if _, err := io.WriteString(tc.c, control.TCPMagic); err != nil {
		return
	}
	_ = tc.c.SetDeadline(time.Time{})
	go b.writeLoop(cctx, tc, cancel)
	buf := make([]byte, control.TCPMaxFrame)
	for {
		_ = tc.c.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		msg, err := control.ReadFrame(tc.c, buf)
		if err != nil {
			return
		}
		b.mu.Lock()
		in := b.in
		b.mu.Unlock()
		if in == nil {
			continue
		}
		select {
		case in <- tcpFrame{ep: tc.ep, data: append([]byte(nil), msg...)}:
		default:
		}
	}
}

// readKnock reads an optional SPA knock at the start of a stream (#614).
// With port hiding on, the knock is required; without it a knock is read
// and ignored, so devices that knock (they cannot know whether the gate is
// on) still reach a coordinator that does not hide its port. It returns
// the reader the preamble follows on.
func (b *tcpBind) readKnock(c net.Conn) (io.Reader, bool) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return nil, false
	}
	if string(head[:]) != obfs.SPAMagic {
		if b.knock != nil {
			return nil, false
		}
		return io.MultiReader(bytes.NewReader(head[:]), c), true
	}
	knock := make([]byte, obfs.SPAKnockSize)
	copy(knock, head[:])
	if _, err := io.ReadFull(c, knock[4:]); err != nil {
		return nil, false
	}
	if b.knock == nil {
		return c, true
	}
	return c, b.knock(c, knock)
}

func (b *tcpBind) writeLoop(ctx context.Context, tc *tcpConn, fail context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			_ = tc.c.Close()
			return
		case frame := <-tc.out:
			_ = tc.c.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
			if _, err := tc.c.Write(frame); err != nil {
				fail()
				_ = tc.c.Close()
				return
			}
		}
	}
}

// connCount is the number of open TCP connections (tests, diagnostics).
func (b *tcpBind) connCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.conns)
}
