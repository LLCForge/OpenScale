package coordinator

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
)

// memBind is a UDP bind stand-in: it records sends and delivers queued
// datagrams to its single receive function.
type memBind struct {
	mu   sync.Mutex
	sent [][]byte
	to   []conn.Endpoint
	in   chan memPkt
	done chan struct{}
}

type memPkt struct {
	data []byte
	from conn.Endpoint
}

func newMemBind() *memBind { return &memBind{in: make(chan memPkt, 16), done: make(chan struct{})} }

func (b *memBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p := <-b.in:
			sizes[0] = copy(packets[0], p.data)
			eps[0] = p.from
			return 1, nil
		case <-b.done:
			return 0, net.ErrClosed
		}
	}}, 51820, nil
}
func (b *memBind) Close() error         { return nil }
func (b *memBind) SetMark(uint32) error { return nil }
func (b *memBind) BatchSize() int       { return 1 }
func (b *memBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, buf := range bufs {
		b.sent = append(b.sent, append([]byte(nil), buf...))
		b.to = append(b.to, ep)
	}
	return nil
}
func (b *memBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

func startTCPBind(t *testing.T, maxConns, perIP int) (*tcpBind, *memBind, conn.ReceiveFunc, string) {
	t.Helper()
	base := newMemBind()
	tb := newTCPBind(base, slog.New(slog.DiscardHandler), maxConns, perIP)
	fns, _, err := tb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		close(base.done)
		_ = tb.Close()
	})
	go tb.serve(ctx, ln)
	return tb, base, fns[len(fns)-1], ln.Addr().String()
}

func dialTransport(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, control.TCPMagic); err != nil {
		t.Fatal(err)
	}
	return c
}

func wgFrame(typ byte, n int) []byte {
	m := make([]byte, n)
	m[0] = typ
	f, _ := control.AppendFrame(nil, m)
	return f
}

// Frames from a connection reach WireGuard as one endpoint per connection,
// and WireGuard's answers to that endpoint go back on the connection.
func TestTCPTransportCarriesFrames(t *testing.T) {
	tb, _, recv, addr := startTCPBind(t, 8, 8)
	c := dialTransport(t, addr)
	if err := control.ReadMagic(c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wgFrame(1, 148)); err != nil {
		t.Fatal(err)
	}
	packets, sizes, eps := [][]byte{make([]byte, 2048)}, []int{0}, []conn.Endpoint{nil}
	n, err := recv(packets, sizes, eps)
	if err != nil || n != 1 || sizes[0] != 148 || packets[0][0] != 1 {
		t.Fatalf("recv = %d %v size %d", n, err, sizes[0])
	}
	ep, ok := eps[0].(*tcpEndpoint)
	if !ok {
		t.Fatalf("endpoint %T", eps[0])
	}
	if _, err := netip.ParseAddrPort(ep.DstToString()); err == nil {
		t.Fatal("a TCP endpoint must not look like a UDP address to other devices")
	}
	reply := make([]byte, 92)
	reply[0] = 2
	if err := tb.Send([][]byte{reply}, ep); err != nil {
		t.Fatal(err)
	}
	got, err := control.ReadFrame(c, make([]byte, control.TCPMaxFrame))
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("reply %d bytes, %v", len(got), err)
	}
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	for {
		_, err := c.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("connection was not closed")
			}
			return
		}
	}
}

func TestTCPTransportLimits(t *testing.T) {
	tb, _, _, addr := startTCPBind(t, 8, 2)
	c1, c2 := dialTransport(t, addr), dialTransport(t, addr)
	for _, c := range []net.Conn{c1, c2} {
		if err := control.ReadMagic(c); err != nil {
			t.Fatal(err)
		}
	}
	// The third connection from the same address is refused.
	c3, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	expectClosed(t, c3)
	if n := tb.connCount(); n != 2 {
		t.Fatalf("%d connections open", n)
	}
}

func TestTCPTransportClosesOnBadInput(t *testing.T) {
	_, _, _, addr := startTCPBind(t, 8, 8)
	// A foreign preamble.
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\n\r\n")
	expectClosed(t, c)
	// A frame that is not a WireGuard message.
	c2 := dialTransport(t, addr)
	if err := control.ReadMagic(c2); err != nil {
		t.Fatal(err)
	}
	_, _ = c2.Write([]byte{0, 8, 9, 9, 9, 9, 9, 9, 9, 9})
	expectClosed(t, c2)
	// An oversized frame header.
	c3 := dialTransport(t, addr)
	if err := control.ReadMagic(c3); err != nil {
		t.Fatal(err)
	}
	_, _ = c3.Write([]byte{0xff, 0xff})
	expectClosed(t, c3)
}

// The UDP echo is answered with a reply of the same size and never reaches
// WireGuard.
func TestUDPEchoAnswered(t *testing.T) {
	base := newMemBind()
	tb := newTCPBind(base, slog.New(slog.DiscardHandler), 8, 8)
	fns, _, err := tb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer close(base.done)
	from := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:4000")}
	req := append([]byte(control.UDPEchoRequest), bytes.Repeat([]byte{7}, control.UDPEchoNonce)...)
	base.in <- memPkt{data: req, from: from}
	wg := make([]byte, 148)
	wg[0] = 1
	base.in <- memPkt{data: wg, from: from}
	packets, sizes, eps := [][]byte{make([]byte, 2048)}, []int{0}, []conn.Endpoint{nil}
	for {
		n, err := fns[0](packets, sizes, eps)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
	}
	if sizes[0] != 148 {
		t.Fatalf("WireGuard saw %d bytes; the echo was not filtered", sizes[0])
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.sent) != 1 || len(base.sent[0]) != len(req) || !control.IsUDPEcho(base.sent[0], control.UDPEchoReply) ||
		!bytes.Equal(base.sent[0][len(control.UDPEchoReply):], req[len(control.UDPEchoRequest):]) {
		t.Fatalf("echo reply %q", base.sent)
	}
}

func TestTCPLimitsValidated(t *testing.T) {
	if err := validTCPLimits(-1, 0); err == nil {
		t.Fatal("negative limit accepted")
	}
	if err := validTCPLimits(MaxTCPMaxConns+1, 0); err == nil {
		t.Fatal("limit above the maximum accepted")
	}
	if err := validTCPLimits(0, 0); err != nil {
		t.Fatal(err)
	}
}
