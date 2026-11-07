package node

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/filter"
)

// failingTUN is an OS interface whose reads and writes fail on demand.
type failingTUN struct {
	readErr  atomic.Pointer[error]
	writeErr atomic.Pointer[error]
	reads    atomic.Int32
	closed   chan struct{}
	once     sync.Once
	events   chan tun.Event
	packets  chan []byte
}

func newFailingTUN() *failingTUN {
	return &failingTUN{closed: make(chan struct{}), events: make(chan tun.Event), packets: make(chan []byte, 8)}
}

func (f *failingTUN) setReadErr(err error)  { f.readErr.Store(&err) }
func (f *failingTUN) setWriteErr(err error) { f.writeErr.Store(&err) }

func (f *failingTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.reads.Add(1)
	if p := f.readErr.Load(); p != nil && *p != nil {
		return 0, *p
	}
	select {
	case pkt := <-f.packets:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	case <-time.After(5 * time.Millisecond):
		return 0, nil
	}
}

func (f *failingTUN) Write(bufs [][]byte, offset int) (int, error) {
	if p := f.writeErr.Load(); p != nil && *p != nil {
		return 0, *p
	}
	return len(bufs), nil
}

func (f *failingTUN) File() *os.File           { return nil }
func (f *failingTUN) MTU() (int, error)        { return 1280, nil }
func (f *failingTUN) Name() (string, error)    { return "test0", nil }
func (f *failingTUN) Events() <-chan tun.Event { return f.events }
func (f *failingTUN) BatchSize() int           { return 1 }
func (f *failingTUN) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testWrap(inner tun.Device, failAfter time.Duration) *wrapTUN {
	return newWrapTUN(inner, wrapOptions{
		filter: filter.New(time.Now), intercept: func([]byte) bool { return false },
		logger: quietLogger(), failAfter: failAfter, failMinErrors: 4,
	})
}

func TestWrapTUNDetectsPersistentReadErrors(t *testing.T) {
	f := newFailingTUN()
	w := testWrap(f, 200*time.Millisecond)
	defer w.Close()
	f.setReadErr(errors.New("read /dev/net/tun: file descriptor in bad state"))
	select {
	case <-w.Failed():
	case <-time.After(5 * time.Second):
		t.Fatal("persistent read errors not detected")
	}
	if !errors.Is(w.Err(), ErrTunnelLost) {
		t.Fatalf("Err %v", w.Err())
	}
	// The loop paused between errors instead of spinning.
	if n := f.reads.Load(); n > 200 {
		t.Fatalf("%d reads in the failure window: busy loop", n)
	}
}

func TestWrapTUNSurvivesTransientErrors(t *testing.T) {
	f := newFailingTUN()
	w := testWrap(f, 300*time.Millisecond)
	defer w.Close()
	for i := 0; i < 5; i++ {
		f.setReadErr(errors.New("temporary"))
		time.Sleep(20 * time.Millisecond)
		f.setReadErr(nil)
		time.Sleep(20 * time.Millisecond)
	}
	f.setReadErr(tun.ErrTooManySegments)
	time.Sleep(400 * time.Millisecond)
	f.setReadErr(nil)
	select {
	case <-w.Failed():
		t.Fatalf("transient errors treated as fatal: %v", w.Err())
	case <-time.After(200 * time.Millisecond):
	}
}

func TestWrapTUNClosedUnderneath(t *testing.T) {
	f := newFailingTUN()
	w := testWrap(f, time.Hour)
	defer w.Close()
	f.setReadErr(os.ErrClosed) // Wintun adapter removed
	select {
	case <-w.Failed():
	case <-time.After(5 * time.Second):
		t.Fatal("closed interface not detected")
	}
	// Our own Close is not a failure.
	g := newFailingTUN()
	w2 := testWrap(g, time.Hour)
	_ = w2.Close()
	select {
	case <-w2.Failed():
		t.Fatal("Close reported as a failure")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWrapTUNDetectsPersistentWriteErrors(t *testing.T) {
	f := newFailingTUN()
	w := testWrap(f, 100*time.Millisecond)
	defer w.Close()
	f.setWriteErr(errors.New("write: input/output error"))
	pkt := make([]byte, readOffset+20)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		w.writeOS(pkt[readOffset:])
		select {
		case <-w.Failed():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("persistent write errors not detected")
}

// recvOnce returns the given packets from a fake socket.
func recvOnce(froms []netip.AddrPort) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for i, from := range froms {
			sizes[i] = copy(packets[i], []byte{byte(i), byte(i), byte(i)})
			eps[i] = &conn.StdNetEndpoint{AddrPort: from}
		}
		return len(froms), nil
	}
}

func TestForceRelayBindTalksToCoordinatorOnly(t *testing.T) {
	coord := netip.MustParseAddrPort("203.0.113.1:51820")
	peer := netip.MustParseAddrPort("198.51.100.4:41641")
	b := newRelayBind(nil, func([control.RelayIDLen]byte, []byte) bool { return true }, true)

	fn := b.onlyCoordinator(recvOnce([]netip.AddrPort{peer, coord, peer, coord}))
	packets := make([][]byte, 4)
	for i := range packets {
		packets[i] = make([]byte, 16)
	}
	sizes, eps := make([]int, 4), make([]conn.Endpoint, 4)
	// Before the coordinator is known nothing gets through.
	if n, err := fn(packets, sizes, eps); n != 0 || err != nil {
		t.Fatalf("received %d (%v) without a known coordinator", n, err)
	}
	b.setCoordinator(coord.Addr())
	n, err := fn(packets, sizes, eps)
	if err != nil || n != 2 {
		t.Fatalf("received %d packets (%v), want the coordinator's 2", n, err)
	}
	for i := 0; i < n; i++ {
		if eps[i].DstIP() != coord.Addr() {
			t.Fatalf("packet %d from %v", i, eps[i].DstIP())
		}
	}
	// Kept packets were moved to the front with their data.
	if packets[0][0] != 1 || packets[1][0] != 3 || sizes[0] != 3 {
		t.Fatalf("compaction wrong: %v %v", packets[:2], sizes[:2])
	}

	// Sending: direct to a peer is dropped, the relay endpoint is used.
	sent := 0
	b.send = func([control.RelayIDLen]byte, []byte) bool { sent++; return true }
	if err := b.Send([][]byte{{1}}, &conn.StdNetEndpoint{AddrPort: peer}); err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, &relayEndpoint{}); err != nil || sent != 1 {
		t.Fatalf("relay send %v, sent %d", err, sent)
	}

	// Without forcing, everything passes.
	free := newRelayBind(nil, nil, false)
	if !free.directAllowed(peer.Addr()) {
		t.Fatal("direct path refused without forcing")
	}
}

func TestMarkBindGoesThroughDevice(t *testing.T) {
	var got []uint32
	mb := markBind{relayBind: newRelayBind(nil, nil, false), setMark: func(m uint32) error { got = append(got, m); return nil }}
	var b conn.Bind = mb
	if err := b.SetMark(0x4f53); err != nil {
		t.Fatal(err)
	}
	if err := b.SetMark(0); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 0x4f53 || got[1] != 0 {
		t.Fatalf("marks %v", got)
	}
	// Interface binding (Windows exit node) still reaches the real bind.
	if _, ok := b.(conn.BindSocketToInterface); !ok {
		t.Fatal("markBind lost BindSocketToInterface")
	}
}
