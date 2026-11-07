package node

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/packet"
)

const (
	// readOffset leaves headroom for the virtio header Linux TUN offload
	// needs in front of each packet.
	readOffset    = 16
	maxPacketSize = 65535
	queueLen      = 1024
)

// Persistent TUN failure detection (F-146). An interface deleted from
// outside, or a driver gone bad, makes every read or write fail; transient
// errors (a full queue, a dropped packet) do not last.
const (
	// tunFailAfter: errors without a single success for this long ...
	tunFailAfter = 3 * time.Second
	// tunFailMinErrors: ... and at least this many in a row mean the
	// interface is gone.
	tunFailMinErrors = 8
	// tunErrPauseMax caps the pause between failed reads, so a dead
	// interface never turns the read loop into a busy loop.
	tunErrPauseMax = 250 * time.Millisecond
)

// ErrTunnelLost is returned by Engine.Run when the tunnel interface stopped
// working (deleted from outside, driver failure). The caller may recreate
// the interface and start a new engine.
var ErrTunnelLost = errors.New("tünel arayüzü kayboldu")

// wrapOptions configures a wrapTUN.
type wrapOptions struct {
	filter    *filter.Filter
	intercept func(pkt []byte) bool
	local     func(pkt []byte) (reply []byte, handled bool)
	logger    *slog.Logger
	// mtu is the tunnel MTU TCP MSS options are clamped to (F-048); zero
	// disables clamping.
	mtu int
	// touch, when set, sees every packet the filter passed: outbound before
	// WireGuard gets it (lazy peers are configured then, F-020), inbound
	// after.
	touch func(pkt []byte, outbound bool)
	// pad, when set, pads a packet of n bytes in buf before WireGuard gets
	// it and returns the new length (ADR-0043). classify, when set, sorts
	// packets from the OS into priority queues (prioHigh, prioNormal,
	// prioLow).
	pad      func(buf []byte, n int) int
	classify func(pkt []byte) int
	// failAfter and failMinErrors tune failure detection; zero uses the
	// defaults.
	failAfter     time.Duration
	failMinErrors int
	now           func() time.Time
}

// failTracker counts consecutive errors and decides when they persist.
type failTracker struct {
	mu        sync.Mutex
	after     time.Duration
	minErrors int
	first     time.Time
	count     int
}

// fail records one error and reports whether failures have persisted.
func (f *failTracker) fail(now time.Time) (consecutive int, persistent bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.count == 0 {
		f.first = now
	}
	f.count++
	return f.count, f.count >= f.minErrors && now.Sub(f.first) >= f.after
}

// ok resets the count after a success.
func (f *failTracker) ok() {
	f.mu.Lock()
	f.count = 0
	f.mu.Unlock()
}

// wrapTUN sits between the OS interface and WireGuard. Packets from the OS
// pass the outbound filter; packets from peers pass the inbound filter;
// control replies from the coordinator are consumed here and never reach
// the OS; control requests are injected directly into WireGuard.
type wrapTUN struct {
	inner     tun.Device
	filter    *filter.Filter
	intercept func(pkt []byte) bool
	// local answers packets the OS addresses to this program (MagicDNS):
	// handled packets never reach WireGuard; a non-nil reply goes back to
	// the OS.
	local  func(pkt []byte) (reply []byte, handled bool)
	logger *slog.Logger
	mtu    int
	touch  func(pkt []byte, outbound bool)
	now    func() time.Time
	inject chan []byte
	fromOS chan []byte
	// pad, classify and the high/low queues: see wrapOptions (ADR-0043).
	pad        func(buf []byte, n int) int
	classify   func(pkt []byte) int
	fromOSHigh chan []byte
	fromOSLow  chan []byte
	closed     chan struct{}
	closeOnce  sync.Once

	readFails  failTracker
	writeFails failTracker
	failed     chan struct{}
	failOnce   sync.Once
	failErr    error
}

func newWrapTUN(inner tun.Device, o wrapOptions) *wrapTUN {
	if o.failAfter <= 0 {
		o.failAfter = tunFailAfter
	}
	if o.failMinErrors <= 0 {
		o.failMinErrors = tunFailMinErrors
	}
	if o.now == nil {
		o.now = time.Now
	}
	w := &wrapTUN{
		inner:      inner,
		filter:     o.filter,
		intercept:  o.intercept,
		local:      o.local,
		logger:     o.logger,
		mtu:        o.mtu,
		touch:      o.touch,
		now:        o.now,
		inject:     make(chan []byte, queueLen),
		fromOS:     make(chan []byte, queueLen),
		closed:     make(chan struct{}),
		readFails:  failTracker{after: o.failAfter, minErrors: o.failMinErrors},
		writeFails: failTracker{after: o.failAfter, minErrors: o.failMinErrors},
		failed:     make(chan struct{}),
		pad:        o.pad,
		classify:   o.classify,
	}
	if w.classify != nil {
		w.fromOSHigh, w.fromOSLow = make(chan []byte, queueLen), make(chan []byte, queueLen)
	}
	go w.readLoop()
	return w
}

// Failed is closed when the interface stopped working for good; Err then
// says why.
func (w *wrapTUN) Failed() <-chan struct{} { return w.failed }

// Err returns the failure that closed Failed, or nil.
func (w *wrapTUN) Err() error {
	select {
	case <-w.failed:
		return w.failErr
	default:
		return nil
	}
}

func (w *wrapTUN) fail(op string, err error) {
	w.failOnce.Do(func() {
		w.failErr = fmt.Errorf("%w: %s: %v", ErrTunnelLost, op, err)
		w.logger.Error("tunnel interface failed", "op", op, "error", err.Error())
		close(w.failed)
	})
}

// ioError handles a failed read or write of the OS interface. It returns
// the pause before the next attempt and whether to give up.
func (w *wrapTUN) ioError(op string, t *failTracker, err error) (time.Duration, bool) {
	if w.isClosed() {
		return 0, true
	}
	if errors.Is(err, os.ErrClosed) {
		// Closed underneath us (Wintun adapter removed): no retry helps.
		w.fail(op, err)
		return 0, true
	}
	n, persistent := t.fail(w.now())
	if persistent {
		w.fail(op, err)
		return 0, true
	}
	w.logger.Debug("tun "+op, "error", err.Error(), "consecutive", n)
	return min(time.Millisecond<<min(n, 16), tunErrPauseMax), false
}

func (w *wrapTUN) readLoop() {
	batch := max(w.inner.BatchSize(), 1)
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, readOffset+maxPacketSize)
	}
	sizes := make([]int, batch)
	for {
		n, err := w.inner.Read(bufs, sizes, readOffset)
		if n > 0 {
			w.readFails.ok()
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][readOffset : readOffset+sizes[i]]
			if w.local != nil {
				if reply, handled := w.local(pkt); handled {
					if reply != nil {
						w.writeOS(reply)
					}
					continue
				}
			}
			if !w.filter.Outbound(pkt) {
				continue
			}
			cp := append([]byte(nil), pkt...)
			if w.mtu > 0 {
				packet.ClampMSS(cp, w.mtu)
			}
			if w.touch != nil {
				w.touch(cp, true)
			}
			select {
			case w.queueFor(cp) <- cp:
			case <-w.closed:
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, tun.ErrTooManySegments) {
			continue // some packets of a large batch were dropped
		}
		pause, stop := w.ioError("read", &w.readFails, err)
		if stop {
			return
		}
		select {
		case <-time.After(pause):
		case <-w.closed:
			return
		}
	}
}

// Inject queues a packet for WireGuard as if the OS had sent it. It is used
// only for control requests and never blocks.
func (w *wrapTUN) Inject(pkt []byte) bool {
	select {
	case w.inject <- pkt:
		return true
	default:
		return false
	}
}

// writeOS hands a locally generated packet to the operating system.
func (w *wrapTUN) writeOS(pkt []byte) {
	buf := make([]byte, readOffset+len(pkt))
	copy(buf[readOffset:], pkt)
	if _, err := w.inner.Write([][]byte{buf}, readOffset); err != nil {
		_, _ = w.ioError("write", &w.writeFails, err)
		return
	}
	w.writeFails.ok()
}

func (w *wrapTUN) File() *os.File { return w.inner.File() }

func (w *wrapTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, err := w.next()
	if err != nil {
		return 0, err
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	if w.pad != nil {
		sizes[0] = w.pad(bufs[0][offset:], sizes[0])
	}
	return 1, nil
}

func (w *wrapTUN) Write(bufs [][]byte, offset int) (int, error) {
	pass := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		if offset > len(buf) {
			continue
		}
		pkt := buf[offset:]
		if w.intercept(pkt) {
			continue
		}
		if w.filter.Inbound(pkt) {
			if w.touch != nil {
				w.touch(pkt, false)
			}
			if w.mtu > 0 {
				// Peers' SYN and SYN-ACK too: the local end must not send
				// segments larger than the tunnel either.
				packet.ClampMSS(pkt, w.mtu)
			}
			pass = append(pass, buf)
		}
	}
	if len(pass) == 0 {
		return len(bufs), nil
	}
	if _, err := w.inner.Write(pass, offset); err != nil {
		_, _ = w.ioError("write", &w.writeFails, err)
		return 0, err
	}
	w.writeFails.ok()
	return len(bufs), nil
}

func (w *wrapTUN) MTU() (int, error)        { return w.inner.MTU() }
func (w *wrapTUN) Name() (string, error)    { return w.inner.Name() }
func (w *wrapTUN) Events() <-chan tun.Event { return w.inner.Events() }

// BatchSize is 1: Read hands over one packet at a time.
func (w *wrapTUN) BatchSize() int { return 1 }

func (w *wrapTUN) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.closed)
		err = w.inner.Close()
	})
	return err
}

func (w *wrapTUN) isClosed() bool {
	select {
	case <-w.closed:
		return true
	default:
		return false
	}
}
