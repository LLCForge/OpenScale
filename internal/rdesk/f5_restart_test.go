package rdesk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// F5: the answer to a restart request has to reach the viewer. Closing the
// socket with client data still unread makes the kernel send a reset, and
// Windows then drops the answer the viewer has not read yet.

func TestRestartReplySurvivesUnreadClientData(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h := newHarness(t, func(c *Config) {
		c.Power = func(context.Context, PowerRequest) error {
			close(entered)
			<-release
			return nil
		}
	})
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reply := make(chan error, 1)
	go func() { reply <- c.RequestRestart(ctx, false) }()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal("restart request did not reach the device")
	}
	// The read goroutine is inside the Power callback, so these bytes stay
	// unread in the server's socket buffer when the session ends.
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, werr := c.conn.Write(make([]byte, 32<<10))
	close(release)
	if werr != nil {
		t.Fatal(werr)
	}
	if err := <-reply; err != nil {
		t.Fatalf("restart answer lost: %v", err)
	}
	waitFor(t, "session end", func() bool { return c.Err() != nil })
	if err := c.Err(); !errors.Is(err, ErrSessionEnded) || !strings.Contains(err.Error(), "yeniden başlatılıyor") {
		t.Fatalf("session end reason lost: %v", err)
	}
}

// A reply that arrived together with the end of the session is the answer;
// the viewer must not report the end instead.
func TestWaitExtPrefersReplyOverSessionEnd(t *testing.T) {
	c := &Client{done: make(chan struct{})}
	c.ext.init("", false)
	close(c.done)
	ctx := testCtx(t)
	for range 200 {
		c.ext.replies[extPower] <- extReply{ok: true}
		r, err := c.waitExt(ctx, extPower)
		if err != nil || !r.ok {
			t.Fatalf("reply lost: %+v %v", r, err)
		}
	}
	c.fail(ErrSessionEnded)
	if _, err := c.waitExt(ctx, extPower); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("no reply must report the end: %v", err)
	}
}

func loopbackPair(t *testing.T) (server, peer *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	a, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*net.TCPConn), d.(*net.TCPConn)
}

// With unread data in the server's buffer the peer still gets everything
// that was written, followed by a clean end of stream instead of a reset.
func TestDrainBeforeCloseGivesCleanEOF(t *testing.T) {
	srv, peer := loopbackPair(t)
	want := []byte("son ileti")
	if _, err := peer.Write(make([]byte, 32<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Write(want); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the unread bytes reach the server
	done := make(chan struct{})
	go func() {
		defer close(done)
		drainBeforeClose(srv, endDrainTimeout)
		_ = srv.Close()
	}()
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(peer) // nil only on a clean end of stream
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %q, %v", got, err)
	}
	_ = peer.Close()
	<-done
}

// A peer that stopped reading holds the frame write in progress. The graceful
// end must cut it instead of waiting writeTimeout: Close waits on endOnce with
// the server lock held, so this would stall the whole server. No bye follows
// the cut write, because it would land in the middle of a frame.
func TestGracefulEndCutsStalledWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sess := &session{conn: a, w: &wire{}, cancel: func() {}}
	sess.wmu.Lock()
	writing := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		defer sess.wmu.Unlock()
		_ = a.SetWriteDeadline(time.Now().Add(writeTimeout))
		close(writing)
		_, err := a.Write(make([]byte, 1<<10)) // nobody reads b
		writeDone <- err
	}()
	<-writing
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	done := make(chan struct{})
	go func() {
		sess.finish(byeShutdown, "cihaz yeniden başlatılıyor", true)
		close(done)
	}()
	limit := endWriteStall + 3*time.Second
	if limit >= writeTimeout {
		t.Fatalf("limit %v cannot tell a cut write from writeTimeout %v", limit, writeTimeout)
	}
	select {
	case <-done:
	case <-time.After(limit):
		_ = a.Close() // lets the writer and finish return
		t.Fatalf("end still waiting for the stalled write after %v", limit)
	}
	if d := time.Since(start); d > limit {
		t.Fatalf("end took %v", d)
	}
	var ne net.Error
	if err := <-writeDone; !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("write not cut by the deadline: %v", err)
	}
}

// A healthy write that ends in time keeps the bye: the peer still learns why.
func TestGracefulEndKeepsByeAfterShortWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sess := &session{conn: a, w: &wire{}, cancel: func() {}}
	sess.wmu.Lock()
	release := time.AfterFunc(100*time.Millisecond, sess.wmu.Unlock)
	defer release.Stop()
	done := make(chan struct{})
	go func() {
		sess.finish(byeShutdown, "cihaz yeniden başlatılıyor", true)
		close(done)
	}()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encodeBye(byeShutdown, "cihaz yeniden başlatılıyor")) {
		t.Fatalf("bye lost: %q", got)
	}
	<-done
}

// A peer that neither hangs up nor stops sending cannot hold the end up.
func TestDrainBeforeCloseIsBounded(t *testing.T) {
	const limit = 3 * time.Second
	t.Run("silent peer", func(t *testing.T) {
		srv, _ := loopbackPair(t)
		start := time.Now()
		drainBeforeClose(srv, 100*time.Millisecond)
		if d := time.Since(start); d > limit {
			t.Fatalf("drain took %v", d)
		}
	})
	t.Run("flooding peer", func(t *testing.T) {
		srv, peer := loopbackPair(t)
		var wg sync.WaitGroup
		defer wg.Wait()
		defer func() { _ = peer.Close() }()
		wg.Go(func() {
			buf := make([]byte, 64<<10)
			for {
				_ = peer.SetWriteDeadline(time.Now().Add(limit))
				if _, err := peer.Write(buf); err != nil {
					return
				}
			}
		})
		start := time.Now()
		drainBeforeClose(srv, endDrainTimeout)
		if d := time.Since(start); d > limit {
			t.Fatalf("drain took %v", d)
		}
	})
	t.Run("connection without half close", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		start := time.Now()
		drainBeforeClose(a, time.Hour)
		if d := time.Since(start); d > limit {
			t.Fatalf("drain took %v", d)
		}
	})
}
