package speedtest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func startServer(t *testing.T, cfg Config) (*Server, netip.AddrPort) {
	t.Helper()
	if cfg.Allow == nil {
		cfg.Allow = func(netip.Addr) bool { return true }
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return srv, ln.Addr().(*net.TCPAddr).AddrPort()
}

func TestDownloadAndUpload(t *testing.T) {
	_, addr := startServer(t, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, dir := range []Direction{Download, Upload} {
		res, err := Run(ctx, addr, dir, 300*time.Millisecond)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if res.Direction != dir || res.Bytes <= 0 || res.Elapsed <= 0 || res.Mbps() <= 0 {
			t.Fatalf("%s: unexpected result %+v", dir, res)
		}
		if res.Elapsed > 5*time.Second {
			t.Fatalf("%s: elapsed %v exceeds limit", dir, res.Elapsed)
		}
	}
}

func TestDenied(t *testing.T) {
	_, addr := startServer(t, Config{Allow: func(netip.Addr) bool { return false }})
	if _, err := Run(context.Background(), addr, Download, 200*time.Millisecond); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestAllowSeesLoopbackSource(t *testing.T) {
	got := make(chan netip.Addr, 1)
	_, addr := startServer(t, Config{Allow: func(a netip.Addr) bool { got <- a; return true }})
	if _, err := Run(context.Background(), addr, Download, 150*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("Allow saw %v", a)
	}
}

func TestDurationLimit(t *testing.T) {
	_, addr := startServer(t, Config{MaxDuration: time.Second})
	if _, err := Run(context.Background(), addr, Upload, 2*time.Second); !errors.Is(err, ErrTooLong) {
		t.Fatalf("err = %v, want ErrTooLong", err)
	}
	if _, err := Run(context.Background(), addr, Upload, 10*time.Millisecond); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("short duration err = %v, want ErrBadRequest", err)
	}
}

func TestByteLimit(t *testing.T) {
	_, addr := startServer(t, Config{MaxBytes: 1 << 20})
	res, err := Run(context.Background(), addr, Download, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bytes != 1<<20 {
		t.Fatalf("download bytes = %d, want %d", res.Bytes, 1<<20)
	}
	res, err = Run(context.Background(), addr, Upload, 500*time.Millisecond)
	if err != nil && !errors.Is(err, ErrLimitReached) {
		t.Fatalf("upload err = %v", err)
	}
	if err == nil && res.Bytes > 1<<20 {
		t.Fatalf("upload counted %d bytes beyond the limit", res.Bytes)
	}
}

func TestSingleTestAtATime(t *testing.T) {
	srv, addr := startServer(t, Config{})
	first := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), addr, Download, 1500*time.Millisecond)
		first <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !srv.busy.Load() {
		if time.Now().After(deadline) {
			t.Fatal("first test never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := Run(context.Background(), addr, Upload, 100*time.Millisecond); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent test err = %v, want ErrBusy", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first test: %v", err)
	}
}

func TestListenAddrValidation(t *testing.T) {
	srv, err := NewServer(Config{Allow: func(netip.Addr) bool { return true }, ListenAddr: netip.MustParseAddrPort("0.0.0.0:7000")})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ListenAndServe(context.Background()); !errors.Is(err, ErrInvalidListenAddr) {
		t.Fatalf("err = %v, want ErrInvalidListenAddr", err)
	}
	if _, err := NewServer(Config{}); err == nil {
		t.Fatal("NewServer without Allow succeeded")
	}
}
