package coordinator

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/obfs"
)

func TestObfsTLSTransport(t *testing.T) {
	tb, _, recv, _ := startTCPBind(t, 8, 8)
	ready := make(chan struct{})
	close(ready)
	s := &Server{tcp: tb, logger: slog.New(slog.DiscardHandler), ready: ready}
	cert, pin, err := obfs.GenerateCertificate([]string{"cdn.example.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeObfsTLS(ctx, ln, obfs.ServerConfig(cert)) }()

	cfg, err := obfs.ClientTLS{ServerName: "cdn.example.test", Pins: []string{pin.String()}}.Config(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := obfs.DialTLS(raw, cfg, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, control.TCPMagic); err != nil {
		t.Fatal(err)
	}
	if err := control.ReadMagic(c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wgFrame(1, 148)); err != nil {
		t.Fatal(err)
	}
	packets, sizes, eps := [][]byte{make([]byte, 2048)}, []int{0}, []conn.Endpoint{nil}
	n, err := recv(packets, sizes, eps)
	if err != nil || n != 1 || sizes[0] != 148 {
		t.Fatalf("recv = %d %v size %d", n, err, sizes[0])
	}

	// A prober speaking HTTPS gets a web server's 404.
	raw2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := obfs.DialTLS(raw2, &tls.Config{InsecureSkipVerify: true}, 5*time.Second) //nolint:gosec // test prober
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(p, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	body, _ := io.ReadAll(p)
	if !strings.HasPrefix(string(body), "HTTP/1.1 404") {
		t.Fatalf("prober got %q", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestObfsTLSNeedsTCPTransport(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	s := &Server{logger: slog.New(slog.DiscardHandler), ready: ready}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ServeObfsTLS(context.Background(), ln, &tls.Config{}); !errors.Is(err, ErrNoTCPTransport) {
		t.Fatalf("%v", err)
	}
	if _, err := ObfsBind(newMemBind(), "", obfs.Padding{}); err == nil {
		t.Fatal("empty network id accepted")
	}
	if b, err := ObfsBind(newMemBind(), "net-1", obfs.DefaultPadding()); err != nil || b.Mode() != obfs.ModeAuto {
		t.Fatalf("%v", err)
	}
}
