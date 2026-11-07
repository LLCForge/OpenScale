package coordinator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/obfs"
)

func TestObfsFileValidateAndSave(t *testing.T) {
	bad := []ObfsFile{
		{Mode: "on"},
		{Mode: "auto", TLSListen: "example.test:443"},
		{TLSListen: ":0"},
		{TLSListen: "443"},
		{Names: []string{"a b"}},
		{Names: make([]string, maxObfsNames+1)},
	}
	for _, f := range bad {
		if err := f.Validate(); err == nil {
			t.Fatalf("accepted %+v", f)
		}
	}
	dir := t.TempDir()
	if f, err := LoadObfsFile(dir); err != nil || f.Enabled() {
		t.Fatalf("missing file: %+v %v", f, err)
	}
	want := ObfsFile{Mode: "auto", TLSListen: "127.0.0.1:443", Names: []string{"cdn.example.test"}}
	if err := SaveObfsFile(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadObfsFile(dir)
	if err != nil || got.Mode != "auto" || got.TLSListen != want.TLSListen || len(got.Names) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if err := SaveObfsFile(dir, ObfsFile{Mode: "on"}); err == nil {
		t.Fatal("saved invalid file")
	}
}

// TestApplyObfsWiresBindAndTLS checks the start path used by the CLI and
// the service: the bind is wrapped, the certificate is created in the
// state directory and the TLS listener (127.0.0.1) carries the transport.
func TestApplyObfsWiresBindAndTLS(t *testing.T) {
	r := newExtRig(t)
	dir := t.TempDir()
	base := r.s.cfg

	off := base
	if rt, err := ApplyObfs(&off, dir, ObfsFile{Mode: "off"}, time.Now()); err != nil || rt != nil || off.Bind != nil {
		t.Fatalf("off: %v %v", rt, err)
	}
	noTCP := base
	if _, err := ApplyObfs(&noTCP, dir, ObfsFile{TLSListen: "127.0.0.1:0"}, time.Now()); !errors.Is(err, ErrNoTCPTransport) {
		t.Fatalf("no tcp: %v", err)
	}

	cfg := base
	cfg.Bind = newMemBind()
	cfg.TCPListen = "127.0.0.1:0"
	rt, err := ApplyObfs(&cfg, dir, ObfsFile{Mode: "auto", TLSListen: "127.0.0.1:0", Names: []string{"cdn.example.test"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := cfg.Bind.(*obfs.Bind); !ok || b.Mode() != obfs.ModeAuto || rt.Bind != b {
		t.Fatalf("bind not wrapped: %T", cfg.Bind)
	}
	if _, pin, err := obfs.LoadOrCreateCertificate(dir, []string{"x"}, time.Now()); err != nil || pin != rt.Pin {
		t.Fatalf("certificate not kept: %v", err)
	}
	addr := rt.Addr()
	if addr == nil {
		t.Fatal("no listener")
	}

	tb, _, recv, _ := startTCPBind(t, 8, 8)
	ready := make(chan struct{})
	close(ready)
	s := &Server{tcp: tb, logger: slog.New(slog.DiscardHandler), ready: ready}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.Serve(ctx, s, func(err error) { t.Errorf("serve: %v", err) })
	rt.Close() // after Serve the listener belongs to the server

	ccfg, err := obfs.ClientTLS{ServerName: "cdn.example.test", Pins: []string{rt.Pin.String()}}.Config(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := obfs.DialTLS(raw, ccfg, 5*time.Second)
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
	if n, err := recv(packets, sizes, eps); err != nil || n != 1 || sizes[0] != 148 {
		t.Fatalf("recv = %d %v", n, err)
	}
}
