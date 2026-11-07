package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeProxy is a SOCKS5 server on 127.0.0.1 that records the request and
// then echoes the stream.
type fakeProxy struct {
	ln       net.Listener
	wantAuth *Auth
	reply    byte
	method   byte // 0xfe: choose normally
	got      chan []byte
}

func newFakeProxy(t *testing.T) *fakeProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{ln: ln, method: 0xfe, got: make(chan []byte, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go p.serve()
	return p
}

func (p *fakeProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *fakeProxy) handle(c net.Conn) {
	defer c.Close()
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	m := byte(methodNone)
	if p.wantAuth != nil {
		m = methodUserPwd
	}
	if p.method != 0xfe {
		m = p.method
	}
	if !bytes.Contains(methods, []byte{m}) && m != methodNoGood {
		m = methodNoGood
	}
	_, _ = c.Write([]byte{5, m})
	if m == methodNoGood {
		return
	}
	if m == methodUserPwd {
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return
		}
		user := make([]byte, v[1])
		_, _ = io.ReadFull(c, user)
		var pl [1]byte
		_, _ = io.ReadFull(c, pl[:])
		pass := make([]byte, pl[0])
		_, _ = io.ReadFull(c, pass)
		ok := string(user) == p.wantAuth.Username && string(pass) == p.wantAuth.Password
		if !ok {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	var addr []byte
	switch req[3] {
	case atypIPv4:
		addr = make([]byte, 4)
	case atypIPv6:
		addr = make([]byte, 16)
	case atypDomain:
		var n [1]byte
		_, _ = io.ReadFull(c, n[:])
		addr = make([]byte, n[0])
	}
	_, _ = io.ReadFull(c, addr)
	var port [2]byte
	_, _ = io.ReadFull(c, port[:])
	p.got <- append(append(append([]byte(nil), req[:]...), addr...), port[:]...)
	_, _ = c.Write([]byte{5, p.reply, 0, atypIPv4, 127, 0, 0, 1, 0x1f, 0x90})
	if p.reply != 0 {
		return
	}
	_, _ = io.Copy(c, c)
}

func TestConnectByName(t *testing.T) {
	p := newFakeProxy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, p.ln.Addr().String(), "abcdefghij234567.onion:443", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := <-p.got
	want := append([]byte{5, 1, 0, atypDomain}, "abcdefghij234567.onion"...)
	want = binary.BigEndian.AppendUint16(want, 443)
	// The fake strips the length byte of the name.
	if !bytes.Equal(got, want) {
		t.Fatalf("request %x, want %x", got, want)
	}
	if _, err := c.Write([]byte("merhaba")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "merhaba" {
		t.Fatalf("echo %q %v", buf, err)
	}
}

func TestConnectWithAuthAndAddresses(t *testing.T) {
	p := newFakeProxy(t)
	p.wantAuth = &Auth{Username: "openscale-1", Password: "x"}
	ctx := context.Background()
	c, err := Dial(ctx, p.ln.Addr().String(), "203.0.113.5:443", p.wantAuth, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := <-p.got; !bytes.Equal(got, []byte{5, 1, 0, atypIPv4, 203, 0, 113, 5, 1, 0xbb}) {
		t.Fatalf("IPv4 request %x", got)
	}
	c, err = Dial(ctx, p.ln.Addr().String(), "[2001:db8::1]:443", p.wantAuth, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := <-p.got; got[3] != atypIPv6 || len(got) != 4+16+2 {
		t.Fatalf("IPv6 request %x", got)
	}
	if _, err := Dial(ctx, p.ln.Addr().String(), "203.0.113.5:443", &Auth{Username: "openscale-1", Password: "yanlis"}, nil); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	// Without credentials the proxy (wanting them) refuses the method.
	if _, err := Dial(ctx, p.ln.Addr().String(), "203.0.113.5:443", nil, nil); !errors.Is(err, ErrNoAcceptableMethod) {
		t.Fatalf("no credentials: %v", err)
	}
}

func TestReplyErrorAndBadInput(t *testing.T) {
	p := newFakeProxy(t)
	p.reply = 5
	_, err := Dial(context.Background(), p.ln.Addr().String(), "example.org:443", nil, nil)
	var re *ReplyError
	if !errors.As(err, &re) || re.Code != 5 {
		t.Fatalf("got %v, want connection refused reply", err)
	}
	for _, bad := range []string{"example.org", "example.org:0", "example.org:70000", "[fe80::1%eth0]:443"} {
		if _, err := Dial(context.Background(), p.ln.Addr().String(), bad, nil, nil); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
	if _, err := Dial(context.Background(), p.ln.Addr().String(), "a:1", &Auth{}, nil); err == nil {
		t.Error("empty credentials accepted")
	}
}

func TestDialHonoursContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(3 * time.Second) // never answers in time
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Dial(ctx, ln.Addr().String(), "example.org:443", nil, nil); err == nil {
		t.Fatal("silent proxy accepted")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("context deadline ignored")
	}
}

func FuzzReadReply(f *testing.F) {
	f.Add([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90})
	f.Add([]byte{5, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80})
	f.Add([]byte{5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, b []byte) {
		ap, err := ReadReply(bytes.NewReader(b))
		if err == nil && len(b) > 0 && b[1] != 0 {
			t.Fatal("failure reply accepted")
		}
		_ = ap
	})
}
