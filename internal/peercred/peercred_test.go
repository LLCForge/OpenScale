package peercred

import (
	"errors"
	"net"
	"runtime"
	"testing"
)

// loopbackPair returns the server and client views of one 127.0.0.1
// connection.
func loopbackPair(t *testing.T) (remote, local string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	srv := <-accepted
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv.RemoteAddr().String(), srv.LocalAddr().String()
}

func TestOwnConnectionIsFound(t *testing.T) {
	remote, local := loopbackPair(t)
	client, _ := parseLoopback(remote)
	server, _ := parseLoopback(local)
	id, err := Lookup(client, server)
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Lookup = %v", err)
		}
		if err := (Policy{}).Check(remote, local); err != nil {
			t.Fatal("unsupported systems fall back to the token")
		}
		return
	}
	if err != nil {
		t.Fatalf("Lookup(%s -> %s): %v", remote, local, err)
	}
	if !id.Self {
		t.Fatalf("own connection not recognized: %+v", id)
	}
	if err := (Policy{SameUser: true}).Check(remote, local); err != nil {
		t.Fatalf("same user denied: %v", err)
	}
	if err := (Policy{}).Check(remote, local); !errors.Is(err, ErrDenied) && !id.Admin {
		t.Fatalf("empty policy allowed a caller: %v", err)
	}
}

func TestUnknownConnectionIsDenied(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("lookup unsupported here")
	}
	_, local := loopbackPair(t)
	// A port nobody connected from.
	if err := (Policy{Admins: true, SameUser: true}).Check("127.0.0.1:1", local); !errors.Is(err, ErrDenied) {
		t.Fatalf("unknown connection: %v", err)
	}
}

func TestNonLoopbackIsDenied(t *testing.T) {
	if err := (Policy{SameUser: true}).Check("192.0.2.1:5000", "127.0.0.1:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("non-loopback caller: %v", err)
	}
	if err := (Policy{SameUser: true}).Check("garbage", "127.0.0.1:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("garbage address: %v", err)
	}
}
