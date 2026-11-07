//go:build linux

package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixPeerLinux(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := UnixPeer(c.(*net.UnixConn))
	if err != nil {
		t.Fatal(err)
	}
	if id.PID != os.Getpid() || id.UID != os.Geteuid() || !id.Self || id.Admin != (os.Geteuid() == 0) {
		t.Fatalf("%+v", id)
	}
	if !id.HasGroup(os.Getegid()) {
		t.Fatalf("primary group missing: %+v", id)
	}
}

func TestIdentityFromUcred(t *testing.T) {
	if _, err := identityFromUcred(nil, 0); err == nil {
		t.Fatal("nil accepted")
	}
	if _, err := identityFromUcred(&unix.Ucred{Pid: 0, Uid: 1}, 0); err == nil {
		t.Fatal("pid 0 accepted")
	}
	id, err := identityFromUcred(&unix.Ucred{Pid: 9, Uid: 0, Gid: 4}, 1000)
	if err != nil || !id.Admin || id.Self || id.PID != 9 || !id.HasGroup(4) {
		t.Fatalf("%+v %v", id, err)
	}
}
