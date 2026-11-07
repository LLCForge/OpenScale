package peercred

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProgramPolicyPathsAndHashes(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "openscale")
	b := filepath.Join(dir, "kopya")
	c := filepath.Join(dir, "baska")
	for p, body := range map[string]string{a: "program-1", b: "program-1", c: "program-2"} {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := HashProgram(a)
	if err != nil {
		t.Fatal(err)
	}
	pol := ProgramPolicy{Paths: []string{a}, Hashes: [][32]byte{sum}}
	if err := pol.AllowsProgram(a); err != nil {
		t.Fatal(err)
	}
	if err := pol.AllowsProgram(b); err != nil {
		t.Fatalf("same bytes elsewhere: %v", err)
	}
	if err := pol.AllowsProgram(c); !errors.Is(err, ErrForeignProgram) {
		t.Fatalf("other program: %v", err)
	}
	if err := (ProgramPolicy{Paths: []string{a}}).AllowsProgram(b); !errors.Is(err, ErrForeignProgram) {
		t.Fatalf("path-only policy: %v", err)
	}
	if err := pol.AllowsProgram(""); !errors.Is(err, ErrForeignProgram) {
		t.Fatal(err)
	}
}

// A loopback connection from this test process to itself: the program
// is the test binary, so the self policy allows it and a policy for
// another file refuses it (Windows; Linux only knows the socket's user).
func TestCheckProgramLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	srv := <-accepted
	defer srv.Close()
	self, err := SelfProgramPolicy()
	if err != nil {
		t.Fatal(err)
	}
	remote, local := srv.RemoteAddr().String(), srv.LocalAddr().String()
	if err := self.CheckProgram(remote, local); err != nil {
		t.Fatalf("self: %v", err)
	}
	other := ProgramPolicy{Paths: []string{filepath.Join(t.TempDir(), "x")}}
	err = other.CheckProgram(remote, local)
	if runtime.GOOS == "windows" && !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign policy: %v", err)
	}
	if err := self.CheckProgram("10.0.0.1:5", local); !errors.Is(err, ErrDenied) {
		t.Fatalf("non-loopback: %v", err)
	}
	if runtime.GOOS == "windows" {
		pid, err := ProcessOf(remote, local)
		if err != nil || pid != os.Getpid() {
			t.Fatalf("ProcessOf = %d, %v", pid, err)
		}
	}
}

func TestIsDescendant(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("no process tree here")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := cmd.Process.Pid
	ok, err := IsDescendant(child, os.Getpid())
	_ = cmd.Wait()
	if err != nil || !ok {
		t.Fatalf("child of this process: %v, %v", ok, err)
	}
	if ok, _ := IsDescendant(os.Getpid(), child); ok {
		t.Fatal("parent counted as descendant of its child")
	}
	if ok, _ := IsDescendant(os.Getpid(), os.Getpid()); !ok {
		t.Fatal("a process is its own descendant")
	}
	if ok, _ := IsDescendant(0, 1); ok {
		t.Fatal("zero pid")
	}
}
