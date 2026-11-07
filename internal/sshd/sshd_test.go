package sshd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	name := u.Username
	if i := strings.LastIndexByte(name, byte(0x5C)); i >= 0 {
		name = name[i+1:]
	}
	if !validUserName(name) {
		t.Skipf("current user name %q is outside the accepted character set", name)
	}
	return name
}

func allowLoopback(user string) AuthorizeFunc {
	return func(remote netip.Addr, localUser string) (bool, string) {
		if remote == loopback && localUser == user {
			return true, ""
		}
		return false, "kural yok"
	}
}

func startServer(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	if cfg.HostKeyPath == "" && cfg.HostKey == nil {
		cfg.HostKeyPath = filepath.Join(t.TempDir(), "ssh_host_ed25519")
	}
	srv, err := New(cfg)
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
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return srv, ln.Addr().String()
}

func dial(addr, user string, hostKey ssh.PublicKey) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) { return nil, nil })},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

// dialNone authenticates with the "none" method, as OpenSSH tries first.
func dialNone(addr, user string, hostKey ssh.PublicKey) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{User: user, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 5 * time.Second}
	return ssh.Dial("tcp", addr, cfg)
}

func TestExecCommand(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u)})
	for name, dialer := range map[string]func(string, string, ssh.PublicKey) (*ssh.Client, error){"keyboard-interactive": dial, "none": dialNone} {
		client, err := dialer(addr, u, srv.HostKey())
		if err != nil {
			t.Fatalf("%s: dial: %v", name, err)
		}
		sess, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := sess.CombinedOutput("echo openscale-test")
		if err != nil {
			t.Fatalf("%s: exec: %v (%q)", name, err, out)
		}
		if !strings.Contains(string(out), "openscale-test") {
			t.Fatalf("%s: output = %q", name, out)
		}
		sess, err = client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		err = sess.Run("exit 3")
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
			t.Fatalf("%s: exit status err = %v", name, err)
		}
		_ = client.Close()
	}
}

func TestStdinIsForwarded(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u)})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	cmd := "cat"
	if runtime.GOOS == "windows" {
		cmd = "more"
	}
	sess.Stdin = strings.NewReader("girdi-satiri\n")
	out, err := sess.Output(cmd)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "girdi-satiri") {
		t.Fatalf("output = %q", out)
	}
}

func TestUnauthorizedRejected(t *testing.T) {
	u := currentUser(t)
	var calls atomic.Int32
	srv, addr := startServer(t, Config{Authorize: func(remote netip.Addr, localUser string) (bool, string) {
		calls.Add(1)
		if remote != loopback {
			t.Errorf("Authorize saw %v", remote)
		}
		return false, "kural yok"
	}})
	if c, err := dial(addr, u, srv.HostKey()); err == nil {
		c.Close()
		t.Fatal("unauthorized keyboard-interactive login succeeded")
	}
	if c, err := dialNone(addr, u, srv.HostKey()); err == nil {
		c.Close()
		t.Fatal("unauthorized none login succeeded")
	}
	if calls.Load() == 0 {
		t.Fatal("Authorize was never called")
	}
	// Password and public key methods are not offered at all.
	cfg := &ssh.ClientConfig{User: u, Auth: []ssh.AuthMethod{ssh.Password("x")}, HostKeyCallback: ssh.FixedHostKey(srv.HostKey()), Timeout: 5 * time.Second}
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("password login succeeded")
	}
}

func TestUnknownOrForeignUserRejected(t *testing.T) {
	_, addr := startServer(t, Config{Authorize: func(netip.Addr, string) (bool, string) { return true, "" }})
	hk := func(string, net.Addr, ssh.PublicKey) error { return nil }
	for _, name := range []string{"openscale-no-such-user-x", "bad name", "../x", "-x"} {
		cfg := &ssh.ClientConfig{User: name, HostKeyCallback: hk, Timeout: 5 * time.Second}
		if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
			c.Close()
			t.Fatalf("login as %q succeeded", name)
		}
	}
}

func TestAuthTimeout(t *testing.T) {
	u := currentUser(t)
	_, addr := startServer(t, Config{Authorize: allowLoopback(u), AuthTimeout: 300 * time.Millisecond})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("server did not close the unauthenticated connection")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("closed after %v", time.Since(start))
	}
}

func TestIdleTimeout(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u), IdleTimeout: 300 * time.Millisecond})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection was not closed")
	}
}

func TestMaxConnections(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u), MaxConnections: 1})
	first, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if c, err := dial(addr, u, srv.HostKey()); err == nil {
		c.Close()
		t.Fatal("second connection accepted beyond the limit")
	}
}

func TestMaxChannels(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u), MaxChannelsPerConn: 1})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s1, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	if s2, err := client.NewSession(); err == nil {
		s2.Close()
		t.Fatal("second channel accepted beyond the limit")
	}
}

func startEcho(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

func TestForwardDisabledByDefault(t *testing.T) {
	u := currentUser(t)
	echo := startEcho(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u)})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if c, err := client.Dial("tcp", echo.Addr().String()); err == nil {
		c.Close()
		t.Fatal("forward succeeded without AuthorizeForward")
	}
}

func TestForwardAuthorized(t *testing.T) {
	u := currentUser(t)
	echo := startEcho(t)
	echoAddr := echo.Addr().(*net.TCPAddr).AddrPort()
	srv, addr := startServer(t, Config{
		Authorize: allowLoopback(u),
		AuthorizeForward: func(remote netip.Addr, localUser string, dst netip.AddrPort) (bool, string) {
			return dst == echoAddr, "yalnızca yankı sunucusu"
		},
	})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c, err := client.Dial("tcp", echoAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tünel-üzerinden")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, msg) {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	c.Close()
	if c2, err := client.Dial("tcp", "127.0.0.1:1"); err == nil {
		c2.Close()
		t.Fatal("forward to a non-authorized port succeeded")
	}
}

func TestRevalidateClosesRevokedSessions(t *testing.T) {
	u := currentUser(t)
	var allowed atomic.Bool
	allowed.Store(true)
	srv, addr := startServer(t, Config{Authorize: func(remote netip.Addr, localUser string) (bool, string) {
		return allowed.Load() && localUser == u, "izin geri alındı"
	}})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for deadline := time.Now().Add(5 * time.Second); srv.authenticatedCount() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("connection never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := srv.Revalidate(); n != 0 {
		t.Fatalf("Revalidate closed %d while allowed", n)
	}
	allowed.Store(false)
	if n := srv.Revalidate(); n != 1 {
		t.Fatalf("Revalidate closed %d, want 1", n)
	}
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("revoked connection still open")
	}
}

func TestInteractiveShellWithPTY(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{Authorize: allowLoopback(u)})
	client, err := dial(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out safeBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// The typed command never contains the result, so seeing 1042 proves
	// the shell evaluated it.
	line := "echo $((6*7+1000))\n"
	if runtime.GOOS == "windows" {
		line = "set /a 6*7+1000\r\n"
	}
	if _, err := io.WriteString(stdin, line); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(out.String(), "1042") {
		if time.Now().After(deadline) {
			t.Fatalf("shell output = %q", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	exit := "exit\n"
	if runtime.GOOS == "windows" {
		exit = "exit\r\n"
	}
	_, _ = io.WriteString(stdin, exit)
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shell exit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shell did not exit")
	}
}

func TestHostKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "host")
	a, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey().Marshal(), b.PublicKey().Marshal()) {
		t.Fatal("host key changed between loads")
	}
	if a.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %s", a.PublicKey().Type())
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, %v", fi.Mode().Perm(), err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{HostKeyPath: filepath.Join(t.TempDir(), "k")}); err == nil {
		t.Fatal("New without Authorize succeeded")
	}
	srv, err := New(Config{
		HostKeyPath: filepath.Join(t.TempDir(), "k"),
		Authorize:   func(netip.Addr, string) (bool, string) { return true, "" },
		ListenAddr:  netip.MustParseAddrPort("0.0.0.0:22"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ListenAndServe(context.Background()); !errors.Is(err, ErrInvalidListenAddr) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidUserNameAndForwardTarget(t *testing.T) {
	for _, n := range []string{"ali", "a.b", "user_1", "MACHINE$", "x-y"} {
		if !validUserName(n) {
			t.Errorf("validUserName(%q) = false", n)
		}
	}
	for _, n := range []string{"", "-x", ".x", "a b", "a/b", "a$b", strings.Repeat("a", 65), "kök"} {
		if validUserName(n) {
			t.Errorf("validUserName(%q) = true", n)
		}
	}
	if got, ok := forwardTarget("localhost", 80); !ok || got.String() != "127.0.0.1:80" {
		t.Errorf("localhost = %v, %v", got, ok)
	}
	if got, ok := forwardTarget("[fd00::1]", 443); !ok || got.String() != "[fd00::1]:443" {
		t.Errorf("ipv6 = %v, %v", got, ok)
	}
	for _, h := range []string{"example.com", "0.0.0.0", "224.0.0.1", "fe80::1%eth0", ""} {
		if _, ok := forwardTarget(h, 80); ok {
			t.Errorf("forwardTarget(%q) accepted", h)
		}
	}
	if _, ok := forwardTarget("127.0.0.1", 70000); ok {
		t.Error("port 70000 accepted")
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
