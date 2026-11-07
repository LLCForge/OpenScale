package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testDir returns a folder inside the package (never the system
// temporary directory) and removes it afterwards.
func testDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("testdata", ".tmp", strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Join("testdata", ".tmp"))
		_ = os.Remove("testdata")
	})
	return dir
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fakeSSHD is a tiny password SSH server on 127.0.0.1 whose shell echoes
// its input and reports window changes.
type fakeSSHD struct {
	addr     netip.AddrPort
	mu       sync.Mutex
	hostKey  ssh.Signer
	user     string
	pass     string
	kbd      bool // keyboard-interactive instead of password
	userCA   ssh.PublicKey
	resizes  []string
	attempts int
}

func startFake(t *testing.T, f *fakeSSHD) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().(*net.TCPAddr).AddrPort()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
}

func (f *fakeSSHD) config() *ssh.ServerConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg := &ssh.ServerConfig{}
	check := func(user, pw string) (*ssh.Permissions, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.attempts++
		if user == f.user && pw == f.pass {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("hayır")
	}
	if f.kbd {
		cfg.KeyboardInteractiveCallback = func(meta ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ch("", "", []string{"Kod adı: ", "Parola: "}, []bool{true, false})
			if err != nil || len(ans) != 2 {
				return nil, errors.New("hayır")
			}
			return check(meta.User(), ans[1])
		}
	} else {
		cfg.PasswordCallback = func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return check(meta.User(), string(pw))
		}
	}
	if f.userCA != nil {
		ca := f.userCA
		cc := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), ca.Marshal()) }}
		cfg.PublicKeyCallback = cc.Authenticate
	}
	cfg.AddHostKey(f.hostKey)
	return cfg
}

func (f *fakeSSHD) serve(c net.Conn) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, f.config())
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, rq, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for r := range rq {
				switch r.Type {
				case "pty-req", "shell":
					_ = r.Reply(true, nil)
					if r.Type == "shell" {
						go func() {
							buf := make([]byte, 256)
							for {
								n, err := ch.Read(buf)
								if n > 0 {
									if bytes.Contains(buf[:n], []byte("exit")) {
										_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
										_ = ch.Close()
										return
									}
									_, _ = ch.Write(append([]byte("yankı:"), buf[:n]...))
								}
								if err != nil {
									return
								}
							}
						}()
					}
				case "window-change":
					var m struct{ Cols, Rows, W, H uint32 }
					if ssh.Unmarshal(r.Payload, &m) == nil {
						f.mu.Lock()
						f.resizes = append(f.resizes, fmt.Sprintf("%dx%d", m.Cols, m.Rows))
						f.mu.Unlock()
					}
				default:
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
				}
			}
		}()
	}
}

func pw(s string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(s), nil }
}

func TestPasswordLoginPinsHostKey(t *testing.T) {
	dir := testDir(t)
	f := &fakeSSHD{hostKey: newSigner(t), user: "ayse", pass: "doğru"}
	startFake(t, f)
	kh := OpenKnownHosts(filepath.Join(dir, "known_hosts.json"))
	ctx := context.Background()
	var given []byte
	c, err := Dial(ctx, Config{Addr: f.addr, User: "ayse", KnownHosts: kh, Password: func() ([]byte, error) {
		given = []byte("doğru")
		return given, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Host.Status != HostKeyPinned || c.Host.Fingerprint != ssh.FingerprintSHA256(f.hostKey.PublicKey()) {
		t.Fatalf("first connection: %+v", c.Host)
	}
	if !bytes.Equal(given, make([]byte, len(given))) {
		t.Fatalf("password buffer not wiped: %q", given)
	}
	sh, err := c.Shell("xterm", 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Write([]byte("merhaba")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := sh.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "yankı:merhaba") {
		t.Fatalf("shell echo: %q %v", buf[:n], err)
	}
	if err := sh.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		got := strings.Join(f.resizes, ",")
		f.mu.Unlock()
		if got == "120x40" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resizes %q", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _ = sh.Write([]byte("exit"))
	select {
	case <-sh.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shell did not end")
	}
	_ = sh.Close()
	_ = c.Close()

	c2, err := Dial(ctx, Config{Addr: f.addr, User: "ayse", KnownHosts: kh, Password: pw("doğru")})
	if err != nil {
		t.Fatal(err)
	}
	if c2.Host.Status != HostKeyKnown {
		t.Fatalf("second connection: %+v", c2.Host)
	}
	_ = c2.Close()

	// The target now shows another key: refused with both fingerprints.
	f.mu.Lock()
	f.hostKey = newSigner(t)
	f.mu.Unlock()
	_, err = Dial(ctx, Config{Addr: f.addr, User: "ayse", KnownHosts: kh, Password: pw("doğru")})
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) || !errors.Is(err, ErrHostKeyChanged) || changed.Received != ssh.FingerprintSHA256(f.hostKey.PublicKey()) {
		t.Fatalf("changed key: %v", err)
	}
	list, err := kh.List()
	if err != nil || len(list) != 1 || list[0].Fingerprint != changed.Pinned {
		t.Fatalf("list: %v %+v", err, list)
	}
	if ok, err := kh.Forget(f.addr.String()); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	c3, err := Dial(ctx, Config{Addr: f.addr, User: "ayse", KnownHosts: kh, Password: pw("doğru")})
	if err != nil || c3.Host.Status != HostKeyPinned {
		t.Fatalf("after forget: %v", err)
	}
	_ = c3.Close()
}

func TestWrongPasswordAndKeyboardInteractive(t *testing.T) {
	dir := testDir(t)
	f := &fakeSSHD{hostKey: newSigner(t), user: "ayse", pass: "doğru"}
	startFake(t, f)
	kh := OpenKnownHosts(filepath.Join(dir, "kh.json"))
	if _, err := Dial(context.Background(), Config{Addr: f.addr, User: "ayse", KnownHosts: kh, Password: pw("yanlış")}); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password: %v", err)
	}
	g := &fakeSSHD{hostKey: newSigner(t), user: "ayse", pass: "doğru", kbd: true}
	startFake(t, g)
	c, err := Dial(context.Background(), Config{Addr: g.addr, User: "ayse", KnownHosts: kh, Password: pw("doğru")})
	if err != nil {
		t.Fatalf("keyboard-interactive: %v", err)
	}
	_ = c.Close()
}

func TestCertificatesBothWays(t *testing.T) {
	dir := testDir(t)
	userCA, hostCA, userKey := newSigner(t), newSigner(t), newSigner(t)
	hostKey := newSigner(t)
	hostCert := &ssh.Certificate{Key: hostKey.PublicKey(), CertType: ssh.HostCert, KeyId: "hedef", ValidPrincipals: []string{"127.0.0.1"},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
	if err := hostCert.SignCert(rand.Reader, hostCA); err != nil {
		t.Fatal(err)
	}
	hs, err := ssh.NewCertSigner(hostCert, hostKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSSHD{hostKey: hs, user: "ayse", pass: "yok-bu", userCA: userCA.PublicKey()}
	startFake(t, f)
	uc := &ssh.Certificate{Key: userKey.PublicKey(), CertType: ssh.UserCert, KeyId: "kisa", ValidPrincipals: []string{"ayse"},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(10 * time.Minute).Unix())}
	if err := uc.SignCert(rand.Reader, userCA); err != nil {
		t.Fatal(err)
	}
	us, err := ssh.NewCertSigner(uc, userKey)
	if err != nil {
		t.Fatal(err)
	}
	kh := OpenKnownHosts(filepath.Join(dir, "kh.json"))
	c, err := Dial(context.Background(), Config{Addr: f.addr, User: "ayse", KnownHosts: kh, Certificate: us, HostCAs: []ssh.PublicKey{hostCA.PublicKey()}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Host.Status != HostKeyCertified {
		t.Fatalf("host status %+v", c.Host)
	}
	_ = c.Close()
	if list, _ := kh.List(); len(list) != 0 {
		t.Fatal("a certified host key was pinned")
	}
}

func TestDialValidation(t *testing.T) {
	kh := OpenKnownHosts(filepath.Join("testdata", "never-written.json"))
	cases := []Config{
		{Addr: netip.MustParseAddrPort("0.0.0.0:22"), User: "a", KnownHosts: kh, Password: pw("x")},
		{Addr: netip.MustParseAddrPort("127.0.0.1:22"), User: "-oProxyCommand", KnownHosts: kh, Password: pw("x")},
		{Addr: netip.MustParseAddrPort("127.0.0.1:22"), User: "a", Password: pw("x")},
		{Addr: netip.MustParseAddrPort("127.0.0.1:22"), User: "a", KnownHosts: kh},
	}
	for i, c := range cases {
		if _, err := Dial(context.Background(), c); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	var s secret
	if _, err := s.get(func() ([]byte, error) { return make([]byte, maxPassword+1), nil }); err == nil {
		t.Fatal("long password accepted")
	}
	_ = io.EOF
}

func TestKnownHostsCorruptFile(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "kh.json")
	if err := os.WriteFile(path, []byte(`{"version":9,"hosts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	kh := OpenKnownHosts(path)
	if _, err := kh.Check("h", newSigner(t).PublicKey()); err == nil {
		t.Fatal("corrupt file accepted")
	}
}
