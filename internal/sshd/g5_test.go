package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func memSigner(t *testing.T) ssh.Signer {
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

func certClient(t *testing.T, addr, user string, host ssh.PublicKey, cert *ssh.Certificate, key ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	cs, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)}, HostKeyCallback: ssh.FixedHostKey(host), Timeout: 5 * time.Second}
	return ssh.Dial("tcp", addr, cfg)
}

func TestIssueUserCertificateLimits(t *testing.T) {
	ca, user := memSigner(t), memSigner(t)
	now := time.Now()
	if _, err := IssueUserCertificate(ca, user.PublicKey(), "ayse", 11*time.Minute, CertOptions{}, nil, now); err == nil {
		t.Fatal("eleven minute certificate issued")
	}
	if _, err := IssueUserCertificate(ca, user.PublicKey(), "../root", time.Minute, CertOptions{}, nil, now); err == nil {
		t.Fatal("bad principal accepted")
	}
	if _, err := IssueUserCertificate(ca, user.PublicKey(), "ayse", time.Minute, CertOptions{SourceAddress: "nope"}, nil, now); err == nil {
		t.Fatal("bad source address accepted")
	}
	cert, err := IssueUserCertificate(ca, user.PublicKey(), "ayse", 10*time.Minute, CertOptions{ForceCommand: "yedekle"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.UserCert || cert.ValidPrincipals[0] != "ayse" || cert.CriticalOptions["force-command"] != "yedekle" {
		t.Fatalf("certificate: %+v", cert)
	}
	if life := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; life > MaxCertLifetime+certSkew {
		t.Fatalf("lifetime %v", life)
	}
	if _, err := IssueUserCertificate(ca, cert, "ayse", time.Minute, CertOptions{}, nil, now); err == nil {
		t.Fatal("certificate for a certificate")
	}
}

func TestCertificateLogin(t *testing.T) {
	u := currentUser(t)
	ca, other, key := memSigner(t), memSigner(t), memSigner(t)
	srv, addr := startServer(t, Config{HostKey: memSigner(t), Authorize: allowLoopback(u), UserCAs: []ssh.PublicKey{ca.PublicKey()}, RequireCertificate: true})
	now := time.Now()

	good, err := IssueUserCertificate(ca, key.PublicKey(), u, 5*time.Minute, CertOptions{}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := certClient(t, addr, u, srv.HostKey(), good, key)
	if err != nil {
		t.Fatalf("valid certificate refused: %v", err)
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput("echo sertifika-tamam")
	if err != nil || !strings.Contains(string(out), "sertifika-tamam") {
		t.Fatalf("exec: %v %q", err, out)
	}
	_ = c.Close()

	// The tunnel address alone is not enough any more.
	if c, err := dialNone(addr, u, srv.HostKey()); err == nil {
		c.Close()
		t.Fatal("login without certificate")
	}
	// Signed by another authority.
	foreign, _ := IssueUserCertificate(other, key.PublicKey(), u, 5*time.Minute, CertOptions{}, nil, now)
	if c, err := certClient(t, addr, u, srv.HostKey(), foreign, key); err == nil {
		c.Close()
		t.Fatal("foreign certificate accepted")
	}
	// Expired.
	old, _ := IssueUserCertificate(ca, key.PublicKey(), u, time.Minute, CertOptions{}, nil, now.Add(-time.Hour))
	if c, err := certClient(t, addr, u, srv.HostKey(), old, key); err == nil {
		c.Close()
		t.Fatal("expired certificate accepted")
	}
	// Another account.
	wrong, _ := IssueUserCertificate(ca, key.PublicKey(), "baskasi", 5*time.Minute, CertOptions{}, nil, now)
	if c, err := certClient(t, addr, u, srv.HostKey(), wrong, key); err == nil {
		c.Close()
		t.Fatal("certificate for another account accepted")
	}
	// A long-lived certificate signed elsewhere with the right authority.
	long := &ssh.Certificate{Key: key.PublicKey(), CertType: ssh.UserCert, KeyId: "uzun", ValidPrincipals: []string{u},
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(24 * time.Hour).Unix())}
	if err := long.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if c, err := certClient(t, addr, u, srv.HostKey(), long, key); err == nil {
		c.Close()
		t.Fatal("day-long certificate accepted")
	}
}

func TestRequireCertificateNeedsAuthority(t *testing.T) {
	if _, err := New(Config{HostKey: memSigner(t), Authorize: allowLoopback("x"), RequireCertificate: true}); err == nil {
		t.Fatal("RequireCertificate without UserCAs accepted")
	}
}

func TestCommandAllowList(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{HostKey: memSigner(t), Authorize: allowLoopback(u),
		Commands: func(remote netip.Addr, user string) ([]string, bool) {
			return []string{"echo yedek-tamam", "echo ikinci"}, true
		},
		AuthorizeForward: func(netip.Addr, string, netip.AddrPort) (bool, string) { return true, "" },
	})
	c, err := dialNone(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	out, err := sess.CombinedOutput("echo yedek-tamam")
	if err != nil || !strings.Contains(string(out), "yedek-tamam") {
		t.Fatalf("allowed command: %v %q", err, out)
	}
	sess, _ = c.NewSession()
	if out, err := sess.CombinedOutput("echo baska"); err == nil {
		t.Fatalf("command outside the list ran: %q", out)
	}
	sess, _ = c.NewSession()
	if err := sess.Shell(); err == nil {
		t.Fatal("shell opened for a restricted account with two commands")
	}
	if conn, err := c.Dial("tcp", "127.0.0.1:9"); err == nil {
		conn.Close()
		t.Fatal("restricted account forwarded a port")
	}
}

func TestForceCommandFromCertificate(t *testing.T) {
	u := currentUser(t)
	ca, key := memSigner(t), memSigner(t)
	srv, addr := startServer(t, Config{HostKey: memSigner(t), Authorize: allowLoopback(u), UserCAs: []ssh.PublicKey{ca.PublicKey()}, RequireCertificate: true})
	cert, err := IssueUserCertificate(ca, key.PublicKey(), u, 2*time.Minute, CertOptions{ForceCommand: "echo zorunlu"}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := certClient(t, addr, u, srv.HostKey(), cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	if out, err := sess.CombinedOutput("echo serbest"); err == nil {
		t.Fatalf("command other than force-command ran: %q", out)
	}
	sess, _ = c.NewSession()
	out, err := sess.CombinedOutput("echo zorunlu")
	if err != nil || !strings.Contains(string(out), "zorunlu") {
		t.Fatalf("forced command: %v %q", err, out)
	}
}

func TestRestrictionMerge(t *testing.T) {
	s := &Server{cfg: Config{Commands: func(netip.Addr, string) ([]string, bool) { return []string{"a"}, true }}}
	r := s.restrictionFor(loopback, "u", &ssh.Permissions{CriticalOptions: map[string]string{"force-command": "b"}})
	if !r.restricted || r.commandAllowed("a") || r.commandAllowed("b") || r.commandAllowed("") {
		t.Fatalf("disagreeing rule and certificate must allow nothing: %+v", r)
	}
	free := connRestriction{}
	if !free.commandAllowed("") || !free.commandAllowed("x") {
		t.Fatal("unrestricted connection limited")
	}
}

func TestSSHKillAll(t *testing.T) {
	u := currentUser(t)
	srv, addr := startServer(t, Config{HostKey: memSigner(t), Authorize: allowLoopback(u)})
	c, err := dialNone(addr, u, srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	if n := srv.KillAll(10 * time.Minute); n != 1 {
		t.Fatalf("killed %d", n)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed")
	}
	if c2, err := dialNone(addr, u, srv.HostKey()); err == nil {
		c2.Close()
		t.Fatal("connected during the block")
	}
	srv.LiftKillBlock()
	c3, err := dialNone(addr, u, srv.HostKey())
	if err != nil {
		t.Fatalf("after lifting: %v", err)
	}
	_ = c3.Close()
	_ = net.IPv4len
}
