package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/sshd"
)

func TestServiceRuleCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	out := h.run(exitOK, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--service", "ssh", "--users", "ali,system", "--allow-forward"}, dir...)...)
	mustContain(t, out, "+ kural laptop -> masaustu ssh(kullanıcılar: ali,system; port yönlendirme)", "tam yetki")
	h.run(exitUsage, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--service", "ssh", "--users", "ali", "--ports", "22"}, dir...)...)
	h.run(exitUsage, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--proto", "any", "--users", "ali"}, dir...)...)
	// Validation in the trust package: ssh needs users, wake needs a relay.
	h.run(exitError, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--service", "ssh"}, dir...)...)
	h.run(exitError, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--service", "wake"}, dir...)...)
	out = h.run(exitOK, append([]string{"rule", "add", "--from", "masaustu", "--to", "laptop", "--service", "wake", "--via", "masaustu"}, dir...)...)
	mustContain(t, out, "wake(aracı: masaustu)")
	h.run(exitOK, append([]string{"rule", "add", "--from", "*", "--to", "laptop", "--service", "files"}, dir...)...)
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	mustContain(t, out, "laptop -> masaustu ssh(", "* -> laptop files")
}

func TestRemoteUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.run(exitUsage, "ssh")
	h.run(exitUsage, "ssh", "--port", "0", "laptop")
	h.run(exitUsage, "send", "yalniz-dosya")
	h.run(exitUsage, "speedtest", "laptop", "--sure", "1m")
	h.run(exitUsage, "files")
	h.run(exitUsage, "files", "bilinmeyen")
	h.run(exitUsage, "files", "auto", "laptop", "belki", "--state-dir", t.TempDir())
}

func TestParseFlagsWithArgs(t *testing.T) {
	h := newHarness(t)
	fs := newFlagSet(h.env, "test")
	up := fs.Bool("upload", false, "")
	name := fs.String("name", "", "")
	if err := parseFlagsWithArgs(fs, []string{"a.txt", "--upload", "--name", "b.txt", "laptop"}, 2); err != nil {
		t.Fatal(err)
	}
	if !*up || *name != "b.txt" || fs.Arg(0) != "a.txt" || fs.Arg(1) != "laptop" {
		t.Fatalf("parsed %v %q %v", *up, *name, fs.Args())
	}
	fs2 := newFlagSet(h.env, "test")
	if err := parseFlagsWithArgs(fs2, []string{"a", "b"}, 1); err == nil {
		t.Fatal("extra argument must fail")
	}
}

func TestVerifyHostKey(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	newKey := func() ssh.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	k1, k2 := newKey(), newKey()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4022}
	// Non-interactive first connection without a fingerprint is refused.
	if err := verifyHostKey(h.env, path, "nas", "")("nas", addr, k1); err == nil {
		t.Fatal("unverified first connection must fail")
	}
	if err := verifyHostKey(h.env, path, "nas", ssh.FingerprintSHA256(k2))("nas", addr, k1); err == nil {
		t.Fatal("wrong fingerprint must fail")
	}
	if err := verifyHostKey(h.env, path, "nas", ssh.FingerprintSHA256(k1))("nas", addr, k1); err != nil {
		t.Fatal(err)
	}
	// Remembered: no fingerprint needed any more.
	if err := verifyHostKey(h.env, path, "nas", "")("nas", addr, k1); err != nil {
		t.Fatal(err)
	}
	// A changed key is refused even with a matching --fingerprint.
	err := verifyHostKey(h.env, path, "nas", ssh.FingerprintSHA256(k2))("nas", addr, k2)
	if err == nil || !strings.Contains(err.Error(), "değişti") {
		t.Fatalf("changed key: %v", err)
	}
	// Interactive confirmation.
	h.env.IsTerminal = func() bool { return true }
	h.env.ReadLine = func(string) (string, error) { return "evet", nil }
	if err := verifyHostKey(h.env, path, "vps", "")("vps", addr, k2); err != nil {
		t.Fatal(err)
	}
	if got, err := knownHost(path, "vps"); err != nil || got == nil {
		t.Fatalf("vps not stored: %v", err)
	}
	if got, _ := knownHost(path, "nas"); got == nil {
		t.Fatal("storing vps must keep nas")
	}
}

// TestSSHCommandEndToEnd runs "openscale ssh" against the embedded server
// on loopback.
func TestSSHCommandEndToEnd(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	name := u.Username
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	if strings.ContainsAny(name, " ") {
		t.Skip("account name with spaces")
	}
	srv, err := sshd.New(sshd.Config{
		HostKeyPath: filepath.Join(t.TempDir(), "host_key"),
		Authorize: func(netip.Addr, string) (bool, string) {
			return true, ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	h := newHarness(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	fp := ssh.FingerprintSHA256(srv.HostKey())
	base := []string{"ssh", "--port", port, "--known-hosts", kh, "--state-dir", t.TempDir(), "--user", name}
	out := h.run(exitOK, append(base, "--fingerprint", fp, "127.0.0.1", "echo", "merhaba")...)
	mustContain(t, out, "merhaba")
	// The remote exit status becomes the process exit status.
	h.run(3, append(base, "127.0.0.1", "exit", "3")...)
}
