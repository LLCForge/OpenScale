package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sshclient"
	"github.com/openscale/openscale/internal/trust"
	"golang.org/x/crypto/ssh"
)

// g5Env is a test environment whose files live inside the package
// (never the system temporary directory).
func g5Env(t *testing.T) (*Env, string, *bytes.Buffer) {
	t.Helper()
	dir := filepath.Join("testdata", ".g5tmp", strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Join("testdata", ".g5tmp"))
	})
	out := &bytes.Buffer{}
	now := time.Now()
	env := &Env{
		Stdin: strings.NewReader(""), Stdout: out, Stderr: out, Now: func() time.Time { return now }, Random: rand.Reader,
		ReadSecret:      func(string) ([]byte, error) { return nil, errors.New("no terminal in tests") },
		ReadLine:        func(string) (string, error) { return "", errors.New("no terminal in tests") },
		IsTerminal:      func() bool { return false },
		Hostname:        func() (string, error) { return "Test-PC", nil },
		DefaultStateDir: func() (string, error) { return filepath.Join(dir, "state"), nil },
		Argon2:          trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1},
	}
	return env, dir, out
}

func TestG5SSHCertIssue(t *testing.T) {
	env, dir, out := g5Env(t)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(caPriv, "ca")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(userPub)
	keyPath := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(keyPath, ssh.MarshalAuthorizedKey(sp), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"ssh-cert", "issue", "--ca", caPath, "--key", keyPath, "--principal", "yedek", "--ttl", "11m"}, env); code == exitOK {
		t.Fatal("eleven minutes accepted")
	}
	out.Reset()
	if code := Run([]string{"ssh-cert", "issue", "--ca", caPath, "--key", keyPath, "--principal", "yedek", "--force-command", "yedekle"}, env); code != exitOK {
		t.Fatalf("issue: %d\n%s", code, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "id_ed25519-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	cert := pub.(*ssh.Certificate)
	if cert.ValidPrincipals[0] != "yedek" || cert.CriticalOptions["force-command"] != "yedekle" {
		t.Fatalf("%+v", cert)
	}
	// Never overwrites.
	if code := Run([]string{"ssh-cert", "issue", "--ca", caPath, "--key", keyPath, "--principal", "yedek"}, env); code == exitOK {
		t.Fatal("certificate overwritten")
	}
}

func TestG5HostKeysCommand(t *testing.T) {
	env, dir, out := g5Env(t)
	kh := filepath.Join(dir, "kh.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	if _, err := sshclient.OpenKnownHosts(kh).Check("sunucu:22", sp); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"ssh-hostkeys", "list", "--known-hosts", kh}, env); code != exitOK || !strings.Contains(out.String(), ssh.FingerprintSHA256(sp)) {
		t.Fatalf("list: %d\n%s", code, out)
	}
	out.Reset()
	if code := Run([]string{"ssh-hostkeys", "forget", "--known-hosts", kh, "sunucu:22"}, env); code != exitOK {
		t.Fatalf("forget: %d\n%s", code, out)
	}
	if code := Run([]string{"ssh-hostkeys", "forget", "--known-hosts", kh, "sunucu:22"}, env); code == exitOK {
		t.Fatal("forgot twice")
	}
}

func TestG5PanelAuthCommand(t *testing.T) {
	env, dir, out := g5Env(t)
	netDir := filepath.Join(dir, "ag")
	pass := "çok gizli parola 42"
	if _, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity},
		[]byte(pass), env.adminOptions(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"panel-auth", "status", "--dir", netDir}, env); code != exitOK || !strings.Contains(out.String(), "Yönetici kipi (15 dk): kapalı") {
		t.Fatalf("status: %d\n%s", code, out)
	}
	env.ReadSecret = func(string) ([]byte, error) { return []byte("yanlış"), nil }
	if code := Run([]string{"panel-auth", "set", "--dir", netDir, "admin-mode", "on"}, env); code == exitOK {
		t.Fatal("wrong passphrase accepted")
	}
	env.ReadSecret = func(string) ([]byte, error) { return []byte(pass), nil }
	if code := Run([]string{"panel-auth", "set", "--dir", netDir, "admin-mode", "on"}, env); code != exitOK {
		t.Fatalf("set: %d\n%s", code, out)
	}
	if code := Run([]string{"panel-auth", "set", "--dir", netDir, "local-mfa", "on"}, env); code == exitOK {
		t.Fatal("local MFA without a factor accepted")
	}
	p, err := panel.LoadPanelAuth(netDir)
	if err != nil || !p.AdminMode || p.LocalMFA {
		t.Fatalf("%v %+v", err, p)
	}
}
