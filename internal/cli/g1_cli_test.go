package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

var (
	g1KeyLine   = regexp.MustCompile(`Açık anahtar: (\S+)`)
	g1GrantLine = regexp.MustCompile(`kimlik ([0-9a-f]{32})`)
)

type fakeG1Token struct{ priv ed25519.PrivateKey }

func (f *fakeG1Token) PublicKey() ed25519.PublicKey { return f.priv.Public().(ed25519.PublicKey) }
func (f *fakeG1Token) SignMessage(msg []byte) ([]byte, error) {
	return ed25519.Sign(f.priv, msg), nil
}
func (f *fakeG1Token) Close() error { return nil }

func TestG1AdminCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	work := t.TempDir()
	adminPass := h.secretFile("ap", "yönetici anahtar parolası 77")
	keyFile := filepath.Join(work, "helper.key")
	out := h.run(exitOK, "admin", "keygen", "--out", keyFile, "--passphrase-file", adminPass)
	if g1KeyLine.FindStringSubmatch(out) == nil {
		t.Fatalf("keygen:\n%s", out)
	}
	grant := filepath.Join(work, "grant.json")
	h.run(exitUsage, "admin", "grant", "--dir", h.netDir, "--name", "helper", "--key", keyFile, "--ops", "root.rotate", "--out", grant, pass)
	h.run(exitUsage, "admin", "grant", "--dir", h.netDir, "--name", "helper", "--key", keyFile, "--ops", "rules", "--days", "91", "--out", grant, pass)
	out = h.run(exitOK, "admin", "grant", "--dir", h.netDir, "--name", "helper", "--key", keyFile, "--ops", "rules,lockdown,ssh.cert", "--days", "30", "--out", grant, pass)
	m := g1GrantLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("grant:\n%s", out)
	}
	out = h.run(exitOK, "admin", "grants", "--dir", h.netDir)
	if !strings.Contains(out, "helper") || !strings.Contains(out, "geçerli") {
		t.Fatalf("grants:\n%s", out)
	}

	doc := filepath.Join(h.netDir, "network.json")
	signed := filepath.Join(work, "v2.json")
	out = h.run(exitOK, "admin", "sign", "--grant", grant, "--document", doc, "--root", h.rootKeyText(), "--key", keyFile,
		"--passphrase-file", adminPass, "--lockdown", "on", "--dry-run")
	if !strings.Contains(out, "Risk:") || !strings.Contains(out, "ACİL KİLİT") {
		t.Fatalf("sign dry run:\n%s", out)
	}
	h.run(exitOK, "admin", "sign", "--grant", grant, "--document", doc, "--root", h.rootKeyText(), "--key", keyFile,
		"--passphrase-file", adminPass, "--lockdown", "on", "--out", signed)
	data, err := securefile.ReadLimited(signed, trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil || !env.IsAdminSigned() {
		t.Fatalf("signed document: %v", err)
	}
	root, _ := trust.ParseKey(h.rootKeyText())
	if _, err := trust.VerifyDocumentSignature(env, root[:]); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Out of scope: a device is not ours to add, extend or revoke.
	h.run(exitError, "admin", "sign", "--grant", grant, "--document", doc, "--root", h.rootKeyText(), "--key", keyFile,
		"--passphrase-file", adminPass, "--extend", "nope", "--out", filepath.Join(work, "x.json"))

	out = h.run(exitOK, "admin", "risk", "--dir", h.netDir, "--document", signed)
	if !strings.Contains(out, "Risk:") {
		t.Fatalf("risk:\n%s", out)
	}
	out = h.run(exitOK, "admin", "pii", "--dir", h.netDir)
	if !strings.Contains(out, "bulunmadı") {
		t.Fatalf("pii:\n%s", out)
	}

	// Portable administrator.
	portable := filepath.Join(work, "helper.portable")
	pp := h.secretFile("pp", "taşınabilir dosya parolası 31")
	h.run(exitOK, "admin", "portable", "seal", "--key", keyFile, "--passphrase-file", adminPass, "--portable-passphrase-file", pp,
		"--grant", grant, "--root", h.rootKeyText(), "--out", portable)
	nd, _ := trust.VerifyDocumentSignature(env, root[:])
	out = h.run(exitOK, "admin", "portable", "check", "--portable", portable, "--passphrase-file", pp, "--root", h.rootKeyText(), "--network-id", nd.NetworkID)
	if !strings.Contains(out, "geçerli: helper") {
		t.Fatalf("portable check:\n%s", out)
	}

	// SSH user certificate signed by the root.
	_, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, _ := ssh.NewPublicKey(userPriv.Public())
	userFile := filepath.Join(work, "id_ed25519.pub")
	if err := os.WriteFile(userFile, ssh.MarshalAuthorizedKey(userPub), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(work, "id-cert.pub")
	h.run(exitUsage, "admin", "ssh-cert", "--dir", h.netDir, "--root-passphrase-file", h.passFile, "--user-key", userFile, "--principal", "deploy")
	out = h.run(exitOK, "admin", "ssh-cert", "--dir", h.netDir, "--root-passphrase-file", h.passFile, "--user-key", userFile, "--principal", "deploy", "--out", cert)
	if !strings.Contains(out, "SSH sertifikası yazıldı") {
		t.Fatalf("ssh-cert:\n%s", out)
	}

	// Revocation by the root.
	out = h.run(exitOK, "admin", "revoke", "--dir", h.netDir, "--id", m[1], pass)
	if !strings.Contains(out, "Yönetici yetkisi geri alındı") {
		t.Fatalf("revoke:\n%s", out)
	}
	h.run(exitError, "admin", "sign", "--grant", grant, "--document", doc, "--root", h.rootKeyText(), "--key", keyFile,
		"--passphrase-file", adminPass, "--lockdown", "on", "--dry-run")
}

func TestG1DuressAndEmergencyCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	out := h.run(exitOK, "admin", "duress", "status", "--dir", h.netDir)
	if !strings.Contains(out, "yok") {
		t.Fatalf("duress status:\n%s", out)
	}
	dp := h.secretFile("dp", "baskı altında görünüm 5 kapı")
	h.run(exitError, "admin", "duress", "set", "--dir", h.netDir, pass, "--duress-passphrase-file", dp)

	ep := h.secretFile("ep", "acil durum zarf parolası 64")
	out = h.run(exitOK, "admin", "emergency", "prepare", "--dir", h.netDir, pass, "--emergency-passphrase-file", ep)
	if !strings.Contains(out, "her şeyi kilitle") {
		t.Fatalf("prepare:\n%s", out)
	}
	out = h.run(exitOK, "admin", "emergency", "status", "--dir", h.netDir)
	if !strings.Contains(out, "güncel") {
		t.Fatalf("status:\n%s", out)
	}
	h.run(exitUsage, "admin", "emergency", "publish", "--dir", h.netDir, "--emergency-passphrase-file", ep)
	out = h.run(exitOK, "admin", "emergency", "publish", "--dir", h.netDir, "--emergency-passphrase-file", ep, "--confirm", "PANIK")
	if !strings.Contains(out, "yayımlandı") {
		t.Fatalf("publish:\n%s", out)
	}
}

func TestG1KeyTokenWithFakeToken(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := g1OpenTokenFunc
	g1OpenTokenFunc = func(*Env, g1TokenFlags) (g1Token, g1TokenInfo, error) {
		return &fakeG1Token{priv: priv}, g1TokenInfo{Kind: "openpgp", Version: "5.4.3", Reader: "Sahte okuyucu"}, nil
	}
	defer func() { g1OpenTokenFunc = old }()

	out := h.run(exitOK, "key", "token", "status", "--dir", h.netDir)
	if !strings.Contains(out, "openpgp") || !strings.Contains(out, "Rol: bilinmiyor") {
		t.Fatalf("status:\n%s", out)
	}
	// Grant the token's key and sign as an administrator on the token.
	var k trust.Key
	copy(k[:], priv.Public().(ed25519.PublicKey))
	work := t.TempDir()
	grant := filepath.Join(work, "grant.json")
	h.run(exitOK, "admin", "grant", "--dir", h.netDir, "--name", "jeton", "--key", k.String(), "--ops", "lockdown", "--on-token",
		"--token-kind", "openpgp", "--token-serial", "12345678", "--out", grant, pass)
	out = h.run(exitOK, "key", "token", "status", "--grant", grant)
	if !strings.Contains(out, "Rol: yönetici jeton") {
		t.Fatalf("status with grant:\n%s", out)
	}
	doc := filepath.Join(h.netDir, "network.json")
	signed := filepath.Join(work, "v2.json")
	h.run(exitOK, "admin", "sign", "--grant", grant, "--document", doc, "--root", h.rootKeyText(), "--token", "--lockdown", "on", "--out", signed)
	data, _ := securefile.ReadLimited(signed, trust.MaxEnvelopeSize)
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil || env.Algorithm != trust.AlgEd25519Digest {
		t.Fatalf("token-signed document: %v %q", err, env.Algorithm)
	}
	// Token import refuses to run without exactly one source.
	h.run(exitUsage, "key", "token", "import")
	out = h.run(exitOK, "key", "token", "import", "--dir", h.netDir, "--dry-run")
	if !strings.Contains(out, "Kuru çalıştırma") {
		t.Fatalf("import dry run:\n%s", out)
	}
}
