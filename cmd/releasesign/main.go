// Command releasesign manages OpenScale release signing keys and signs
// release manifests (ADR-0022). It runs only on the owner's machines:
//
//	releasesign root-keygen    -out root.key -pub root.pub
//	releasesign signing-keygen -out signing.key -pub signing.pub
//	releasesign certify        -root-key root.key -signing-pub signing.pub -out signing.cert [-days 90] [-serial N]
//	releasesign sign           -key signing.key -cert signing.cert -root-pub root.pub \
//	                           -version 0.9.0 -build 20261030.1200 -source-date-epoch N \
//	                           -out openscale-0.9.0.release.json [-sums SHA256SUMS] FILE...
//	releasesign revoke         -root-key root.key -signing-pub old.pub -out revoked.json [-in revoked.json] [-reason TEXT]
//	releasesign pubkey         FILE
//
// Passphrases are read from the terminal, or from the file named by
// -passphrase-file (or OPENSCALE_RELEASE_PASSPHRASE_FILE), which must be
// private (0600) on POSIX systems.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/securefile"
)

const (
	passphraseEnv   = "OPENSCALE_RELEASE_PASSPHRASE_FILE"
	maxPassFileSize = 4096
	maxSmallFile    = 1 << 20
)

// env holds everything the commands touch, so tests can replace it.
type env struct {
	stdout, stderr io.Writer
	now            func() time.Time
	random         io.Reader
	// passphrase returns a passphrase; confirm asks twice for new keys.
	passphrase func(prompt string, confirm bool) ([]byte, error)
}

func main() {
	e := &env{
		stdout: os.Stdout,
		stderr: os.Stderr,
		now:    time.Now,
		random: rand.Reader,
	}
	e.passphrase = func(prompt string, confirm bool) ([]byte, error) {
		return readPassphrase(e.stderr, prompt, confirm, os.Getenv(passphraseEnv))
	}
	if err := run(os.Args[1:], e); err != nil {
		fmt.Fprintln(os.Stderr, "releasesign:", err)
		os.Exit(1)
	}
}

func run(args []string, e *env) error {
	if len(args) == 0 {
		return errors.New("komut gerekli: root-keygen, signing-keygen, certify, sign, revoke, pubkey, witness-keygen, witness, advisory")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "root-keygen":
		return cmdKeygen(rest, e, release.RoleRoot)
	case "signing-keygen":
		return cmdKeygen(rest, e, release.RoleSigning)
	case "certify":
		return cmdCertify(rest, e)
	case "sign":
		return cmdSign(rest, e)
	case "revoke":
		return cmdRevoke(rest, e)
	case "pubkey":
		return cmdPubkey(rest, e)
	case "witness-keygen": // #581, p13.go
		return cmdKeygen(rest, e, release.RoleWitness)
	case "witness":
		return cmdWitness(rest, e)
	case "advisory": // #582, p13.go
		return cmdAdvisory(rest, e)
	default:
		return fmt.Errorf("bilinmeyen komut %q", cmd)
	}
}

func newFlags(name string, e *env) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	pf := fs.String("passphrase-file", "", "parolayı bu özel dosyadan oku (varsayılan: terminal veya $"+passphraseEnv+")")
	return fs, pf
}

// withPassphraseFile makes a -passphrase-file flag override the default.
func withPassphraseFile(e *env, path string) *env {
	if path == "" {
		return e
	}
	c := *e
	c.passphrase = func(prompt string, confirm bool) ([]byte, error) {
		return readPassphrase(e.stderr, prompt, confirm, path)
	}
	return &c
}

func cmdKeygen(args []string, e *env, role string) error {
	fs, pf := newFlags(role+"-keygen", e)
	out := fs.String("out", "", "şifreli özel anahtar dosyası (yeni)")
	pubOut := fs.String("pub", "", "açık anahtar dosyası (isteğe bağlı)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errors.New("-out gerekli")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s zaten var; anahtarlar asla üzerine yazılmaz", *out)
	}
	e = withPassphraseFile(e, *pf)
	pass, err := e.passphrase(fmt.Sprintf("Yeni %s anahtarı parolası: ", roleName(role)), true)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := release.CheckPassphrase(pass); err != nil {
		return fmt.Errorf("parola zayıf: en az %d karakter ve en az 6 farklı karakter olmalı", release.MinPassphraseLength)
	}
	pub, priv, err := release.GenerateKey(e.random)
	if err != nil {
		return err
	}
	defer wipe(priv)
	sealed, err := release.SealKey(priv, role, pass, release.DefaultKDF, e.random)
	if err != nil {
		return err
	}
	data, err := release.MarshalSealedKey(sealed)
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("anahtar yazılamadı: %w", err)
	}
	if *pubOut != "" {
		if err := writePublic(*pubOut, []byte(pub.String()+"\n")); err != nil {
			return err
		}
	}
	fmt.Fprintf(e.stdout, "Anahtar (%s): %s\nAçık anahtar: %s\nParmak izi: %s\n", roleName(role), *out, pub, pub.Fingerprint())
	if role == release.RoleRoot {
		fmt.Fprintln(e.stdout, "Kök anahtarı çevrimdışı saklayın; parmak izini ayrı bir yere (kâğıt) yazın.")
	}
	return nil
}

func cmdCertify(args []string, e *env) error {
	fs, pf := newFlags("certify", e)
	rootKey := fs.String("root-key", "", "şifreli sürüm kök anahtarı")
	signingPub := fs.String("signing-pub", "", "imzalama açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...)")
	out := fs.String("out", "", "sertifika dosyası")
	days := fs.Int("days", int(release.DefaultCertificateValidity/(24*time.Hour)), "geçerlilik (gün)")
	serial := fs.Uint64("serial", 0, "seri numarası (0: başlangıç zamanı)")
	notBefore := fs.String("not-before", "", "geçerlilik başlangıcı, RFC 3339 (varsayılan: şimdi)")
	comment := fs.String("comment", "", "açıklama (en fazla 200 karakter)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootKey == "" || *signingPub == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("-root-key, -signing-pub ve -out gerekli")
	}
	if *days < 1 || time.Duration(*days)*24*time.Hour > release.MaxCertificateValidity {
		return fmt.Errorf("-days 1 ile %d arasında olmalı", int(release.MaxCertificateValidity/(24*time.Hour)))
	}
	sp, err := loadPublicKey(*signingPub)
	if err != nil {
		return err
	}
	nb := e.now()
	if *notBefore != "" {
		if nb, err = time.Parse(time.RFC3339, *notBefore); err != nil {
			return fmt.Errorf("-not-before: %w", err)
		}
	}
	if *serial == 0 {
		*serial = uint64(nb.Unix())
	}
	e = withPassphraseFile(e, *pf)
	priv, err := openKey(e, *rootKey, release.RoleRoot)
	if err != nil {
		return err
	}
	defer wipe(priv)
	env, cert, err := release.IssueCertificate(priv, release.CertificateRequest{
		SigningKey: sp, Serial: *serial, NotBefore: nb, Validity: time.Duration(*days) * 24 * time.Hour, Comment: *comment,
	})
	if err != nil {
		return err
	}
	data, err := release.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	if err := writePublic(*out, data); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "Sertifika: %s\nİmzalama anahtarı: %s\nGeçerlilik: %s - %s\n", *out, cert.SigningKey.Fingerprint(),
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	return nil
}

func cmdSign(args []string, e *env) error {
	fs, pf := newFlags("sign", e)
	keyPath := fs.String("key", "", "şifreli imzalama anahtarı")
	certPath := fs.String("cert", "", "imzalama anahtarının sertifikası")
	rootPub := fs.String("root-pub", "", "sürüm kök açık anahtarı (dosya veya "+release.PublicKeyPrefix+"...)")
	version := fs.String("version", "", "sürüm, ör. 0.9.0")
	build := fs.String("build", "", "derleme damgası")
	sde := fs.Int64("source-date-epoch", -1, "SOURCE_DATE_EPOCH")
	out := fs.String("out", "", "imzalı sürüm dosyası")
	sums := fs.String("sums", "", "ayrıca SHA256SUMS yaz (isteğe bağlı)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *certPath == "" || *rootPub == "" || *version == "" || *out == "" || *sde < 0 || fs.NArg() == 0 {
		return errors.New("-key, -cert, -root-pub, -version, -source-date-epoch, -out ve en az bir dosya gerekli")
	}
	root, err := loadPublicKey(*rootPub)
	if err != nil {
		return err
	}
	certData, err := securefile.ReadLimited(*certPath, maxSmallFile)
	if err != nil {
		return err
	}
	certEnv, err := release.UnmarshalEnvelope(certData)
	if err != nil {
		return err
	}
	// Fail before asking for the passphrase if the certificate is unusable.
	cert, err := release.VerifyCertificate(root, certEnv)
	if err != nil {
		return err
	}
	if !cert.ValidAt(e.now()) {
		return fmt.Errorf("sertifikanın süresi dolmuş veya henüz geçerli değil (%s - %s); yeni imzalama anahtarı sertifikalayın",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	var artifacts []release.Artifact
	for _, p := range fs.Args() {
		a, err := hashFile(p)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, a)
	}
	m := release.NewManifest(*version, *build, *sde, artifacts)
	e = withPassphraseFile(e, *pf)
	priv, err := openKey(e, *keyPath, release.RoleSigning)
	if err != nil {
		return err
	}
	defer wipe(priv)
	data, err := release.SignManifest(priv, certEnv, root, m, e.now())
	if err != nil {
		return err
	}
	// Check the result exactly as a verifier will before publishing it.
	v, err := release.Verify(root, data, release.VerifyOptions{Now: e.now()})
	if err != nil {
		return fmt.Errorf("imzalanan sürüm doğrulanamadı: %w", err)
	}
	if err := writePublic(*out, data); err != nil {
		return err
	}
	if *sums != "" {
		if err := writePublic(*sums, []byte(v.Manifest.SHA256Sums())); err != nil {
			return err
		}
	}
	fmt.Fprintf(e.stdout, "İmzalı sürüm: %s (%s, %d dosya, imzalama anahtarı %s)\n", *out, v.Manifest.Version, len(v.Manifest.Artifacts), cert.SigningKey.Fingerprint())
	return nil
}

func cmdRevoke(args []string, e *env) error {
	fs, pf := newFlags("revoke", e)
	rootKey := fs.String("root-key", "", "şifreli sürüm kök anahtarı")
	in := fs.String("in", "", "mevcut iptal listesi (isteğe bağlı)")
	signingPub := fs.String("signing-pub", "", "iptal edilecek imzalama açık anahtarı")
	reason := fs.String("reason", "", "neden (isteğe bağlı)")
	out := fs.String("out", "", "yeni iptal listesi")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootKey == "" || *signingPub == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("-root-key, -signing-pub ve -out gerekli")
	}
	sp, err := loadPublicKey(*signingPub)
	if err != nil {
		return err
	}
	sealed, err := readSealed(*rootKey, release.RoleRoot)
	if err != nil {
		return err
	}
	list := release.Revocations{}
	if *in != "" {
		data, err := securefile.ReadLimited(*in, release.MaxRevocationsSize)
		if err != nil {
			return err
		}
		old, err := release.VerifyRevocations(sealed.PublicKey, data)
		if err != nil {
			return err
		}
		list = *old
	}
	if list.IsRevoked(sp) {
		return errors.New("bu anahtar zaten iptal edilmiş")
	}
	list.Sequence++
	list.Issued = e.now()
	list.Revoked = append(list.Revoked, release.RevokedKey{SigningKey: sp, Reason: *reason})
	e = withPassphraseFile(e, *pf)
	priv, err := openSealed(e, sealed, *rootKey)
	if err != nil {
		return err
	}
	defer wipe(priv)
	data, err := release.SignRevocations(priv, list)
	if err != nil {
		return err
	}
	if err := writePublic(*out, data); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "İptal listesi: %s (sıra %d, %d anahtar)\n", *out, list.Sequence, len(list.Revoked))
	return nil
}

func cmdPubkey(args []string, e *env) error {
	if len(args) != 1 {
		return errors.New("kullanım: releasesign pubkey DOSYA")
	}
	k, err := loadPublicKey(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "%s\nParmak izi: %s\n", k, k.Fingerprint())
	return nil
}

// loadPublicKey accepts the text form, a public key file or a sealed key file.
func loadPublicKey(s string) (release.PublicKey, error) {
	if strings.HasPrefix(s, release.PublicKeyPrefix) {
		return release.ParsePublicKey(s)
	}
	data, err := securefile.ReadLimited(s, release.MaxSealedKeySize)
	if err != nil {
		return release.PublicKey{}, err
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte(release.PublicKeyPrefix)) {
		return release.ParsePublicKey(string(trimmed))
	}
	sealed, err := release.UnmarshalSealedKey(data)
	if err != nil {
		return release.PublicKey{}, fmt.Errorf("%s: açık anahtar veya anahtar dosyası değil: %w", s, err)
	}
	return sealed.PublicKey, nil
}

func readSealed(path, role string) (*release.SealedKey, error) {
	data, err := securefile.ReadPrivate(path, release.MaxSealedKeySize)
	if err != nil {
		return nil, err
	}
	sealed, err := release.UnmarshalSealedKey(data)
	if err != nil {
		return nil, err
	}
	if sealed.Role != role {
		return nil, fmt.Errorf("%s bir %s anahtarı değil", path, roleName(role))
	}
	return sealed, nil
}

func openKey(e *env, path, role string) (ed25519.PrivateKey, error) {
	sealed, err := readSealed(path, role)
	if err != nil {
		return nil, err
	}
	return openSealed(e, sealed, path)
}

func openSealed(e *env, sealed *release.SealedKey, path string) (ed25519.PrivateKey, error) {
	pass, err := e.passphrase(fmt.Sprintf("Parola, %s anahtarı (%s): ", roleName(sealed.Role), filepath.Base(path)), false)
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	priv, err := sealed.Open(pass)
	if err != nil {
		return nil, errors.New("parola yanlış veya anahtar dosyası bozuk")
	}
	return priv, nil
}

func hashFile(path string) (release.Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return release.Artifact{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return release.Artifact{}, err
	}
	if !info.Mode().IsRegular() {
		return release.Artifact{}, fmt.Errorf("%s normal bir dosya değil", path)
	}
	return release.HashArtifact(filepath.Base(path), f)
}

// writePublic atomically writes a non-secret file.
func writePublic(path string, data []byte) error {
	if err := securefile.Replace(path, data); err != nil {
		return err
	}
	// securefile.Replace creates 0600 files; public outputs are world-readable.
	return os.Chmod(path, 0o644)
}

func readPassphrase(stderr io.Writer, prompt string, confirm bool, file string) ([]byte, error) {
	if file != "" {
		data, err := securefile.ReadPrivate(file, maxPassFileSize)
		if err != nil {
			return nil, fmt.Errorf("parola dosyası: %w", err)
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Reading a line from a pipe would echo the passphrase (for example
		// in mintty without winpty), so refuse instead.
		return nil, errors.New("terminal yok: parolayı -passphrase-file ile verin veya komutu winpty ile çalıştırın")
	}
	fmt.Fprint(stderr, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(stderr, "Tekrar: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return nil, err
		}
		defer wipe(p2)
		if !bytes.Equal(p, p2) {
			wipe(p)
			return nil, errors.New("parolalar eşleşmiyor")
		}
	}
	return p, nil
}

func roleName(role string) string {
	switch role {
	case release.RoleRoot:
		return "sürüm kök"
	case release.RoleWitness:
		return "tanık"
	}
	return "imzalama"
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
