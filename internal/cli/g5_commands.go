package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/sshclient"
	"github.com/openscale/openscale/internal/sshd"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// G5 commands (remote access and sign-in): a terminal on a device's own
// OpenSSH (ADR-0203), pinned host keys, short-lived SSH user
// certificates (#668) and the panel's second factor and administrator
// mode settings (ADR-0199).

func init() { registerCommands(g5Commands()...) }

func g5Commands() []command {
	return []command{
		{"ssh-term", "Bir cihazın kendi OpenSSH sunucusuna tünel içinden kullanıcı adı ve parolayla terminal açar (sunucu anahtarı sabitlenir)", cmdSSHTerm},
		{"ssh-hostkeys", "Sabitlenmiş SSH sunucu anahtarları: list | forget <sunucu>", cmdSSHHostKeys},
		{"ssh-cert issue", "Yönetici anahtarıyla en çok 10 dakikalık SSH kullanıcı sertifikası imzalar (#668)", cmdSSHCertIssue},
		{"panel-auth", "Panel girişi: status | set <ayar> on|off (ikinci etken, yeniden doğrulama, yönetici kipi)", cmdPanelAuth},
	}
}

// --- ssh-term ---

func g5KnownHostsPath(env *Env, base, flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	if base == "" && env.DefaultStateDir != nil {
		d, err := env.DefaultStateDir()
		if err != nil {
			return "", err
		}
		base = d
	}
	if base == "" {
		return "", errors.New("bilinen sunucular dosyası için --known-hosts verin")
	}
	return filepath.Join(base, "ssh_known_hosts.json"), nil
}

func cmdSSHTerm(env *Env, args []string) error {
	fs := newFlagSet(env, "ssh-term")
	rf := addRemoteFlags(fs)
	user := fs.String("user", "", "hedef cihazdaki hesap (zorunlu)")
	port := fs.Int("port", 22, "hedefin SSH portu")
	khFlag := fs.String("known-hosts", "", "sabitlenmiş sunucu anahtarları dosyası (varsayılan: durum klasörü)")
	certFlag := fs.String("cert", "", "parola yerine kısa ömürlü sertifika (OpenSSH -cert.pub dosyası; özel anahtar aynı adın .pub'sız hâli)")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale ssh-term --user <hesap> <cihaz>")
		fmt.Fprintln(env.Stderr, "Hedef Linux cihazın kendi OpenSSH sunucusuna tünel içinden bağlanır. Parola istenir, saklanmaz.")
		fmt.Fprintln(env.Stderr, "İlk bağlantıda sunucu anahtarı sabitlenir; değişirse bağlantı kesilir (openscale ssh-hostkeys forget).")
		fs.PrintDefaults()
	}
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if *user == "" {
		return usageError("--user gerekli")
	}
	if *port < 1 || *port > 65535 {
		return usageError("--port 1-65535 olmalı")
	}
	ctx := envContext(env)
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if name == "" {
		name = addr.String()
	}
	khPath, err := g5KnownHostsPath(env, rc.base, *khFlag)
	if err != nil {
		return err
	}
	cfg := sshclient.Config{
		Addr: netip.AddrPortFrom(addr, uint16(*port)), HostName: fmt.Sprintf("%s:%d", name, *port), User: *user,
		KnownHosts: sshclient.OpenKnownHosts(khPath),
	}
	if *certFlag != "" {
		signer, err := loadCertSigner(env, *certFlag)
		if err != nil {
			return err
		}
		cfg.Certificate = signer
	} else {
		if env.ReadSecret == nil {
			return errors.New("parola okunamıyor (terminal yok)")
		}
		cfg.Password = func() ([]byte, error) {
			return env.ReadSecret(fmt.Sprintf("%s@%s parolası: ", *user, name))
		}
	}
	client, err := sshclient.Dial(ctx, cfg)
	var changed *sshclient.HostKeyChangedError
	if errors.As(err, &changed) {
		fmt.Fprintf(env.Stderr, "UYARI: %s sunucu anahtarı değişti.\n  kayıtlı: %s\n  gelen:   %s\n", changed.Host, changed.Pinned, changed.Received)
		fmt.Fprintln(env.Stderr, "Değişiklik beklenmiyorsa bağlanmayın. Beklenen bir yeniden kurulumsa: openscale ssh-hostkeys forget "+changed.Host)
		return errors.New("bağlantı kesildi: sunucu anahtarı değişti")
	}
	if err != nil {
		return err
	}
	defer client.Close()
	if client.Host.Status == sshclient.HostKeyPinned {
		fmt.Fprintf(env.Stderr, "Yeni sunucu anahtarı sabitlendi: %s %s\n", client.Host.Type, client.Host.Fingerprint)
	}
	return runTerminal(ctx, env, client)
}

// runTerminal connects the local terminal to a remote shell.
func runTerminal(ctx context.Context, env *Env, client *sshclient.Client) error {
	cols, rows := 80, 24
	in, isFile := env.Stdin.(*os.File)
	raw := isFile && term.IsTerminal(int(in.Fd()))
	if raw {
		if w, h, err := term.GetSize(int(in.Fd())); err == nil {
			cols, rows = w, h
		}
	}
	sh, err := client.Shell(os.Getenv("TERM"), cols, rows)
	if err != nil {
		return err
	}
	defer sh.Close()
	if raw {
		old, err := term.MakeRaw(int(in.Fd()))
		if err == nil {
			defer func() { _ = term.Restore(int(in.Fd()), old) }()
		}
	}
	go func() { _, _ = io.Copy(sh, env.Stdin) }()
	go func() { _, _ = io.Copy(env.Stdout, sh) }()
	select {
	case <-sh.Done():
	case <-ctx.Done():
	}
	return nil
}

func loadCertSigner(env *Env, certPath string) (ssh.Signer, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil, fmt.Errorf("sertifika okunamadı: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("dosya bir SSH sertifikası değil")
	}
	keyPath := strings.TrimSuffix(certPath, "-cert.pub")
	key, err := loadPrivateKey(env, keyPath)
	if err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, key)
}

// loadPrivateKey reads an OpenSSH private key, asking for its passphrase
// when it is encrypted. The passphrase is wiped afterwards.
func loadPrivateKey(env *Env, path string) (ssh.Signer, error) {
	data, err := securefile.ReadLimited(path, 64<<10)
	if err != nil {
		return nil, err
	}
	defer wipeCLI(data)
	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if env.ReadSecret == nil {
			return nil, errors.New("anahtar parolalı; parola okunamıyor")
		}
		pass, err := env.ReadSecret(filepath.Base(path) + " parolası: ")
		if err != nil {
			return nil, err
		}
		defer wipeCLI(pass)
		return ssh.ParsePrivateKeyWithPassphrase(data, pass)
	}
	return signer, err
}

func wipeCLI(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- ssh-hostkeys ---

func cmdSSHHostKeys(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("bir alt komut yazın: list | forget <sunucu>")
	}
	sub, rest := args[0], args[1:]
	fs := newFlagSet(env, "ssh-hostkeys "+sub)
	rf := addRemoteFlags(fs)
	khFlag := fs.String("known-hosts", "", "sabitlenmiş sunucu anahtarları dosyası")
	asJSON := fs.Bool("json", false, "JSON çıktı (list)")
	n := 0
	if sub == "forget" {
		n = 1
	}
	if err := parseFlagsWithArgs(fs, rest, n); err != nil {
		return err
	}
	rc := loadRemoteContext(env, rf)
	path, err := g5KnownHostsPath(env, rc.base, *khFlag)
	if err != nil {
		return err
	}
	kh := sshclient.OpenKnownHosts(path)
	switch sub {
	case "list":
		list, err := kh.List()
		if err != nil {
			return err
		}
		if *asJSON {
			return json.NewEncoder(env.Stdout).Encode(list)
		}
		tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SUNUCU\tTÜR\tPARMAK İZİ\tİLK GÖRÜLME")
		for _, e := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Host, e.Type, e.Fingerprint, e.FirstSeen.Local().Format("2006-01-02 15:04"))
		}
		return tw.Flush()
	case "forget":
		ok, err := kh.Forget(fs.Arg(0))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s için kayıt yok", fs.Arg(0))
		}
		fmt.Fprintf(env.Stdout, "%s sunucu anahtarı kaydı silindi; sonraki bağlantı yeni anahtarı sabitler.\n", fs.Arg(0))
		return nil
	}
	return usageError("bilinmeyen alt komut: %s", sub)
}

// --- ssh-cert issue (#668) ---

func cmdSSHCertIssue(env *Env, args []string) error {
	fs := newFlagSet(env, "ssh-cert issue")
	caPath := fs.String("ca", "", "yönetici (CA) özel anahtarı, OpenSSH biçimi (zorunlu)")
	keyPath := fs.String("key", "", "kullanıcının açık anahtarı (.pub, zorunlu)")
	principal := fs.String("principal", "", "hedefteki hesap (zorunlu)")
	ttl := fs.Duration("ttl", sshd.MaxCertLifetime, "geçerlilik süresi (en çok 10m)")
	force := fs.String("force-command", "", "sertifika yalnızca bu komutu çalıştırsın (#669)")
	source := fs.String("source", "", "yalnızca bu adreslerden (CIDR, virgülle)")
	out := fs.String("out", "", "yazılacak sertifika dosyası (varsayılan: <key>-cert.pub; üzerine yazılmaz)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *caPath == "" || *keyPath == "" || *principal == "" {
		return usageError("--ca, --key ve --principal gerekli")
	}
	pubData, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		return fmt.Errorf("açık anahtar okunamadı: %w", err)
	}
	ca, err := loadPrivateKey(env, *caPath)
	if err != nil {
		return fmt.Errorf("yönetici anahtarı açılamadı: %w", err)
	}
	cert, err := sshd.IssueUserCertificate(ca, pub, *principal, *ttl, sshd.CertOptions{ForceCommand: *force, SourceAddress: *source}, rand.Reader, env.Now())
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = strings.TrimSuffix(*keyPath, ".pub") + "-cert.pub"
	}
	if err := securefile.WriteNew(dst, ssh.MarshalAuthorizedKey(cert)); err != nil {
		return fmt.Errorf("%s yazılamadı (var olan dosyanın üzerine yazılmaz): %w", dst, err)
	}
	fmt.Fprintf(env.Stdout, "Sertifika yazıldı: %s\nHesap: %s, geçerlilik sonu: %s\n", dst, *principal,
		time.Unix(int64(cert.ValidBefore), 0).Local().Format("2006-01-02 15:04:05"))
	return nil
}

// --- panel-auth ---

var panelAuthSettings = map[string]func(*panel.PanelAuth) *bool{
	"reauth-critical": func(p *panel.PanelAuth) *bool { return &p.ReauthCritical },
	"admin-mode":      func(p *panel.PanelAuth) *bool { return &p.AdminMode },
	"admin-token":     func(p *panel.PanelAuth) *bool { return &p.AdminToken },
	"local-mfa":       func(p *panel.PanelAuth) *bool { return &p.LocalMFA },
}

func cmdPanelAuth(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("bir alt komut yazın: status | set <reauth-critical|admin-mode|admin-token|local-mfa> on|off")
	}
	sub, rest := args[0], args[1:]
	fs := newFlagSet(env, "panel-auth "+sub)
	dirFlag := fs.String("dir", "", "ağ klasörü (Windows'ta varsayılan: servisin ağ klasörü)")
	asJSON := fs.Bool("json", false, "JSON çıktı (status)")
	n := 0
	if sub == "set" {
		n = 2
	}
	if err := parseFlagsWithArgs(fs, rest, n); err != nil {
		return err
	}
	dir, err := networkDirFlag(*dirFlag)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		p, err := panel.LoadPanelAuth(dir)
		if err != nil {
			return err
		}
		st := map[string]any{
			"security_keys": len(p.WebAuthn), "totp": p.TOTP != nil, "totp_remote": p.TOTP != nil && p.TOTP.Remote != nil,
			"reauth_critical": p.ReauthCritical, "admin_mode": p.AdminMode, "admin_token": p.AdminToken, "local_mfa": p.LocalMFA,
		}
		if *asJSON {
			return json.NewEncoder(env.Stdout).Encode(st)
		}
		onoff := func(b bool) string {
			if b {
				return "açık"
			}
			return "kapalı"
		}
		fmt.Fprintf(env.Stdout, "Güvenlik anahtarı: %d\nTOTP: %s (uzak panel: %s)\nKritik işlemde yeniden doğrulama: %s\nYönetici kipi (15 dk): %s\nYubiKey çekilince düşme: %s\nBu bilgisayarda da ikinci etken: %s\n",
			len(p.WebAuthn), onoff(p.TOTP != nil), onoff(p.TOTP != nil && p.TOTP.Remote != nil), onoff(p.ReauthCritical), onoff(p.AdminMode), onoff(p.AdminToken), onoff(p.LocalMFA))
		return nil
	case "set":
		field, ok := panelAuthSettings[fs.Arg(0)]
		if !ok {
			return usageError("bilinmeyen ayar: %s", fs.Arg(0))
		}
		var v bool
		switch fs.Arg(1) {
		case "on":
			v = true
		case "off":
		default:
			return usageError("değer on veya off olmalı")
		}
		// Changing sign-in protection needs the root key passphrase.
		nw, err := admin.Load(dir, env.adminOptions())
		if err != nil {
			return err
		}
		if env.ReadSecret == nil {
			return errors.New("parola okunamıyor (terminal yok)")
		}
		pass, err := env.ReadSecret("Kök anahtar parolası: ")
		if err != nil {
			return err
		}
		err = nw.CheckPassphrase(pass)
		wipeCLI(pass)
		if err != nil {
			return err
		}
		if _, err := panel.UpdatePanelAuth(dir, func(p *panel.PanelAuth) error {
			*field(p) = v
			if p.LocalMFA && !p.HasFactor() {
				return errors.New("önce panelden bir güvenlik anahtarı veya TOTP kaydedin")
			}
			return nil
		}); err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "%s: %s\n", fs.Arg(0), fs.Arg(1))
		return nil
	}
	return usageError("bilinmeyen alt komut: %s", sub)
}
