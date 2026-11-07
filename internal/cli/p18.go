//go:build !openscale_noservices

package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/pki"
	"github.com/openscale/openscale/internal/proxy"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/pkg/client"
)

// Tunnel services, Faz 6 (ADR-0138, ADR-0139, ADR-0140): the internal CA,
// certificates, publishing services inside the tunnel, the nginx
// auth_request endpoint and the connect shortcuts. Built without the
// openscale_noservices tag only (#300).

func p18Commands() []command {
	return []command{
		{"ca init", "İç sertifika otoritesini bu cihazda (dağıtıcı) oluşturur; anahtar cihazdan çıkmaz (ADR-0138)", cmdCAInit},
		{"ca approve", "İç CA sertifikasını parmak iziyle doğrulayıp ağ belgesine sabitler (kök anahtar)", cmdCAApprove},
		{"ca remove", "İç CA'yı ağ belgesinden kaldırır (kök anahtar)", cmdCARemove},
		{"ca show", "İç CA sertifikasını ve güven deposuna ekleme komutlarını gösterir (depoyu değiştirmez)", cmdCAShow},
		{"cert", "Bu cihazın bir adı için iç CA'dan kısa ömürlü TLS sertifikası alır: <ad>", cmdCert},
		{"serve", "Tünel içinde servis yayınlar: list | add <ad> --http URL|--dir DİZİN|--tcp ADRES:PORT|--oidc | rm <ad> | client add|rm (ADR-0139)", cmdServe},
		{"auth-server", "nginx auth_request için cihaz kimliği uç noktası (yalnızca loopback; ADR-0139)", cmdAuthServer},
		{"connect", "Bir cihaza kısayolla bağlanır: <cihaz> --rdp | --ssh | --http | --https [--service ad]", cmdConnect},
	}
}

// remoteBase returns the remote context and requires the document.
func remoteMember(env *Env, rf remoteFlags) (remoteContext, error) {
	rc := loadRemoteContext(env, rf)
	if rc.doc == nil {
		return rc, errors.New("ağ belgesi okunamadı; komutu yönetici olarak çalıştırın veya --data-dir/--state-dir verin")
	}
	return rc, nil
}

// --- internal CA ---

func cmdCAInit(env *Env, args []string) error {
	fs := newFlagSet(env, "ca init")
	rf := addRemoteFlags(fs)
	device := fs.String("device", "", "bu cihazın belgedeki adı (varsayılan: tünel adresinden bulunur)")
	days := fs.Int("days", int(pki.DefaultCAValidity.Hours()/24), "CA sertifikasının geçerliliği (gün, en çok 825)")
	out := fs.String("out", "", "CA sertifikasının (açık) bir kopyasını bu dosyaya da yaz; yönetici cihaza taşımak için")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *days < 1 || *days > int(trust.MaxCAValidity.Hours()/24) {
		return usageError("--days 1 ile %d arasında olmalı", int(trust.MaxCAValidity.Hours()/24))
	}
	rc, err := remoteMember(env, rf)
	if err != nil {
		return err
	}
	self := *device
	if self == "" {
		self = rc.self
	}
	if _, ok := rc.doc.DeviceByName(self); !ok {
		return errors.New("bu cihaz belgede bulunamadı; tüneli açın veya --device verin")
	}
	keyPath := service.CAKeyPath(rc.base)
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s zaten var; eski CA'yı korumak için silinmedi (yenisi için dosyayı elle kaldırın)", keyPath)
	}
	key, err := pki.GenerateKey(env.Random)
	if err != nil {
		return err
	}
	der, err := pki.NewCA(key, rc.doc.DisplayName, rc.doc.DNSDomain, rc.doc.IPv4Prefix, rc.doc.IPv6Prefix, env.Now(), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(keyPath, keyPEM); err != nil {
		return err
	}
	certPEM := pki.CertPEM(der)
	if err := securefile.Replace(service.CACertPath(rc.base), certPEM); err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, certPEM, 0o644); err != nil {
			return err
		}
	}
	fp := pki.Fingerprint(der)
	fmt.Fprintf(env.Stdout, "İç CA oluşturuldu (anahtar: %s, yalnızca bu cihazda).\n", keyPath)
	fmt.Fprintf(env.Stdout, "Kısıtlar: yalnızca *.%s, %s ve %s; yalnızca sunucu sertifikası.\n", rc.doc.DNSDomain, rc.doc.IPv4Prefix, rc.doc.IPv6Prefix)
	fmt.Fprintf(env.Stdout, "Parmak izi (SHA-256): %s\n\n", fp)
	fmt.Fprintln(env.Stdout, "Yönetici cihazda (sertifika dosyasını taşıdıktan sonra):")
	fmt.Fprintf(env.Stdout, "  openscale ca approve --dir <ağ klasörü> --cert ca.crt --issuer %s --fingerprint %s\n", self, fp)
	fmt.Fprintf(env.Stdout, "  openscale rule add --dir <ağ klasörü> --service cert --from '*' --to %s\n", self)
	return nil
}

func cmdCAApprove(env *Env, args []string) error {
	fs := newFlagSet(env, "ca approve")
	common := addEditFlags(fs)
	certFile := fs.String("cert", "", "ca init'in ürettiği CA sertifikası (PEM; zorunlu)")
	issuer := fs.String("issuer", "", "CA anahtarını tutan ve sertifika dağıtan cihaz (zorunlu)")
	certDays := fs.Int("cert-days", trust.DefaultCertDays, "verilecek sertifikaların ömrü (gün, 1-30)")
	fingerprint := fs.String("fingerprint", "", "dağıtıcıda gösterilen parmak izi; yoksa terminalde onay istenir")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *certFile == "" || *issuer == "" {
		return usageError("--cert ve --issuer zorunlu")
	}
	if *certDays < 1 || *certDays > trust.MaxCertDays {
		return usageError("--cert-days 1 ile %d arasında olmalı", trust.MaxCertDays)
	}
	data, err := securefile.ReadLimited(*certFile, 64<<10)
	if err != nil {
		return err
	}
	certs, err := pki.ParseCertsPEM(data)
	if err != nil {
		return err
	}
	der := certs[0].Raw
	fp := pki.Fingerprint(der)
	fmt.Fprintf(env.Stdout, "CA sertifikası: %s\nParmak izi: %s\n", certs[0].Subject.CommonName, fp)
	if *fingerprint != "" {
		if pki.NormalizeFingerprint(*fingerprint) != pki.NormalizeFingerprint(fp) {
			return errors.New("parmak izi uyuşmuyor; sertifika değişmiş olabilir, hiçbir şey imzalanmadı")
		}
	} else if !*common.dryRun {
		if err := confirmCritical(env, "", "CA", "Parmak izi dağıtıcı cihazın ekranındakiyle aynı olmalı"); err != nil {
			return err
		}
	}
	ca := &trust.InternalCA{Certificate: der, Issuer: *issuer}
	if *certDays != trust.DefaultCertDays {
		ca.CertDays = *certDays
	}
	if err := runEdit(env, common, func(doc *trust.Document) error { return doc.SetInternalCA(ca) }); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Sertifika isteyebilecek cihazlar için: openscale rule add --service cert --from '*' --to %s\n", *issuer)
	return nil
}

func cmdCARemove(env *Env, args []string) error {
	fs := newFlagSet(env, "ca remove")
	common := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := runEdit(env, common, func(doc *trust.Document) error {
		if doc.InternalCA == nil {
			return trust.ErrNoInternalCA
		}
		return doc.SetInternalCA(nil)
	}); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Not: CA sertifikasını güven deposuna eklediğiniz cihazlardan elle silin.")
	return nil
}

func cmdCAShow(env *Env, args []string) error {
	fs := newFlagSet(env, "ca show")
	rf := addRemoteFlags(fs)
	out := fs.String("out", "", "CA sertifikasını (PEM) bu dosyaya yaz")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	rc, err := remoteMember(env, rf)
	if err != nil {
		return err
	}
	ca := rc.doc.InternalCA
	if ca == nil {
		return errors.New("ağda iç CA yok (dağıtıcıda 'openscale ca init', yönetici cihazda 'openscale ca approve')")
	}
	c, err := ca.ParsedCertificate()
	if err != nil {
		return err
	}
	certPEM := pki.CertPEM(ca.Certificate)
	path := *out
	if path != "" {
		if err := os.WriteFile(path, certPEM, 0o644); err != nil {
			return err
		}
	} else {
		path = "openscale-ic-ca.crt"
		_, _ = env.Stdout.Write(certPEM)
	}
	fmt.Fprintf(env.Stdout, "\nAd: %s\nParmak izi (SHA-256): %s\nGeçerlilik: %s - %s\n", c.Subject.CommonName, pki.Fingerprint(ca.Certificate), c.NotBefore.UTC().Format(time.DateOnly), c.NotAfter.UTC().Format(time.DateOnly))
	fmt.Fprintf(env.Stdout, "Dağıtıcı: %s; sertifika ömrü: %d gün\n", ca.Issuer, int(ca.Lifetime().Hours()/24))
	fmt.Fprintf(env.Stdout, "Kısıtlar: yalnızca %s altındaki adlar ve %s, %s adresleri; yalnızca sunucu kimliği.\n\n", c.PermittedDNSDomains, rc.doc.IPv4Prefix, rc.doc.IPv6Prefix)
	fmt.Fprintln(env.Stdout, "Bu cihazın tarayıcıları için CA'ya güvenmek isterseniz (OpenScale güven deposunu değiştirmez):")
	for _, s := range pki.TrustStoreSteps(runtime.GOOS, path) {
		fmt.Fprintf(env.Stdout, "  %s\n", s)
	}
	fmt.Fprintf(env.Stdout, "  %s\n", pki.BrowserNote)
	return nil
}

// certCovers reports whether name is one of dns (with one-label
// wildcards) or ips.
func certCovers(name string, dns []string, ips []netip.Addr) bool {
	if a, err := netip.ParseAddr(name); err == nil {
		return slices.Contains(ips, a.Unmap())
	}
	for _, n := range dns {
		if n == name {
			return true
		}
		if base, ok := strings.CutPrefix(n, "*."); ok {
			if _, rest, ok := strings.Cut(name, "."); ok && rest == base {
				return true
			}
		}
	}
	return false
}

func cmdCert(env *Env, args []string) error {
	fs := newFlagSet(env, "cert")
	rf := addRemoteFlags(fs)
	certFile := fs.String("cert-file", "", "sertifika zinciri dosyası (varsayılan: <ad>.crt)")
	keyFile := fs.String("key-file", "", "özel anahtar dosyası (varsayılan: <ad>.key, yalnızca sahibine açık)")
	force := fs.Bool("force", false, "var olan anahtar dosyasının üzerine yaz")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	rc, err := remoteMember(env, rf)
	if err != nil {
		return err
	}
	doc := rc.doc
	if doc.InternalCA == nil {
		return trust.ErrNoInternalCA
	}
	self, ok := doc.DeviceByName(rc.self)
	if !ok {
		return errors.New("bu cihaz belgede bulunamadı; tünel açık olmalı")
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fs.Arg(0))), ".")
	if !strings.Contains(name, ".") {
		if _, err := netip.ParseAddr(name); err != nil {
			name += "." + doc.DNSDomain
		}
	}
	dns, ips, _ := doc.CertNames(self.Name)
	if !certCovers(name, dns, ips) {
		return fmt.Errorf("%s bu cihazın adı değil; iç CA yalnızca %s ve altındaki adlar için sertifika verir", name, self.Name+"."+doc.DNSDomain)
	}
	key, err := pki.GenerateKey(env.Random)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(envContext(env), 45*time.Second)
	defer cancel()
	var leaf []byte
	if doc.InternalCA.Issuer == self.Name {
		keyPEM, err := securefile.ReadPrivate(service.CAKeyPath(rc.base), 64<<10)
		if err != nil {
			return fmt.Errorf("bu cihaz dağıtıcı ama CA anahtarı okunamadı: %w", err)
		}
		ca, err := pki.LoadCA(doc.InternalCA.Certificate, keyPEM)
		if err != nil {
			return err
		}
		if leaf, err = ca.Issue(&key.PublicKey, dns, ips, env.Now(), doc.InternalCA.Lifetime()); err != nil {
			return err
		}
	} else {
		issuer, ok := doc.DeviceByName(doc.InternalCA.Issuer)
		if !ok {
			return trust.ErrUnknownIssuer
		}
		if leaf, err = pki.Request(ctx, netip.AddrPortFrom(issuer.IPv4, trust.CertPort), self.IPv4, key, doc.InternalCA.Certificate, env.Now()); err != nil {
			return err
		}
	}
	base := strings.ReplaceAll(name, "*", "_")
	if *certFile == "" {
		*certFile = base + ".crt"
	}
	if *keyFile == "" {
		*keyFile = base + ".key"
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	write := securefile.WriteNew
	if *force {
		write = securefile.Replace
	}
	if err := write(*keyFile, keyPEM); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s zaten var (--force ile üzerine yazılır)", *keyFile)
		}
		return err
	}
	if err := securefile.Replace(*certFile, pki.CertPEM(leaf, doc.InternalCA.Certificate)); err != nil {
		return err
	}
	certs, err := pki.ParseCertsPEM(pki.CertPEM(leaf))
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Sertifika: %s\nAnahtar: %s\nAdlar: %s\nGeçerlilik sonu: %s\n", *certFile, *keyFile, strings.Join(certs[0].DNSNames, ", "), certs[0].NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintln(env.Stdout, "Sertifika kısa ömürlüdür; süresi dolmadan komutu yeniden çalıştırın. 'openscale serve' ile yayınlanan servislerin sertifikası kendiliğinden yenilenir.")
	return nil
}

// --- serve ---

func cmdServe(env *Env, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "status":
		return serveList(env, args[1:])
	case "add":
		return serveAdd(env, args[1:])
	case "rm", "remove":
		return serveRemove(env, args[1:])
	case "client":
		if len(args) < 2 {
			return usageError("openscale serve client add|rm <servis> --id <istemci>")
		}
		switch args[1] {
		case "add":
			return serveClient(env, args[2:], true)
		case "rm", "remove":
			return serveClient(env, args[2:], false)
		}
	case "-h", "--help", "help":
		fmt.Fprintln(env.Stdout, "Kullanım: openscale serve list | add <ad> ... | rm <ad> | client add|rm <servis> --id <istemci>")
		return nil
	}
	return usageError("bilinmeyen serve alt komutu %q", args[0])
}

func serveContext(env *Env, rf remoteFlags) (remoteContext, proxy.Config, error) {
	rc := loadRemoteContext(env, rf)
	if rc.base == "" {
		return rc, proxy.Config{}, errors.New("veri klasörü bulunamadı; --data-dir veya --state-dir verin")
	}
	cfg, err := service.LoadServeConfig(rc.base)
	return rc, cfg, err
}

func serveList(env *Env, args []string) error {
	fs := newFlagSet(env, "serve list")
	rf := addRemoteFlags(fs)
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	rc, cfg, err := serveContext(env, rf)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, cfg)
	}
	if len(cfg.Services) == 0 {
		fmt.Fprintln(env.Stdout, "Yayınlanan servis yok. Örnek: openscale serve add nas --http http://127.0.0.1:5000")
		return nil
	}
	var self trust.Device
	if rc.doc != nil {
		self, _ = rc.doc.DeviceByName(rc.self)
	}
	for _, s := range cfg.Services {
		where := s.Target
		if s.Type == proxy.TypeFiles {
			where = s.Root
		}
		fmt.Fprintf(env.Stdout, "%-16s %-6s %s", s.Name, s.Type, where)
		if self.Name != "" {
			fmt.Fprintf(env.Stdout, "  ->  %s", proxy.URL(s, self, rc.doc.DNSDomain))
		}
		var notes []string
		if len(s.Paths) > 0 {
			notes = append(notes, "yollar: "+strings.Join(s.Paths, ","))
		}
		if s.ReadOnly {
			notes = append(notes, "salt okunur")
		}
		if len(s.Allow) > 0 {
			notes = append(notes, "yalnızca: "+strings.Join(s.Allow, ","))
		}
		if len(notes) > 0 {
			fmt.Fprintf(env.Stdout, "  (%s)", strings.Join(notes, "; "))
		}
		fmt.Fprintln(env.Stdout)
	}
	if rc.doc != nil && self.Name != "" {
		if !rc.doc.HostsService(self.Name, trust.ServiceServe) && slices.ContainsFunc(cfg.Services, proxy.Service.Shared) {
			fmt.Fprintf(env.Stdout, "\nUyarı: belgede bu cihaza bir serve kuralı yok; ortak port (%d) dinlenmez.\n  openscale rule add --service serve --from <cihazlar> --to %s\n", trust.ServePort, self.Name)
		}
		if rc.doc.InternalCA == nil && slices.ContainsFunc(cfg.Services, func(s proxy.Service) bool { return s.TLS }) {
			fmt.Fprintln(env.Stdout, "Uyarı: tls isteyen servis var ama ağda iç CA yok (openscale ca init / ca approve).")
		}
	}
	return nil
}

func serveAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "serve add")
	rf := addRemoteFlags(fs)
	httpTarget := fs.String("http", "", "ters vekil hedefi (http://127.0.0.1:8080)")
	dir := fs.String("dir", "", "salt okunur sunulacak dizin")
	tcpTarget := fs.String("tcp", "", "TCP iletim hedefi (127.0.0.1:5432; --port gerekir)")
	isOIDC := fs.Bool("oidc", false, "ağ kimliğiyle OIDC sağlayıcısı (ADR-0140)")
	port := fs.Int("port", 0, "kendi tünel portu (yoksa ortak serve portu "+strconv.Itoa(int(trust.ServePort))+")")
	useTLS := fs.Bool("tls", false, "iç CA sertifikasıyla HTTPS sun, düz HTTP'yi yönlendir")
	paths := fs.String("paths", "", "http: yalnızca bu yol önekleri (virgülle, ör. /api/,/static/)")
	readOnly := fs.Bool("read-only", false, "http: yalnızca GET/HEAD/OPTIONS")
	allow := fs.String("allow", "", "kuralları daraltır: yalnızca bu cihazlar/tag:/group: (virgülle)")
	listing := fs.Bool("listing", false, "dir: dizin listelemesini göster")
	replace := fs.Bool("replace", false, "aynı adlı servisi değiştir")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if *port < 0 || *port > 65535 {
		return usageError("--port 1 ile 65535 arasında olmalı")
	}
	svc := proxy.Service{Name: strings.ToLower(fs.Arg(0)), Port: uint16(*port), TLS: *useTLS, Paths: splitList(*paths), ReadOnly: *readOnly, Allow: splitList(*allow), Listing: *listing}
	kinds := 0
	if *httpTarget != "" {
		kinds++
		svc.Type, svc.Target = proxy.TypeHTTP, *httpTarget
	}
	if *dir != "" {
		kinds++
		abs, err := filepath.Abs(*dir)
		if err != nil {
			return err
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return fmt.Errorf("%s bir dizin değil", abs)
		}
		svc.Type, svc.Root = proxy.TypeFiles, abs
	}
	if *tcpTarget != "" {
		kinds++
		svc.Type, svc.Target = proxy.TypeTCP, *tcpTarget
	}
	if *isOIDC {
		kinds++
		svc.Type = proxy.TypeOIDC
	}
	if kinds != 1 {
		return usageError("--http, --dir, --tcp veya --oidc seçeneklerinden tam olarak biri gerekli")
	}
	rc, cfg, err := serveContext(env, rf)
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(cfg.Services, func(s proxy.Service) bool { return s.Name == svc.Name })
	switch {
	case idx >= 0 && !*replace:
		return fmt.Errorf("%q adlı servis zaten var (--replace ile değiştirilir)", svc.Name)
	case idx >= 0:
		svc.Clients = cfg.Services[idx].Clients
		cfg.Services[idx] = svc
	default:
		cfg.Services = append(cfg.Services, svc)
	}
	cfg.Schema = proxy.ConfigSchema
	if err := service.SaveServeConfig(rc.base, cfg); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s yayınlandı (servis birkaç saniye içinde uygular).\n", svc.Name)
	if rc.doc != nil {
		if self, ok := rc.doc.DeviceByName(rc.self); ok {
			fmt.Fprintf(env.Stdout, "Adres: %s\n", proxy.URL(svc, self, rc.doc.DNSDomain))
			if svc.Shared() {
				fmt.Fprintf(env.Stdout, "Erişim kuralı: openscale rule add --service serve --from <cihazlar> --to %s\n", self.Name)
			} else {
				fmt.Fprintf(env.Stdout, "Erişim kuralı: openscale rule add --proto tcp --ports %d --from <cihazlar> --to %s\n", svc.Port, self.Name)
			}
		}
	}
	if svc.Type == proxy.TypeOIDC {
		fmt.Fprintf(env.Stdout, "İstemci eklemek için: openscale serve client add %s --id <istemci> --redirect <adres>\n", svc.Name)
	}
	return nil
}

func serveRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "serve rm")
	rf := addRemoteFlags(fs)
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	rc, cfg, err := serveContext(env, rf)
	if err != nil {
		return err
	}
	n := len(cfg.Services)
	cfg.Services = slices.DeleteFunc(cfg.Services, func(s proxy.Service) bool { return s.Name == fs.Arg(0) })
	if len(cfg.Services) == n {
		return fmt.Errorf("%q adlı yayınlanan servis yok", fs.Arg(0))
	}
	cfg.Schema = proxy.ConfigSchema
	if err := service.SaveServeConfig(rc.base, cfg); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s yayından kaldırıldı.\n", fs.Arg(0))
	return nil
}

func serveClient(env *Env, args []string, add bool) error {
	fs := newFlagSet(env, "serve client")
	rf := addRemoteFlags(fs)
	id := fs.String("id", "", "istemci kimliği (zorunlu)")
	redirect := fs.String("redirect", "", "add: izinli yönlendirme adresleri (virgülle, birebir eşleşir)")
	public := fs.Bool("public", false, "add: sırsız (public) istemci; PKCE yine zorunlu")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	if *id == "" {
		return usageError("--id zorunlu")
	}
	rc, cfg, err := serveContext(env, rf)
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(cfg.Services, func(s proxy.Service) bool { return s.Name == fs.Arg(0) && s.Type == proxy.TypeOIDC })
	if idx < 0 {
		return fmt.Errorf("%q adlı bir oidc servisi yok", fs.Arg(0))
	}
	svc := &cfg.Services[idx]
	svc.Clients = slices.DeleteFunc(svc.Clients, func(c proxy.OIDCClient) bool { return c.ID == *id })
	secret := ""
	if add {
		cl := proxy.OIDCClient{ID: *id, RedirectURIs: splitList(*redirect)}
		if !*public {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			secret = base64.RawURLEncoding.EncodeToString(b)
			sum := sha256.Sum256([]byte(secret))
			cl.SecretSHA256 = hex.EncodeToString(sum[:])
		}
		svc.Clients = append(svc.Clients, cl)
	}
	cfg.Schema = proxy.ConfigSchema
	if err := service.SaveServeConfig(rc.base, cfg); err != nil {
		return err
	}
	if !add {
		fmt.Fprintf(env.Stdout, "%s istemcisi kaldırıldı.\n", *id)
		return nil
	}
	fmt.Fprintf(env.Stdout, "İstemci: %s\n", *id)
	if secret != "" {
		fmt.Fprintf(env.Stdout, "Sır (yalnızca şimdi gösterilir): %s\n", secret)
	}
	if rc.doc != nil {
		if self, ok := rc.doc.DeviceByName(rc.self); ok {
			iss := proxy.URL(*svc, self, rc.doc.DNSDomain)
			fmt.Fprintf(env.Stdout, "Yayıncı (issuer): %s\nKeşif: %s/.well-known/openid-configuration\n", iss, iss)
		}
	}
	return nil
}

// --- nginx auth_request (F-173) ---

const authPath = "/auth"

func cmdAuthServer(env *Env, args []string) error {
	fs := newFlagSet(env, "auth-server")
	listen := fs.String("listen", "127.0.0.1:4180", "dinlenecek loopback adresi (IP:port)")
	header := fs.String("header", "Remote-Addr", "nginx'in istemci adresini koyduğu başlık")
	allow := fs.String("allow", "", "yalnızca bu cihazlar, tag:<etiket> veya group:<grup> (virgülle; boş: ağdaki her cihaz)")
	stateDir := fs.String("state-dir", "", "'openscale up' durum klasörü (yerel API keşfi)")
	nginx := fs.Bool("nginx", false, "örnek nginx yapılandırmasını yazdır ve çık")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *nginx {
		fmt.Fprint(env.Stdout, nginxSnippet(*listen, *header))
		return nil
	}
	h := strings.TrimSpace(*header)
	if h == "" || strings.HasPrefix(strings.ToLower(h), "openscale-") {
		return usageError("--header boş olamaz ve OpenScale- ile başlayamaz")
	}
	ln, err := listenLocal(*listen)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	c, err := client.Discover(ctx, *stateDir)
	if err != nil {
		_ = ln.Close()
		return err
	}
	handler := authHandler(c, h, splitList(*allow))
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	fmt.Fprintf(env.Stdout, "Kimlik uç noktası %s üzerinde (%s). Durdurmak için Ctrl+C.\n", ln.Addr(), authPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listenLocal listens only on loopback: the endpoint trusts the client
// address header, which only the local nginx sets.
func listenLocal(spec string) (net.Listener, error) {
	ap, err := netip.ParseAddrPort(spec)
	if err != nil || !ap.Addr().IsLoopback() {
		return nil, usageError("--listen bir loopback adresi olmalı (ör. 127.0.0.1:4180)")
	}
	return net.Listen("tcp", ap.String())
}

// authHandler answers nginx auth_request subrequests: 204 with the device
// headers for a device of the network the allow list accepts, 403
// otherwise, 502 when the tunnel cannot be asked (fail closed).
func authHandler(r client.Resolver, header string, allow []string) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		dev, ok := client.DeviceFrom(req.Context())
		if !ok || !deviceAllowed(dev, allow) {
			http.Error(w, "izin yok", http.StatusForbidden)
			return
		}
		w.Header().Set(client.HeaderDevice, dev.Name)
		w.Header().Set(client.HeaderFQDN, dev.FQDN)
		w.Header().Set(client.HeaderTags, strings.Join(dev.Tags, ","))
		w.Header().Set("OpenScale-Device-Roles", strings.Join(dev.Roles, ","))
		w.Header().Set(client.HeaderFingerprint, dev.Fingerprint)
		w.WriteHeader(http.StatusNoContent)
	})
	id := client.IdentityHandler(inner, r, client.IdentityOptions{})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if req.URL.Path != authPath {
			http.NotFound(w, req)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "yalnızca GET", http.StatusMethodNotAllowed)
			return
		}
		vals := req.Header.Values(header)
		if len(vals) != 1 {
			http.Error(w, "istemci adresi başlığı eksik veya birden çok", http.StatusBadRequest)
			return
		}
		a, err := netip.ParseAddr(strings.TrimSpace(vals[0]))
		if err != nil {
			http.Error(w, "istemci adresi okunamadı", http.StatusBadRequest)
			return
		}
		r2 := req.Clone(req.Context())
		r2.RemoteAddr = netip.AddrPortFrom(a.Unmap(), 0).String()
		id.ServeHTTP(w, r2)
	})
}

func deviceAllowed(d client.Device, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, e := range allow {
		switch {
		case e == "*":
			return true
		case strings.HasPrefix(e, trust.TagPrefix):
			if slices.Contains(d.Tags, strings.TrimPrefix(e, trust.TagPrefix)) {
				return true
			}
		case strings.HasPrefix(e, trust.GroupPrefix):
			if slices.Contains(d.Groups, strings.TrimPrefix(e, trust.GroupPrefix)) {
				return true
			}
		case e == d.Name:
			return true
		}
	}
	return false
}

func nginxSnippet(listen, header string) string {
	upstream := "http://" + listen
	return `# OpenScale cihaz kimliğiyle erişim (ADR-0139). nginx yalnızca tünel
# adresinde dinlemeli; istemci adresini başlığa nginx koyar, istemcinin
# gönderdiği aynı adlı başlık bu satırla ezilir.
location = /_openscale_auth {
    internal;
    proxy_pass ` + upstream + authPath + `;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header ` + header + ` $remote_addr;
}
location / {
    auth_request /_openscale_auth;
    auth_request_set $os_device $upstream_http_openscale_device;
    auth_request_set $os_tags $upstream_http_openscale_device_tags;
    proxy_set_header OpenScale-Device $os_device;
    proxy_set_header OpenScale-Device-Tags $os_tags;
    proxy_pass http://127.0.0.1:8080;
}
`
}

// --- connect shortcuts (#126) ---

func cmdConnect(env *Env, args []string) error {
	fs := newFlagSet(env, "connect")
	rf := addRemoteFlags(fs)
	rdp := fs.Bool("rdp", false, "Uzak Masaüstü (RDP, tcp/3389) istemcisini açar")
	ssh := fs.Bool("ssh", false, "gömülü SSH ile bağlanır (openscale ssh)")
	web := fs.Bool("http", false, "tarayıcıda http:// adresini açar")
	webs := fs.Bool("https", false, "tarayıcıda https:// adresini açar")
	svcName := fs.String("service", "", "http/https: cihazın yayınladığı servis adı (<servis>.<cihaz>.<alan>:"+strconv.Itoa(int(trust.ServePort))+")")
	port := fs.Int("port", 0, "varsayılan yerine bu port")
	user := fs.String("user", "", "ssh: uzak kullanıcı")
	printOnly := fs.Bool("print", false, "çalıştırma, yalnızca komutu veya adresi yazdır")
	rdpFile := fs.String("rdp-file", "", "rdp: sertleştirilmiş .rdp dosyasını bu yeni dosyaya yaz ve onunla aç")
	rdpAllow := fs.String("rdp-allow", "", "rdp: açılacak yönlendirmeler, virgülle (clipboard,drives,printers,smartcards,audio,microphone,ports,usb,camera,webauthn,location,pos); varsayılan hepsi kapalı")
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	modes := 0
	for _, b := range []bool{*rdp, *ssh, *web, *webs} {
		if b {
			modes++
		}
	}
	if modes != 1 {
		return usageError("--rdp, --ssh, --http veya --https seçeneklerinden tam olarak biri gerekli")
	}
	if *port < 0 || *port > 65535 {
		return usageError("--port 1 ile 65535 arasında olmalı")
	}
	if *ssh {
		sshArgs := []string{}
		if *rf.dataDir != "" {
			sshArgs = append(sshArgs, "--data-dir", *rf.dataDir)
		}
		if *rf.stateDir != "" {
			sshArgs = append(sshArgs, "--state-dir", *rf.stateDir)
		}
		if *port != 0 {
			sshArgs = append(sshArgs, "--port", strconv.Itoa(*port))
		}
		target := fs.Arg(0)
		if *user != "" {
			target = *user + "@" + target
		}
		if *printOnly {
			fmt.Fprintf(env.Stdout, "openscale ssh %s\n", strings.Join(append(sshArgs, target), " "))
			return nil
		}
		return cmdSSH(env, append(sshArgs, target))
	}
	rc := loadRemoteContext(env, rf)
	name, addr, err := rc.resolveTarget(envContext(env), fs.Arg(0))
	if err != nil {
		return err
	}
	if *rdp {
		p := 3389
		if *port != 0 {
			p = *port
		}
		hostport := addr.String()
		if p != 3389 {
			hostport = net.JoinHostPort(addr.String(), strconv.Itoa(p))
		}
		connectRuleHint(env, rc, name, uint16(p))
		return connectRDP(env, rc, name, hostport, p, *rdpFile, *rdpAllow, *printOnly)
	}
	scheme := "http"
	if *webs {
		scheme = "https"
	}
	host := addr.String()
	if rc.doc != nil && name != "" {
		host = name + "." + rc.doc.DNSDomain
	}
	p := *port
	if *svcName != "" {
		if !proxy.ValidName(*svcName) {
			return usageError("geçersiz servis adı %q", *svcName)
		}
		if rc.doc == nil || name == "" {
			return errors.New("servis adı için ağ belgesi gerekir; komutu yönetici olarak çalıştırın")
		}
		host = *svcName + "." + host
		if p == 0 {
			p = int(trust.ServePort)
		}
		if rc.self != "" && !rc.doc.AllowsServe(rc.self, name) {
			fmt.Fprintf(env.Stderr, "uyarı: belgede bu cihazdan %s'a serve kuralı yok; bağlantı reddedilebilir\n", name)
		}
	} else if p != 0 {
		connectRuleHint(env, rc, name, uint16(p))
	} else if scheme == "https" {
		connectRuleHint(env, rc, name, 443)
	} else {
		connectRuleHint(env, rc, name, 80)
	}
	u := scheme + "://" + host
	if p != 0 {
		u = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(p))
	}
	u += "/"
	return launch(env, browserCommand(runtime.GOOS, u), *printOnly)
}

// connectRuleHint warns when no rule lets this device reach port.
func connectRuleHint(env *Env, rc remoteContext, target string, port uint16) {
	if rc.doc == nil || rc.self == "" || target == "" {
		return
	}
	if !rc.doc.Allows(rc.self, target, trust.ProtocolTCP, port) {
		fmt.Fprintf(env.Stderr, "uyarı: belgede bu cihazdan %s'a tcp/%d kuralı yok; bağlantı reddedilebilir\n", target, port)
	}
}

func rdpCommand(goos, hostport string) []string {
	switch goos {
	case "windows":
		return []string{"mstsc.exe", "/v:" + hostport}
	case "darwin":
		return []string{"open", "rdp://full%20address=s:" + hostport}
	default:
		for _, c := range []string{"xfreerdp3", "xfreerdp", "wlfreerdp"} {
			if _, err := exec.LookPath(c); err == nil {
				return []string{c, "/v:" + hostport}
			}
		}
		return []string{"xfreerdp", "/v:" + hostport}
	}
}

func browserCommand(goos, u string) []string {
	switch goos {
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", u}
	case "darwin":
		return []string{"open", u}
	default:
		return []string{"xdg-open", u}
	}
}

// launch starts a desktop program without waiting for it.
func launch(env *Env, argv []string, printOnly bool) error {
	fmt.Fprintln(env.Stdout, strings.Join(argv, " "))
	if printOnly {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s başlatılamadı (yukarıdaki komutu elle çalıştırın): %w", argv[0], err)
	}
	return cmd.Process.Release()
}
