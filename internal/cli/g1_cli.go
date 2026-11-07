package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// G1 commands (ADR-0172..0179): delegated administrator keys, the portable
// administrator blob, hardware tokens (PIV and OpenPGP), sensitive device
// approvals, the duress passphrase, pre-signed emergency documents, the
// risk summary, personal data warnings and short-lived SSH certificates.
// "admin" is registered here with init() (g4_registry.go); "key token" is
// one line in cli.go because it must come before "key", which matches
// first.

func init() {
	registerCommands(command{"admin", "Yetkili yönetici, hassas onay, baskı parolası, acil durum, risk, kişisel veri, SSH sertifikası (G1)", cmdG1Admin})
}

const (
	maxGrantFile     = 64 << 10
	maxAdminKeyFile  = trust.MaxSealedSecretSize
	maxCertInputFile = 16 << 10
	g1TokenWarning   = "UYARI: jeton (YubiKey PIV/OpenPGP) yolu gerçek donanımda denenmedi; yalnızca sahte jetonla test edildi (ADR-0172)."
)

type g1Sub struct {
	name    string
	summary string
	run     func(*Env, []string) error
}

func g1AdminSubcommands() []g1Sub {
	return []g1Sub{
		{"keygen", "Yönetici anahtarı üretir (parolayla mühürlü dosya)", cmdAdminKeygen},
		{"grant", "Kök anahtarla yöneticiye süreli, kapsamlı yetki imzalar (en çok 90 gün)", cmdAdminGrant},
		{"grants", "Verilen yetkileri ve durumlarını listeler", cmdAdminGrants},
		{"revoke", "Bir yönetici yetkisini kökle geri alır: --id KİMLİK", cmdAdminRevoke},
		{"sign", "Yönetici anahtarıyla kapsam içinde yeni belge sürümü imzalar", cmdAdminSign},
		{"portable", "Taşınabilir yönetici: seal (mühürle) | open (aç)", cmdAdminPortable},
		{"sensitive", "Hassas cihaz çift onayı: set | approve | add | status", cmdAdminSensitive},
		{"duress", "Baskı parolası: set | clear | status", cmdAdminDuress},
		{"emergency", "Önceden imzalı acil durum belgeleri: prepare | status | publish (panik)", cmdAdminEmergency},
		{"risk", "Bekleyen taslağın veya bir belgenin risk puanlı özetini gösterir", cmdAdminRisk},
		{"pii", "Ağ adlarında kişisel veri (ad, e-posta, telefon) arar", cmdAdminPII},
		{"ssh-cert", "Kısa ömürlü SSH kullanıcı sertifikası imzalar (kök veya yetkili yönetici)", cmdAdminSSHCert},
	}
}

func cmdG1Admin(env *Env, args []string) error {
	return runG1Sub(env, "admin", g1AdminSubcommands(), args)
}

func runG1Sub(env *Env, prefix string, subs []g1Sub, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(env.Stdout, "Kullanım: openscale %s <alt komut> [seçenekler]\n\nAlt komutlar:\n", prefix)
		for _, c := range subs {
			fmt.Fprintf(env.Stdout, "  %-12s %s\n", c.name, c.summary)
		}
		if len(args) == 0 {
			return usageError("alt komut gerekli")
		}
		return nil
	}
	for _, c := range subs {
		if c.name == args[0] {
			return c.run(env, args[1:])
		}
	}
	return usageError("bilinmeyen alt komut %q", args[0])
}

// --- keys and grants ---

func cmdAdminKeygen(env *Env, args []string) error {
	fs := newFlagSet(env, "admin keygen")
	out := fs.String("out", "", "anahtar dosyası (zorunlu, üzerine yazılmaz)")
	passFile := fs.String("passphrase-file", "", "parolayı bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError("--out zorunlu")
	}
	pass, err := newPassphrase(env, *passFile, "Yönetici anahtarı")
	if err != nil {
		return err
	}
	defer wipe(pass)
	pub, data, err := admin.GenerateAdminKey(pass, env.Argon2, env.Random)
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("anahtar yazılamadı: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Yönetici anahtarı oluşturuldu: %s\nAçık anahtar: %s\n", *out, pub)
	fmt.Fprintln(env.Stdout, "Yetki için kök sahibine açık anahtarı verin: openscale admin grant --key <anahtar>")
	return nil
}

// adminKeyArg accepts a base64 key or a key file (@path or a path to an
// administrator key file).
func adminKeyArg(s string) (trust.Key, error) {
	s = strings.TrimSpace(s)
	if k, err := trust.ParseKey(s); err == nil {
		return k, nil
	}
	data, err := securefile.ReadLimited(strings.TrimPrefix(s, "@"), maxAdminKeyFile)
	if err != nil {
		return trust.Key{}, usageError("--key bir açık anahtar ya da yönetici anahtar dosyası olmalı")
	}
	return admin.AdminKeyFilePublic(data)
}

func cmdAdminGrant(env *Env, args []string) error {
	fs := newFlagSet(env, "admin grant")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu; kök anahtar burada)")
	name := fs.String("name", "", "yönetici adı (küçük harf DNS etiketi, zorunlu)")
	keyText := fs.String("key", "", "yöneticinin açık anahtarı veya anahtar dosyası (zorunlu)")
	ops := fs.String("ops", "", "izinli işlemler, virgülle: "+joinOps())
	tags := fs.String("tags", "", "yalnızca bu etiketli cihazlar (virgülle; boş: tüm ağ)")
	days := fs.Int("days", 30, "yetki süresi (gün, en çok 90)")
	onToken := fs.Bool("on-token", false, "yönetici anahtarı donanım jetonunda (özet imzası kullanılır)")
	tokenKind := fs.String("token-kind", "", "jeton bağlama (#601): piv veya openpgp")
	tokenSerial := fs.Uint("token-serial", 0, "jetonun seri numarası")
	attest := fs.String("attestation", "", "PIV kanıt sertifikası (DER dosyası)")
	inter := fs.String("intermediate", "", "jetonun F9 kanıt sertifikası (DER dosyası)")
	vendorRoot := fs.String("vendor-root", "", "üretici kök sertifikası (DER); verilirse zincir denetlenir")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	rootToken := fs.Bool("root-token", false, "kök anahtar donanım jetonunda (parola sorulmaz)")
	tf := addG1TokenFlags(fs)
	out := fs.String("out", "", "yetki dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *name == "" || *keyText == "" || *out == "" {
		return usageError("--dir, --name, --key ve --out zorunlu")
	}
	key, err := adminKeyArg(*keyText)
	if err != nil {
		return err
	}
	opList, err := admin.ParseAdminOps(*ops)
	if err != nil {
		return usageError("--ops: %v", err)
	}
	life, err := daysFlag(*days, 1, int(trust.MaxAdminGrantLife.Hours()/24), "days")
	if err != nil {
		return err
	}
	req := admin.GrantRequest{Name: *name, Key: key, Lifetime: life, Operations: opList, Tags: splitList(*tags), OnToken: *onToken}
	if *tokenKind != "" {
		b := &trust.TokenBinding{Kind: *tokenKind, Serial: uint32(*tokenSerial)} //nolint:gosec // flag value bounded by Validate
		if *attest != "" {
			if b.Attestation, err = securefile.ReadLimited(*attest, maxCertInputFile); err != nil {
				return err
			}
		}
		if *inter != "" {
			if b.Intermediate, err = securefile.ReadLimited(*inter, maxCertInputFile); err != nil {
				return err
			}
		}
		if *vendorRoot != "" {
			if req.VendorRootDER, err = securefile.ReadLimited(*vendorRoot, maxCertInputFile); err != nil {
				return err
			}
		}
		req.Token = b
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	var sg trust.SignedGrant
	if *rootToken {
		fmt.Fprintln(env.Stderr, g1TokenWarning)
		tok, err := g1OpenToken(env, tf)
		if err != nil {
			return err
		}
		defer tok.Close()
		sg, err = n.IssueAdminGrantWith(tok, req, env.Now())
		if err != nil {
			return err
		}
	} else {
		pass, err := existingPassphrase(env, *passFile)
		if err != nil {
			return err
		}
		sg, err = n.IssueAdminGrant(pass, req, env.Now())
		wipe(pass)
		if err != nil {
			return err
		}
	}
	if err := securefile.WriteNew(*out, append(append([]byte(nil), sg.Encoded...), '\n')); err != nil {
		return fmt.Errorf("yetki yazılamadı: %w", err)
	}
	g := sg.Grant
	fmt.Fprintf(env.Stdout, "Yetki imzalandı: %s (kimlik %s)\n", g.Name, g.ID)
	fmt.Fprintf(env.Stdout, "İşlemler: %s\n", joinAdminOps(g.Operations))
	if len(g.Tags) > 0 {
		fmt.Fprintf(env.Stdout, "Etiketler: %s\n", strings.Join(g.Tags, ", "))
	}
	fmt.Fprintf(env.Stdout, "Geçerlilik: %s tarihine kadar\n", formatTime(g.NotAfter))
	fmt.Fprintln(env.Stdout, "Not: yönetici imzalı belgeleri yalnızca ADR-0172 destekli cihazlar kabul eder.")
	return nil
}

func cmdAdminGrants(env *Env, args []string) error {
	fs := newFlagSet(env, "admin grants")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	list, err := n.AdminGrants(env.Now())
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(env.Stdout, list)
	}
	if len(list) == 0 {
		fmt.Fprintln(env.Stdout, "Verilmiş yönetici yetkisi yok.")
		return nil
	}
	for _, r := range list {
		state := "geçerli"
		switch {
		case r.Revoked:
			state = "geri alındı"
		case r.ExpiredAt:
			state = "süresi doldu"
		}
		fmt.Fprintf(env.Stdout, "%s  %-16s %-12s bitiş %s  işlemler %s", r.ID, r.Name, state, formatTime(r.NotAfter), joinAdminOps(r.Ops))
		if len(r.Tags) > 0 {
			fmt.Fprintf(env.Stdout, "  etiketler %s", strings.Join(r.Tags, ","))
		}
		if r.Token != "" {
			fmt.Fprintf(env.Stdout, "  jeton %s", r.Token)
		}
		fmt.Fprintln(env.Stdout)
	}
	return nil
}

func cmdAdminRevoke(env *Env, args []string) error {
	fs := newFlagSet(env, "admin revoke")
	common := addEditFlags(fs)
	id := fs.String("id", "", "geri alınacak yetkinin kimliği (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *id == "" {
		return usageError("--id zorunlu")
	}
	return runEdit(env, common, admin.RevokeAdminGrant(*id))
}

// --- administrator signing ---

type adminSignerFlags struct {
	key      *string
	portable *string
	passFile *string
	token    *bool
	tf       g1TokenFlags
}

func addAdminSignerFlags(fs *flag.FlagSet) adminSignerFlags {
	return adminSignerFlags{
		key:      fs.String("key", "", "yönetici anahtar dosyası"),
		portable: fs.String("portable", "", "taşınabilir yönetici dosyası (yetkiyi de içerir)"),
		passFile: fs.String("passphrase-file", "", "yönetici anahtarı parolasını bu dosyadan oku"),
		token:    fs.Bool("token", false, "yönetici anahtarı donanım jetonunda"),
		tf:       addG1TokenFlags(fs),
	}
}

// adminKeySource opens the administrator key: software key, portable blob
// or token. close releases it.
type adminKeySource struct {
	priv   ed25519.PrivateKey
	token  g1Token
	grant  []byte
	closed bool
}

func (s *adminKeySource) close() {
	if s.priv != nil {
		trust.WipeKey(s.priv)
	}
	if s.token != nil {
		_ = s.token.Close()
	}
}

func openAdminKey(env *Env, f adminSignerFlags, root ed25519.PublicKey, networkID string) (*adminKeySource, error) {
	n := 0
	for _, set := range []bool{*f.key != "", *f.portable != "", *f.token} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, usageError("--key, --portable veya --token seçeneklerinden tam olarak biri gerekli")
	}
	switch {
	case *f.token:
		fmt.Fprintln(env.Stderr, g1TokenWarning)
		tok, err := g1OpenToken(env, f.tf)
		if err != nil {
			return nil, err
		}
		return &adminKeySource{token: tok}, nil
	case *f.portable != "":
		blob, err := securefile.ReadLimited(*f.portable, admin.MaxPortableBlob)
		if err != nil {
			return nil, err
		}
		pass, err := secretFromFileOrTerminal(env, *f.passFile, "Taşınabilir yönetici parolası: ", "--passphrase-file")
		if err != nil {
			return nil, err
		}
		defer wipe(pass)
		priv, sg, err := admin.OpenPortableAdmin(blob, pass, root, networkID)
		if err != nil {
			return nil, err
		}
		return &adminKeySource{priv: priv, grant: sg.Encoded}, nil
	}
	data, err := securefile.ReadPrivate(*f.key, maxAdminKeyFile)
	if err != nil {
		return nil, fmt.Errorf("yönetici anahtarı okunamadı: %w", err)
	}
	pass, err := secretFromFileOrTerminal(env, *f.passFile, "Yönetici anahtarı parolası: ", "--passphrase-file")
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	priv, err := admin.OpenAdminKeyFile(data, pass)
	if err != nil {
		return nil, err
	}
	return &adminKeySource{priv: priv}, nil
}

func cmdAdminSign(env *Env, args []string) error {
	fs := newFlagSet(env, "admin sign")
	grantFile := fs.String("grant", "", "yetki dosyası (--portable ile gerekmez)")
	document := fs.String("document", "", "güncel imzalı belge (verilmezse --state-dir'deki)")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı")
	stateDir := fs.String("state-dir", "", "üye durum klasörü (kök ve güncel belge buradan)")
	sf := addAdminSignerFlags(fs)
	validity := fs.Int("validity", 30, "yeni sürümün geçerliliği (gün; yetki bitişini aşmaz)")
	revokeDev := fs.String("revoke-device", "", "cihazları iptal et (virgülle)")
	extend := fs.String("extend", "", "cihaz üyeliklerini uzat (virgülle)")
	extendDays := fs.Int("extend-days", 365, "--extend için süre (gün)")
	setTags := fs.String("set-tags", "", "cihaz etiketleri: ad=e1+e2;ad2=e3")
	ruleAdd := fs.String("rule-add", "", "kural ekle: kaynak1+kaynak2>hedef:proto[:port1+port2]")
	lockdown := fs.String("lockdown", "", "acil kilit: on veya off")
	out := fs.String("out", "", "yeni belge dosyası (zorunlu, kuru çalıştırma hariç)")
	dryRun := fs.Bool("dry-run", false, "değişikliği ve riski göster, imzalama")
	accept := fs.Bool("accept", false, "imzalanan belgeyi --state-dir'deki üye durumuna da kabul ettir")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !*dryRun && *out == "" {
		return usageError("--out zorunlu")
	}
	root, err := trustedRoot(env, *rootText, "", *stateDir)
	if err != nil {
		return err
	}
	current, err := currentDocument(env, *document, *stateDir)
	if err != nil {
		return err
	}
	curEnv, err := trust.UnmarshalEnvelope(current)
	if err != nil {
		return err
	}
	curDoc, err := trust.VerifyDocumentSignature(curEnv, root)
	if err != nil {
		return err
	}
	src, err := openAdminKey(env, sf, root, curDoc.NetworkID)
	if err != nil {
		return err
	}
	defer src.close()
	grantData := src.grant
	if grantData == nil {
		if *grantFile == "" {
			return usageError("--grant zorunlu")
		}
		if grantData, err = securefile.ReadLimited(*grantFile, maxGrantFile); err != nil {
			return err
		}
	}
	actx, err := admin.NewAdminContext(root, trimNewline(grantData), current, env.Now())
	if err != nil {
		return err
	}
	change, err := adminSignChange(env.Now(), *revokeDev, *extend, *extendDays, *setTags, *ruleAdd, *lockdown)
	if err != nil {
		return err
	}
	plan, err := actx.PrepareAdmin(env.Now(), time.Duration(*validity)*24*time.Hour, change)
	if err != nil {
		return err
	}
	printAdminPlan(env, plan)
	if *dryRun {
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: hiçbir şey imzalanmadı.")
		return nil
	}
	var data []byte
	if src.token != nil {
		data, err = admin.SignAdminPlanWith(plan, src.token)
	} else {
		data, err = admin.SignAdminPlan(plan, src.priv)
	}
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("belge yazılamadı: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Yönetici imzalı sürüm %d yazıldı: %s\n", plan.Next.Version, *out)
	if *accept {
		sd, err := resolveStateDir(env, *stateDir)
		if err != nil {
			return err
		}
		store, err := member.Open(sd)
		if err != nil {
			return err
		}
		if _, err := store.Accept(data, env.Now()); err != nil {
			return fmt.Errorf("üye durumu belgeyi kabul etmedi: %w", err)
		}
		fmt.Fprintln(env.Stdout, "Belge bu cihazın üye durumuna kabul edildi; eşlere ve koordinatöre yayılır.")
	}
	return nil
}

func trimNewline(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

func currentDocument(env *Env, document, stateDir string) ([]byte, error) {
	if document != "" {
		return securefile.ReadLimited(document, trust.MaxEnvelopeSize)
	}
	sd, err := resolveStateDir(env, stateDir)
	if err != nil {
		return nil, err
	}
	store, err := member.Open(sd)
	if err != nil {
		return nil, fmt.Errorf("güncel belge okunamadı (--document veya --state-dir verin): %w", err)
	}
	data, _ := store.Envelope()
	if len(data) == 0 {
		return nil, errors.New("bu cihazda belge yok")
	}
	return data, nil
}

func printAdminPlan(env *Env, plan *admin.AdminPlan) {
	fmt.Fprintln(env.Stdout, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
	for _, line := range plan.Risk.Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
}

// adminSignChange builds the change of "admin sign" from its flags.
func adminSignChange(now time.Time, revoke, extend string, extendDays int, setTags, ruleAdd, lockdown string) (admin.Change, error) {
	var changes []admin.Change
	if names := splitList(revoke); len(names) > 0 {
		changes = append(changes, func(doc *trust.Document) error {
			_, err := doc.RevokeDevices(names, now)
			return err
		})
	}
	if names := splitList(extend); len(names) > 0 {
		if extendDays < 1 || extendDays > int(trust.MaxDeviceLife.Hours()/24) {
			return nil, usageError("--extend-days geçersiz")
		}
		c, err := admin.BulkMembership(names, admin.BulkOp{Extend: time.Duration(extendDays) * 24 * time.Hour}, now)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	if setTags != "" {
		for _, part := range strings.Split(setTags, ";") {
			name, list, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || name == "" {
				return nil, usageError("--set-tags biçimi: ad=e1+e2;ad2=e3")
			}
			tags := splitPlus(list)
			changes = append(changes, func(doc *trust.Document) error { return doc.SetDeviceTags(name, tags) })
		}
	}
	if ruleAdd != "" {
		r, err := parseCompactRule(ruleAdd)
		if err != nil {
			return nil, err
		}
		changes = append(changes, func(doc *trust.Document) error { return doc.AddRule(r) })
	}
	switch lockdown {
	case "":
	case "on":
		changes = append(changes, admin.SetLockdown(true, "yönetici", now))
	case "off":
		changes = append(changes, admin.SetLockdown(false, "", now))
	default:
		return nil, usageError("--lockdown on veya off olmalı")
	}
	// No flag: a renewal only (version and validity).
	return admin.Combine(changes...), nil
}

// parseCompactRule parses "a+b>c:tcp:22+443".
func parseCompactRule(s string) (trust.Rule, error) {
	from, rest, ok := strings.Cut(s, ">")
	if !ok {
		return trust.Rule{}, usageError("--rule-add biçimi: kaynak>hedef:proto[:portlar]")
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return trust.Rule{}, usageError("--rule-add biçimi: kaynak>hedef:proto[:portlar]")
	}
	r := trust.Rule{From: splitPlus(from), To: splitPlus(parts[0]), Protocol: trust.Protocol(parts[1]), Ports: []string{}}
	if len(parts) == 3 {
		r.Ports = splitPlus(parts[2])
	}
	return r, nil
}

func splitPlus(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "+") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinOps() string {
	var s []string
	for _, op := range trust.AdminOps() {
		s = append(s, string(op))
	}
	return strings.Join(s, ",")
}

func joinAdminOps(ops []trust.AdminOp) string {
	s := make([]string, 0, len(ops))
	for _, op := range ops {
		s = append(s, string(op))
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

// --- portable administrator ---

func cmdAdminPortable(env *Env, args []string) error {
	return runG1Sub(env, "admin portable", []g1Sub{
		{"seal", "Yönetici anahtarını ve yetkisini parolayla taşınabilir dosyaya mühürler", cmdAdminPortableSeal},
		{"check", "Taşınabilir dosyayı parolayla açıp yetkiyi doğrular (anahtarı yazmaz)", cmdAdminPortableCheck},
	}, args)
}

func cmdAdminPortableSeal(env *Env, args []string) error {
	fs := newFlagSet(env, "admin portable seal")
	keyFile := fs.String("key", "", "yönetici anahtar dosyası (zorunlu)")
	passFile := fs.String("passphrase-file", "", "anahtar dosyasının parolası")
	newPassFile := fs.String("portable-passphrase-file", "", "taşınabilir dosyanın parolası (ayrı olmalı)")
	grantFile := fs.String("grant", "", "yetki dosyası (zorunlu)")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı")
	stateDir := fs.String("state-dir", "", "üye durum klasörü")
	out := fs.String("out", "", "taşınabilir dosya (zorunlu); koordinatöre yükleme G2 ucundadır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *keyFile == "" || *grantFile == "" || *out == "" {
		return usageError("--key, --grant ve --out zorunlu")
	}
	root, err := trustedRoot(env, *rootText, "", *stateDir)
	if err != nil {
		return err
	}
	grantData, err := securefile.ReadLimited(*grantFile, maxGrantFile)
	if err != nil {
		return err
	}
	grantData = trimNewline(grantData)
	var probe trust.Envelope
	if err := json.Unmarshal(grantData, &probe); err != nil {
		return fmt.Errorf("yetki dosyası okunamadı: %w", err)
	}
	var g trust.AdminGrant
	if err := json.Unmarshal(probe.Payload, &g); err != nil {
		return fmt.Errorf("yetki dosyası okunamadı: %w", err)
	}
	verified, err := trust.OpenAdminGrant(grantData, root, g.NetworkID)
	if err != nil {
		return err
	}
	data, err := securefile.ReadPrivate(*keyFile, maxAdminKeyFile)
	if err != nil {
		return err
	}
	pass, err := secretFromFileOrTerminal(env, *passFile, "Yönetici anahtarı parolası: ", "--passphrase-file")
	if err != nil {
		return err
	}
	priv, err := admin.OpenAdminKeyFile(data, pass)
	wipe(pass)
	if err != nil {
		return err
	}
	defer trust.WipeKey(priv)
	portPass, err := newPassphrase(env, *newPassFile, "Taşınabilir yönetici dosyası")
	if err != nil {
		return err
	}
	defer wipe(portPass)
	params := trust.StrongerArgon2(env.Argon2, admin.PortableArgon2)
	if env.Argon2.MemoryKiB < admin.PortableArgon2.MemoryKiB && env.Argon2.Time <= 1 {
		params = env.Argon2 // tests use the minimum cost
	}
	id, blob, err := admin.SealPortableAdmin(priv, trust.SignedGrant{Grant: *verified, Encoded: grantData}, portPass, params, env.Random)
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, blob); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Taşınabilir yönetici dosyası yazıldı: %s\nKoordinatör kimliği: %s\n", *out, id)
	fmt.Fprintln(env.Stdout, "Dosya opaktır; çözme yalnızca bu parolayla istemcide yapılır.")
	return nil
}

func cmdAdminPortableCheck(env *Env, args []string) error {
	fs := newFlagSet(env, "admin portable check")
	file := fs.String("portable", "", "taşınabilir dosya (zorunlu)")
	passFile := fs.String("passphrase-file", "", "parolayı bu dosyadan oku")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı")
	stateDir := fs.String("state-dir", "", "üye durum klasörü")
	network := fs.String("network-id", "", "ağ kimliği (verilmezse --state-dir'den)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	root, err := trustedRoot(env, *rootText, "", *stateDir)
	if err != nil {
		return err
	}
	netID := *network
	if netID == "" {
		sd, err := resolveStateDir(env, *stateDir)
		if err != nil {
			return err
		}
		store, err := member.Open(sd)
		if err != nil {
			return usageError("--network-id veya --state-dir gerekli")
		}
		netID = store.Anchor().NetworkID
	}
	blob, err := securefile.ReadLimited(*file, admin.MaxPortableBlob)
	if err != nil {
		return err
	}
	pass, err := secretFromFileOrTerminal(env, *passFile, "Taşınabilir yönetici parolası: ", "--passphrase-file")
	if err != nil {
		return err
	}
	priv, sg, err := admin.OpenPortableAdmin(blob, pass, root, netID)
	wipe(pass)
	if err != nil {
		return err
	}
	trust.WipeKey(priv)
	fmt.Fprintf(env.Stdout, "Taşınabilir dosya geçerli: %s, bitiş %s, işlemler %s\n", sg.Grant.Name, formatTime(sg.Grant.NotAfter), joinAdminOps(sg.Grant.Operations))
	return nil
}

// --- shared token flags (PIV or OpenPGP, ADR-0171) ---

type g1TokenFlags struct {
	reader  *string
	kind    *string
	slot    *string
	pinFile *string
}

func addG1TokenFlags(fs *flag.FlagSet) g1TokenFlags {
	return g1TokenFlags{
		reader:  fs.String("token-reader", "", "kart okuyucu adının bir parçası (boş: ilk Yubico okuyucusu)"),
		kind:    fs.String("token-app", "auto", "jeton uygulaması: auto, piv veya openpgp"),
		slot:    fs.String("token-slot", "9c", "PIV yuvası: 9a, 9c, 9d veya 9e"),
		pinFile: fs.String("pin-file", "", "jeton PIN'ini bu dosyadan oku"),
	}
}

// g1Token is an opened token key.
type g1Token interface {
	trust.DigestSigner
	Close() error
}

// g1TokenInfo describes an opened token for "key token status".
type g1TokenInfo struct {
	Kind    string
	Version string
	Reader  string
}

// g1OpenTokenFunc opens a token; tests replace it (no PC/SC access).
var g1OpenTokenFunc = openRealToken

func g1OpenToken(env *Env, f g1TokenFlags) (g1Token, error) {
	tok, _, err := g1OpenTokenFunc(env, f)
	return tok, err
}

func pinReader(env *Env, f g1TokenFlags) func() ([]byte, error) {
	return func() ([]byte, error) {
		return secretFromFileOrTerminal(env, *f.pinFile, "Jeton PIN'i: ", "--pin-file")
	}
}
