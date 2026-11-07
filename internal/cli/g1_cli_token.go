package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// "openscale key token ...": hardware tokens with automatic PIV/OpenPGP
// selection (internal/piv.OpenToken, ADR-0171). None of this was run
// against a real token; the tests use a fake token.

func g1KeyTokenSubcommands() []g1Sub {
	return []g1Sub{
		{"status", "Takılı jetonu salt okunur gösterir: uygulama, sürüm, açık anahtar ve rolü", cmdKeyTokenStatus},
		{"import", "Kök veya yönetici anahtarını jetona aktarır (PIV 5.7+ ya da OpenPGP, otomatik)", cmdKeyTokenImport},
		{"sign", "Bekleyen değişiklik taslağını jetondaki kök anahtarla imzalar", cmdKeyTokenSign},
		{"approve", "Belge onayını (k-of-n, ADR-0121) jetondaki onaycı anahtarıyla üretir", cmdKeyTokenApprove},
		{"session", "Jetonla yönetici oturumu açar ve rolünü gösterir (tepsi/pencere bunu kullanır)", cmdKeyTokenSession},
	}
}

func cmdG1KeyToken(env *Env, args []string) error {
	return runG1Sub(env, "key token", g1KeyTokenSubcommands(), args)
}

func tokenOptions(env *Env, f g1TokenFlags) (piv.TokenOptions, error) {
	o := piv.TokenOptions{Reader: *f.reader, PIN: pinReader(env, f)}
	switch strings.ToLower(*f.kind) {
	case "", "auto":
	case "piv":
		o.Kind = piv.KindPIV
	case "openpgp":
		o.Kind = piv.KindOpenPGP
	default:
		return o, usageError("--token-app auto, piv veya openpgp olmalı")
	}
	slot, err := parseSlot(*f.slot)
	if err != nil {
		return o, err
	}
	o.Slot = slot
	return o, nil
}

func openRealToken(env *Env, f g1TokenFlags) (g1Token, g1TokenInfo, error) {
	o, err := tokenOptions(env, f)
	if err != nil {
		return nil, g1TokenInfo{}, err
	}
	tok, err := piv.OpenToken(envContext(env), o)
	if err != nil {
		return nil, g1TokenInfo{}, err
	}
	return tok, g1TokenInfo{Kind: string(tok.Kind()), Version: tok.Version().String(), Reader: tok.Reader}, nil
}

func cmdKeyTokenStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "key token status")
	tf := addG1TokenFlags(fs)
	dir := fs.String("dir", "", "ağ klasörü; verilirse anahtar kökle karşılaştırılır")
	stateDir := fs.String("state-dir", "", "üye durum klasörü; verilirse kökle karşılaştırılır")
	grantFile := fs.String("grant", "", "yetki dosyası; verilirse anahtar yöneticiyle karşılaştırılır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	fmt.Fprintln(env.Stderr, g1TokenWarning)
	tok, info, err := g1OpenTokenFunc(env, tf)
	if err != nil {
		return err
	}
	defer tok.Close()
	var k trust.Key
	copy(k[:], tok.PublicKey())
	fmt.Fprintf(env.Stdout, "Uygulama: %s\nSürüm: %s\nOkuyucu: %s\nAçık anahtar: %s\n", info.Kind, info.Version, info.Reader, k)
	if *dir != "" || *stateDir != "" {
		root, err := trustedRoot(env, "", *dir, *stateDir)
		if err == nil && string(root) == string(tok.PublicKey()) {
			fmt.Fprintln(env.Stdout, "Rol: kök anahtar")
			return nil
		}
	}
	if *grantFile != "" {
		data, err := securefile.ReadLimited(*grantFile, maxGrantFile)
		if err != nil {
			return err
		}
		var e trust.Envelope
		var g trust.AdminGrant
		if json.Unmarshal(trimNewline(data), &e) == nil && json.Unmarshal(e.Payload, &g) == nil && g.Key == k {
			fmt.Fprintf(env.Stdout, "Rol: yönetici %s (yetki kimliği %s)\n", g.Name, g.ID)
			return nil
		}
	}
	fmt.Fprintln(env.Stdout, "Rol: bilinmiyor (kök veya verilen yetkiyle eşleşmedi)")
	return nil
}

func cmdKeyTokenImport(env *Env, args []string) error {
	fs := newFlagSet(env, "key token import")
	dir := fs.String("dir", "", "kök anahtarı aktarmak için ağ klasörü")
	adminKey := fs.String("admin-key", "", "aktarılacak yönetici anahtar dosyası")
	passFile := fs.String("passphrase-file", "", "kök/yönetici anahtar parolası")
	reader := fs.String("token-reader", "", "kart okuyucu adının bir parçası")
	app := fs.String("token-app", "auto", "auto (PIV 5.7+ varsa PIV, yoksa OpenPGP), piv veya openpgp")
	slotText := fs.String("token-slot", "9c", "PIV yuvası")
	mgmtKey := fs.String("management-key", "", "PIV yönetim anahtarı, onaltılık veya @dosya (PIV için)")
	mgmtAlg := fs.String("management-alg", "aes192", "PIV yönetim anahtarı türü")
	adminPINFile := fs.String("admin-pin-file", "", "OpenPGP yönetici PIN'i (PW3) dosyası (OpenPGP için)")
	pinPolicy := fs.String("pin-policy", "always", "PIV PIN politikası")
	touchPolicy := fs.String("touch-policy", "always", "dokunma politikası (PIV) / UIF (OpenPGP: always=on)")
	confirm := fs.String("confirm", "", "onay metni (betikler için): JETON")
	dryRun := fs.Bool("dry-run", false, "yalnızca ne yapılacağını göster")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if (*dir == "") == (*adminKey == "") {
		return usageError("--dir (kök) veya --admin-key seçeneklerinden tam olarak biri gerekli")
	}
	slot, err := parseSlot(*slotText)
	if err != nil {
		return err
	}
	what := "yönetici anahtarı"
	if *dir != "" {
		what = "kök anahtar"
	}
	fmt.Fprintln(env.Stderr, g1TokenWarning)
	if *dryRun {
		fmt.Fprintf(env.Stdout, "%s jetona (%s) aktarılacaktı. Kuru çalıştırma: jetona hiçbir şey yazılmadı.\n", what, *app)
		return nil
	}
	if err := confirmCritical(env, *confirm, "JETON", fmt.Sprintf("%s jetona aktarılacak; jetondaki imza anahtarının üzerine yazılır", what)); err != nil {
		return err
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	var priv ed25519.PrivateKey
	if *dir != "" {
		sealed, rerr := readNetworkRootKey(*dir)
		if rerr != nil {
			wipe(pass)
			return rerr
		}
		priv, err = sealed.Open(pass)
	} else {
		data, rerr := securefile.ReadPrivate(*adminKey, maxAdminKeyFile)
		if rerr != nil {
			wipe(pass)
			return rerr
		}
		priv, err = admin.OpenAdminKeyFile(data, pass)
	}
	wipe(pass)
	if err != nil {
		return err
	}
	defer trust.WipeKey(priv)
	card, err := openPIVCard(*reader)
	if err != nil {
		return err
	}
	defer card.Close()
	kind := piv.Kind(strings.ToLower(*app))
	if kind == "auto" || kind == "" {
		if kind, _, err = piv.ChooseImportBackend(card); err != nil {
			return err
		}
	}
	switch kind {
	case piv.KindPIV:
		if *mgmtKey == "" {
			return usageError("PIV için --management-key zorunlu")
		}
		mkText, err := readArg(*mgmtKey, maxManagementKey)
		if err != nil {
			return err
		}
		mk, err := hex.DecodeString(strings.TrimSpace(mkText))
		if err != nil {
			return usageError("--management-key onaltılık olmalı")
		}
		defer wipe(mk)
		alg, err := parseManagementAlg(*mgmtAlg)
		if err != nil {
			return err
		}
		pinPol, err := parsePINPolicy(*pinPolicy)
		if err != nil {
			return err
		}
		touchPol, err := parseTouchPolicy(*touchPolicy)
		if err != nil {
			return err
		}
		client, err := piv.NewClient(card)
		if err != nil {
			return err
		}
		if _, err := client.CheckEd25519Support(); err != nil {
			return err
		}
		if err := client.AuthenticateManagementKey(piv.ManagementKey{Algorithm: alg, Key: mk}, env.Random); err != nil {
			return err
		}
		if err := client.ImportEd25519(slot, priv, pinPol, touchPol); err != nil {
			return err
		}
	case piv.KindOpenPGP:
		pin, err := secretFromFileOrTerminal(env, *adminPINFile, "OpenPGP yönetici PIN'i (PW3): ", "--admin-pin-file")
		if err != nil {
			return err
		}
		defer wipe(pin)
		client, err := piv.NewOpenPGPClient(card)
		if err != nil {
			return err
		}
		uif := byte(piv.UIFOn)
		if *touchPolicy == "never" {
			uif = piv.UIFOff
		}
		if err := client.ImportEd25519(pin, priv, piv.OpenPGPImportOptions{UIF: uif, SinglePINUse: true, Created: env.Now()}); err != nil {
			return err
		}
	default:
		return usageError("--token-app auto, piv veya openpgp olmalı")
	}
	fmt.Fprintf(env.Stdout, "%s jetona aktarıldı (%s); jetondaki açık anahtar dosyadakiyle aynı.\n", what, kind)
	fmt.Fprintln(env.Stdout, "Parolalı dosya geçerli kalır; jeton kaybolursa yetkiyi geri alın (openscale admin revoke).")
	return nil
}

func cmdKeyTokenSign(env *Env, args []string) error {
	fs := newFlagSet(env, "key token sign")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	validity := fs.Int("validity", int(trust.DefaultValidity.Hours()/24), "geçerlilik (gün)")
	dryRun := fs.Bool("dry-run", false, "taslağı ve riski göster, imzalama")
	tf := addG1TokenFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	days, err := daysFlag(*validity, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	plan, err := n.PrepareDraft(env.Now(), days)
	if err != nil {
		return err
	}
	cur, err := n.Document()
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Değişiklikler:")
	for _, line := range plan.Diff.Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
	for _, line := range admin.AssessRisk(cur, plan.Next).Lines() {
		fmt.Fprintf(env.Stdout, "  %s\n", line)
	}
	if *dryRun {
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: hiçbir şey imzalanmadı.")
		return nil
	}
	fmt.Fprintln(env.Stderr, g1TokenWarning)
	tok, err := g1OpenToken(env, tf)
	if err != nil {
		return err
	}
	defer tok.Close()
	if err := n.CommitWith(plan, tok); err != nil {
		return err
	}
	if err := n.DiscardDraft(); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Ağ belgesi sürüm %d jetondaki kök anahtarla imzalandı.\n", plan.Next.Version)
	return nil
}

func cmdKeyTokenApprove(env *Env, args []string) error {
	fs := newFlagSet(env, "key token approve")
	document := fs.String("document", "", "onaylanacak imzalı belge (zorunlu)")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı")
	dir := fs.String("dir", "", "yönetici ağ klasörü")
	stateDir := fs.String("state-dir", "", "üye durum klasörü")
	sensitive := fs.Bool("sensitive", false, "belge onayı yerine hassas cihaz onayı üret (ADR-0174)")
	out := fs.String("out", "", "onay dosyası (zorunlu)")
	tf := addG1TokenFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *document == "" || *out == "" {
		return usageError("--document ve --out zorunlu")
	}
	data, err := securefile.ReadLimited(*document, trust.MaxEnvelopeSize)
	if err != nil {
		return err
	}
	root, err := trustedRoot(env, *rootText, *dir, *stateDir)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stderr, g1TokenWarning)
	tok, err := g1OpenToken(env, tf)
	if err != nil {
		return err
	}
	defer tok.Close()
	var c trust.Cosignature
	var doc *trust.Document
	if *sensitive {
		c, doc, err = admin.ApproveSensitiveWithToken(tok, data, root)
	} else {
		envl, uerr := trust.UnmarshalEnvelope(data)
		if uerr != nil {
			return uerr
		}
		c, doc, err = trust.ApproveDocumentWith(tok, envl, root)
	}
	if err != nil {
		return err
	}
	printApprovedDocument(env, doc)
	encoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, append(encoded, '\n')); err != nil {
		return fmt.Errorf("onay yazılamadı: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Onay yazıldı: %s\n", *out)
	return nil
}

func cmdKeyTokenSession(env *Env, args []string) error {
	fs := newFlagSet(env, "key token session")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı")
	stateDir := fs.String("state-dir", "", "üye durum klasörü")
	grantFile := fs.String("grant", "", "yönetici yetki dosyası (kök oturumu için gerekmez)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	tf := addG1TokenFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	root, err := trustedRoot(env, *rootText, "", *stateDir)
	if err != nil {
		return err
	}
	sd, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	store, err := member.Open(sd)
	if err != nil {
		return err
	}
	doc := store.Document()
	if doc == nil {
		return errors.New("bu cihazda belge yok")
	}
	var grant []byte
	if *grantFile != "" {
		if grant, err = securefile.ReadLimited(*grantFile, maxGrantFile); err != nil {
			return err
		}
		grant = trimNewline(grant)
	}
	fmt.Fprintln(env.Stderr, g1TokenWarning)
	s, err := admin.OpenTokenSession(envContext(env), func(_ context.Context) (admin.TokenSigner, error) {
		return g1OpenToken(env, tf)
	}, root, doc.NetworkID, grant, doc.RevokedAdmins, admin.SessionOptions{Now: env.Now})
	if err != nil {
		return err
	}
	defer s.Close()
	info := s.Info()
	if *asJSON {
		return writeJSON(env.Stdout, info)
	}
	switch info.Role {
	case admin.SessionRoot:
		fmt.Fprintln(env.Stdout, "Yönetici kipi: kök anahtar jetonu takılı.")
	default:
		fmt.Fprintf(env.Stdout, "Yönetici kipi: %s (işlemler %s), oturum %s tarihine kadar.\n", info.Name, joinAdminOps(info.Operations), formatTime(info.Ends))
	}
	return nil
}
