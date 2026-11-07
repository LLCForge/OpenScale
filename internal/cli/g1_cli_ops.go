package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// --- sensitive devices (ADR-0174) ---

func cmdAdminSensitive(env *Env, args []string) error {
	return runG1Sub(env, "admin sensitive", []g1Sub{
		{"set", "Hassas hedefleri ve onaycıları belirler: --targets --threshold --approvers | --clear", cmdSensitiveSet},
		{"approve", "Onaycı olarak belgenin hassas erişim özetini imzalar", cmdSensitiveApprove},
		{"add", "Onaycının imzasını yönetici cihazdaki belgeye ekler", cmdSensitiveAdd},
		{"status", "Hassas cihazları ve onay durumunu gösterir", cmdSensitiveStatus},
	}, args)
}

func cmdSensitiveSet(env *Env, args []string) error {
	fs := newFlagSet(env, "admin sensitive set")
	common := addEditFlags(fs)
	targets := fs.String("targets", "", "hassas cihazlar veya tag:etiket, virgülle")
	threshold := fs.Int("threshold", 2, "gereken onay sayısı (çift kişi kuralı için 2)")
	approvers := fs.String("approvers", "", "onaycılar: ad=ANAHTAR,... ya da @dosya")
	clearIt := fs.Bool("clear", false, "kuralı kaldırır (mevcut onaycıların imzası gerekir)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *clearIt {
		return runEdit(env, common, admin.SetSensitivePolicy(nil))
	}
	if *targets == "" || *approvers == "" {
		return usageError("--targets ve --approvers zorunlu")
	}
	text, err := readArg(*approvers, maxApproversText)
	if err != nil {
		return err
	}
	list, err := parseApprovers(text)
	if err != nil {
		return err
	}
	p := &trust.SensitivePolicy{Targets: splitList(*targets), Threshold: *threshold, Approvers: list}
	return runEdit(env, common, admin.SetSensitivePolicy(p))
}

func cmdSensitiveApprove(env *Env, args []string) error {
	fs := newFlagSet(env, "admin sensitive approve")
	document := fs.String("document", "", "imzalı belge (zorunlu)")
	keyFile := fs.String("key", "", "onaycı anahtar dosyası ('approve keygen')")
	passFile := fs.String("passphrase-file", "", "onaycı anahtarı parolası")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı")
	dir := fs.String("dir", "", "yönetici ağ klasörü")
	stateDir := fs.String("state-dir", "", "üye durum klasörü")
	out := fs.String("out", "", "onay dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *document == "" || *keyFile == "" || *out == "" {
		return usageError("--document, --key ve --out zorunlu (jeton için: openscale key token approve --sensitive)")
	}
	data, err := securefile.ReadLimited(*document, trust.MaxEnvelopeSize)
	if err != nil {
		return err
	}
	root, err := trustedRoot(env, *rootText, *dir, *stateDir)
	if err != nil {
		return err
	}
	keyData, err := securefile.ReadPrivate(*keyFile, trust.MaxSealedKeySize)
	if err != nil {
		return err
	}
	sealed, err := trust.UnmarshalSealedRootKey(keyData)
	if err != nil {
		return err
	}
	pass, err := secretFromFileOrTerminal(env, *passFile, "Onaycı anahtarı parolası: ", "--passphrase-file")
	if err != nil {
		return err
	}
	priv, err := sealed.Open(pass)
	wipe(pass)
	if err != nil {
		return err
	}
	defer trust.WipeKey(priv)
	c, doc, err := admin.ApproveSensitiveWithKey(priv, data, root)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Hassas cihazlar: %s\n", strings.Join(doc.SensitiveDevices(), ", "))
	printApprovedDocument(env, doc)
	encoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, append(encoded, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Hassas erişim onayı yazıldı: %s\n", *out)
	return nil
}

func cmdSensitiveAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "admin sensitive add")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	approval := fs.String("approval", "", "onay dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *approval == "" {
		return usageError("--approval zorunlu")
	}
	data, err := securefile.ReadLimited(*approval, maxApprovalFile)
	if err != nil {
		return err
	}
	var c trust.Cosignature
	if err := json.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("onay dosyası okunamadı: %w", err)
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	st, err := n.AddSensitiveApproval(c)
	if err != nil {
		return err
	}
	printSensitive(env, st)
	return nil
}

func cmdSensitiveStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "admin sensitive status")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	st, err := n.Sensitive()
	if err != nil {
		return err
	}
	printSensitive(env, st)
	return nil
}

func printSensitive(env *Env, st admin.SensitiveState) {
	if len(st.Devices) == 0 && st.Needed == 0 {
		fmt.Fprintln(env.Stdout, "Hassas cihaz kuralı yok.")
		return
	}
	fmt.Fprintf(env.Stdout, "Hassas cihazlar: %s\n", strings.Join(st.Devices, ", "))
	fmt.Fprintf(env.Stdout, "Erişim özeti: %s\n", st.Fingerprint)
	fmt.Fprintf(env.Stdout, "Onaylar: %d/%d (%s)\n", len(st.Approved), st.Needed, strings.Join(st.Approved, ", "))
	if st.Complete {
		fmt.Fprintln(env.Stdout, "Durum: tamam; cihazlar bu sürümü kabul eder.")
	} else {
		fmt.Fprintln(env.Stdout, "Durum: eksik; cihazlar onaylar eklenene kadar bu sürümü reddeder.")
	}
}

// --- duress passphrase (ADR-0176) ---

func cmdAdminDuress(env *Env, args []string) error {
	return runG1Sub(env, "admin duress", []g1Sub{
		{"set", "Baskı parolasını belirler (önce kök anahtar yedeği gerekir)", cmdDuressSet},
		{"clear", "Baskı parolasını kaldırır", cmdDuressClear},
		{"status", "Baskı parolasının ayarlı olup olmadığını gösterir", cmdDuressStatus},
	}, args)
}

func cmdDuressSet(env *Env, args []string) error {
	fs := newFlagSet(env, "admin duress set")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolası")
	duressFile := fs.String("duress-passphrase-file", "", "baskı parolası dosyası")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	duress, err := newPassphrase(env, *duressFile, "Baskı parolası")
	if err != nil {
		return err
	}
	defer wipe(duress)
	if err := n.SetDuressPassphrase(pass, duress); err != nil {
		if errors.Is(err, admin.ErrDuressNoBackup) {
			return errors.New("önce kök anahtarın yedeğini alın (openscale network backup): baskı parolası yerel kök anahtarı siler")
		}
		return err
	}
	fmt.Fprintln(env.Stdout, "Baskı parolası ayarlandı. Panel girişinde kök parolası yerine yazılırsa: yerel kök ve yönetici anahtarları silinir, sessiz alarm kuyruğa alınır, zararsız salt okunur görünüm açılır.")
	fmt.Fprintln(env.Stdout, "Not: SSD'lerde üzerine yazma eski blokların silindiğini garanti etmez; tam disk şifrelemesi önerilir.")
	return nil
}

func cmdDuressClear(env *Env, args []string) error {
	fs := newFlagSet(env, "admin duress clear")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolası")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := n.ClearDuressPassphrase(pass); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Baskı parolası kaldırıldı.")
	return nil
}

func cmdDuressStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "admin duress status")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	if admin.DuressConfigured(*dir) {
		fmt.Fprintln(env.Stdout, "Baskı parolası: ayarlı")
	} else {
		fmt.Fprintln(env.Stdout, "Baskı parolası: yok")
	}
	return nil
}

// --- emergency documents (ADR-0175) ---

func cmdAdminEmergency(env *Env, args []string) error {
	return runG1Sub(env, "admin emergency", []g1Sub{
		{"prepare", "Acil durum belgelerini kökle önceden imzalar ve ayrı parolayla mühürler", cmdEmergencyPrepare},
		{"status", "Hazır acil durum belgelerini ve güncelliklerini gösterir", cmdEmergencyStatus},
		{"publish", "Panik: hazır belgeyi kök anahtar açılmadan yayımlar", cmdEmergencyPublish},
	}, args)
}

func cmdEmergencyPrepare(env *Env, args []string) error {
	fs := newFlagSet(env, "admin emergency prepare")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolası")
	sealFile := fs.String("emergency-passphrase-file", "", "acil durum parolası (kökten ayrı)")
	lock := fs.Bool("lockdown", true, "\"her şeyi kilitle\" belgesi hazırla")
	remove := fs.String("remove", "", "\"X cihazını çıkar\" belgeleri, virgülle")
	days := fs.Int("validity", 400, "belgelerin geçerliliği (gün, en çok 400)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	validity, err := daysFlag(*days, 1, int(trust.MaxValidity.Hours()/24), "validity")
	if err != nil {
		return err
	}
	var specs []admin.EmergencySpec
	for _, d := range splitList(*remove) {
		specs = append(specs, admin.EmergencySpec{Kind: admin.EmergencyRemove, Device: d})
	}
	if *lock {
		// The lock gets the highest version of the set.
		specs = append(specs, admin.EmergencySpec{Kind: admin.EmergencyLockdown})
	}
	if len(specs) == 0 {
		return usageError("hazırlanacak belge yok")
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(pass)
	seal, err := newPassphrase(env, *sealFile, "Acil durum parolası")
	if err != nil {
		return err
	}
	defer wipe(seal)
	recs, err := n.PrepareEmergency(pass, seal, specs, env.Now(), validity)
	if err != nil {
		return err
	}
	for _, r := range recs {
		fmt.Fprintf(env.Stdout, "Hazır: %s (sürüm %d, bitiş %s)\n", emergencyLabel(r), r.Version, formatTime(r.ExpiresAt))
		if r.NeedsApprovals {
			fmt.Fprintln(env.Stdout, "  UYARI: ağ onay istiyor; bu belgeye onaylar eklenmeden cihazlar onu reddeder.")
		}
	}
	fmt.Fprintln(env.Stdout, "Bir setten yalnızca bir belge yayımlanabilir; ağ değiştikçe yeniden hazırlayın.")
	return nil
}

func emergencyLabel(r admin.EmergencyRecord) string {
	if r.Kind == admin.EmergencyRemove {
		return "cihazı çıkar: " + r.Device
	}
	return "her şeyi kilitle"
}

func cmdEmergencyStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "admin emergency status")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	list, err := n.EmergencyStatus(env.Now())
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(env.Stdout, "Hazır acil durum belgesi yok.")
		return nil
	}
	for _, r := range list {
		state := "güncel"
		switch {
		case r.Expired:
			state = "süresi doldu"
		case r.Stale:
			state = "eski (ağ sonradan değişti; yayımlanırsa sonraki değişiklikler kaybolur)"
		}
		fmt.Fprintf(env.Stdout, "%s: sürüm %d, %s\n", emergencyLabel(r), r.Version, state)
	}
	return nil
}

func cmdEmergencyPublish(env *Env, args []string) error {
	fs := newFlagSet(env, "admin emergency publish")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	kind := fs.String("kind", admin.EmergencyLockdown, "lockdown veya remove")
	device := fs.String("device", "", "remove için cihaz adı")
	sealFile := fs.String("emergency-passphrase-file", "", "acil durum parolası")
	confirm := fs.String("confirm", "", "onay metni (betikler için): PANIK")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	if err := confirmCritical(env, *confirm, "PANIK", "Acil durum belgesi bütün cihazlara yayımlanacak"); err != nil {
		return err
	}
	seal, err := secretFromFileOrTerminal(env, *sealFile, "Acil durum parolası: ", "--emergency-passphrase-file")
	if err != nil {
		return err
	}
	defer wipe(seal)
	_, doc, err := n.PublishEmergency(*kind, *device, seal, env.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Acil durum belgesi yayımlandı: sürüm %d. Belge network.json olarak yerleştirildi; servis onu koordinatöre ve eşlere iletir.\n", doc.Version)
	return nil
}

// --- risk summary and personal data (ADR-0177) ---

func cmdAdminRisk(env *Env, args []string) error {
	fs := newFlagSet(env, "admin risk")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	document := fs.String("document", "", "karşılaştırılacak imzalı belge (verilmezse bekleyen taslak)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	cur, err := n.Document()
	if err != nil {
		return err
	}
	var next *trust.Document
	if *document != "" {
		data, err := securefile.ReadLimited(*document, trust.MaxEnvelopeSize)
		if err != nil {
			return err
		}
		e, err := trust.UnmarshalEnvelope(data)
		if err != nil {
			return err
		}
		root, err := trustedRoot(env, "", *dir, "")
		if err != nil {
			return err
		}
		if next, err = trust.VerifyDocumentSignature(e, root); err != nil {
			return err
		}
	} else {
		plan, err := n.PrepareDraft(env.Now(), trust.DefaultValidity)
		if err != nil {
			return err
		}
		next = plan.Next
	}
	r := admin.AssessRisk(cur, next)
	if *asJSON {
		return writeJSON(env.Stdout, r)
	}
	for _, line := range r.Lines() {
		fmt.Fprintln(env.Stdout, line)
	}
	return nil
}

func cmdAdminPII(env *Env, args []string) error {
	fs := newFlagSet(env, "admin pii")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	ws := admin.PersonalDataWarnings(doc)
	if *asJSON {
		if ws == nil {
			ws = []admin.PIIWarning{}
		}
		return writeJSON(env.Stdout, ws)
	}
	if len(ws) == 0 {
		fmt.Fprintln(env.Stdout, "Ağ adlarında kişisel veri kalıbı bulunmadı.")
		return nil
	}
	for _, w := range ws {
		fmt.Fprintln(env.Stdout, w.String())
	}
	fmt.Fprintln(env.Stdout, "Bu adlar her cihaza ve koordinatöre gider; nötr adlar (ör. laptop-1) önerilir.")
	return nil
}

// --- SSH user certificates (ADR-0179) ---

func cmdAdminSSHCert(env *Env, args []string) error {
	fs := newFlagSet(env, "admin ssh-cert")
	dir := fs.String("dir", "", "kök anahtarla imzalamak için ağ klasörü")
	rootPass := fs.String("root-passphrase-file", "", "kök anahtar parolası (--dir ile)")
	grantFile := fs.String("grant", "", "yönetici yetkisi (ssh.cert işlemi gerekir)")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı (yönetici ile)")
	stateDir := fs.String("state-dir", "", "üye durum klasörü (yönetici ile)")
	sf := addAdminSignerFlags(fs)
	userKey := fs.String("user-key", "", "kullanıcının OpenSSH açık anahtar dosyası (zorunlu)")
	principals := fs.String("principal", "", "hedefteki hesap adları, virgülle (zorunlu; root olamaz)")
	ttl := fs.Duration("ttl", admin.DefaultSSHCertLife, "geçerlilik (en çok 1 saat)")
	forward := fs.Bool("forwarding", false, "port yönlendirmeye izin ver")
	out := fs.String("out", "", "sertifika dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *userKey == "" || *principals == "" || *out == "" {
		return usageError("--user-key, --principal ve --out zorunlu")
	}
	keyText, err := securefile.ReadLimited(*userKey, maxCertInputFile)
	if err != nil {
		return err
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(keyText)
	if err != nil {
		return usageError("--user-key bir OpenSSH açık anahtarı olmalı: %v", err)
	}
	req := admin.SSHCertRequest{UserKey: pub, Principals: splitList(*principals), Lifetime: *ttl, KeyID: comment, Forwarding: *forward}
	now := env.Now()
	var cert *ssh.Certificate
	if *dir != "" {
		n, err := loadNetwork(env, *dir)
		if err != nil {
			return err
		}
		doc, err := n.Document()
		if err != nil {
			return err
		}
		sealed, err := readNetworkRootKey(*dir)
		if err != nil {
			return err
		}
		pass, err := existingPassphrase(env, *rootPass)
		if err != nil {
			return err
		}
		priv, err := sealed.Open(pass)
		wipe(pass)
		if err != nil {
			return err
		}
		defer trust.WipeKey(priv)
		if cert, err = admin.SignSSHUserCertWithKey(priv, doc.NetworkID, nil, req, now); err != nil {
			return err
		}
	} else {
		root, err := trustedRoot(env, *rootText, "", *stateDir)
		if err != nil {
			return err
		}
		netID, revoked, err := networkOfState(env, *stateDir)
		if err != nil {
			return err
		}
		src, err := openAdminKey(env, sf, root, netID)
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
		grantData = trimNewline(grantData)
		g, err := trust.CheckAdminGrant(grantData, root, netID, trust.AdminOpSSHCert, now, revoked)
		if err != nil {
			return err
		}
		sg := &trust.SignedGrant{Grant: *g, Encoded: grantData}
		if src.token != nil {
			cert, err = admin.SignSSHUserCertWith(src.token, netID, sg, req, now)
		} else {
			cert, err = admin.SignSSHUserCertWithKey(src.priv, netID, sg, req, now)
		}
		if err != nil {
			return err
		}
	}
	if err := securefile.WriteNew(*out, ssh.MarshalAuthorizedKey(cert)); err != nil {
		return err
	}
	until := time.Unix(int64(cert.ValidBefore), 0) //nolint:gosec // set from the current time above
	fmt.Fprintf(env.Stdout, "SSH sertifikası yazıldı: %s (hesaplar %s, %s tarihine kadar)\n", *out, strings.Join(cert.ValidPrincipals, ","), formatTime(until))
	return nil
}

func networkOfState(env *Env, stateDir string) (string, []string, error) {
	sd, err := resolveStateDir(env, stateDir)
	if err != nil {
		return "", nil, err
	}
	store, err := member.Open(sd)
	if err != nil {
		return "", nil, err
	}
	doc := store.Document()
	if doc == nil {
		return "", nil, errors.New("bu cihazda belge yok")
	}
	return doc.NetworkID, doc.RevokedAdmins, nil
}
