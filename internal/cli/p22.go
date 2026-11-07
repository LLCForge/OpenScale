package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

// P22 commands: k-of-n document approval (ADR-0121), the root key on a PIV
// token (ADR-0123), read-only TPM status (ADR-0124), the quorum backup
// (ADR-0125), the air-gapped owner device (ADR-0126) and travel mode
// (ADR-0129), plus the P15 coordinator limits (ADR-0111) as flags of
// "coordinator run".

const (
	maxApprovalFile   = 8 << 10
	maxManagementKey  = 256
	maxApproversText  = 16 << 10
	p22RootKeyFile    = "root.key"
	p22DocumentFile   = "network.json"
	hwUntestedWarning = "UYARI: donanım jetonu desteği donanımda denenmedi (yalnızca sahte jetonla test edildi, ADR-0123). Kök anahtarın parolalı kopyası ve yedekleri her zaman geçerli kalır."
)

func p22Commands() []command {
	return []command{
		{"network approval set", "Belge onayı için k-of-n onaycı politikası: --threshold k --approvers ad=ANAHTAR,... | --clear", cmdApprovalSet},
		{"network approval show", "Geçerli ağ belgesinin onay durumunu gösterir", cmdApprovalShow},
		{"network quorum-backup", "Kök anahtarın k-of-n sahipli (eşikli parolalı) yedeğini üretir", cmdQuorumBackup},
		{"network quorum-restore", "Kök anahtarı en az k sahibin parolasıyla eşikli yedekten geri yükler", cmdQuorumRestore},
		{"approve keygen", "Belge onaycısı için parolayla korunan Ed25519 anahtarı üretir", cmdApproveKeygen},
		{"approve sign", "İmzalı ağ belgesini kökle doğrular ve onay imzası üretir (dosya anahtarı veya --token)", cmdApproveSign},
		{"approve add", "Onaycının imzasını yönetici cihazdaki geçerli belgeye ekler", cmdApproveAdd},
		{"travel start", "Seyahat kipi: kök anahtar ve yönetim dosyalarını şifreli arşive taşıyıp bu bilgisayardan kaldırır", cmdTravelStart},
		{"travel end", "Seyahat arşivini yedek kök anahtarla açıp yönetim dosyalarını geri yükler", cmdTravelEnd},
		{"travel status", "Ağ klasörünün seyahat kipinde olup olmadığını gösterir", cmdTravelStatus},
		{"airgap check", "Bu bilgisayarın ağa bağlanabilen arayüzlerini listeler (çevrimdışı yönetici cihaz denetimi)", cmdAirgapCheck},
		{"airgap export", "İmzalı, açık belgeleri (network.json, transitions.json) USB belleğe kopyalar", cmdAirgapExport},
		{"airgap import", "Aktarılan belgeleri güvenilen köke göre doğrulayıp servisin ağ klasörüne yerleştirir", cmdAirgapImport},
		{"tpm status", "TPM 2.0 varlığını ve sabit özelliklerini salt okunur gösterir", cmdTPMStatus},
	}
}

// --- k-of-n document approval (ADR-0121) ---

func cmdApprovalSet(env *Env, args []string) error {
	fs := newFlagSet(env, "network approval set")
	common := addEditFlags(fs)
	threshold := fs.Int("threshold", 0, "gereken farklı onay sayısı (k)")
	approvers := fs.String("approvers", "", "onaycılar: ad=ANAHTAR,ad2=ANAHTAR2 ya da @dosya (anahtar: 'approve keygen' veya 'key hw status' çıktısı)")
	clearPolicy := fs.Bool("clear", false, "onay politikasını kaldırır (bu sürüm yine mevcut politikanın onaylarını ister)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *clearPolicy {
		if *threshold != 0 || *approvers != "" {
			return usageError("--clear ile --threshold veya --approvers birlikte kullanılamaz")
		}
		if err := runEdit(env, common, admin.SetApprovalPolicy(nil)); err != nil {
			return err
		}
		if !*common.dryRun {
			fmt.Fprintln(env.Stdout, "Politika kaldırıldı; bu sürüm mevcut onaycıların imzası eklenene kadar cihazlarca kabul edilmez.")
		}
		return nil
	}
	if *approvers == "" {
		return usageError("--approvers zorunlu (veya --clear)")
	}
	text, err := readArg(*approvers, maxApproversText)
	if err != nil {
		return err
	}
	list, err := parseApprovers(text)
	if err != nil {
		return err
	}
	if *threshold < 1 || *threshold > len(list) {
		return usageError("--threshold 1 ile onaycı sayısı (%d) arasında olmalı", len(list))
	}
	policy := &trust.ApprovalPolicy{Threshold: *threshold, Approvers: list}
	if err := runEdit(env, common, admin.SetApprovalPolicy(policy)); err != nil {
		return err
	}
	if !*common.dryRun {
		fmt.Fprintf(env.Stdout, "Onay politikası: %d/%d. Cihazlar bu sürümü onaylar eklenene kadar kabul etmez:\n", *threshold, len(list))
		fmt.Fprintln(env.Stdout, "  onaycı: openscale approve sign --document network.json --key onayci.key --out onay.json")
		fmt.Fprintln(env.Stdout, "  sahip:  openscale approve add --dir <ağ klasörü> --approval onay.json")
	}
	return nil
}

// parseApprovers reads "name=KEY" items separated by commas or new lines.
func parseApprovers(text string) ([]trust.Approver, error) {
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	var out []trust.Approver
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		name, keyText, ok := strings.Cut(f, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, usageError("--approvers öğesi ad=ANAHTAR biçiminde olmalı: %q", f)
		}
		k, err := trust.ParseKey(strings.TrimSpace(keyText))
		if err != nil {
			return nil, usageError("onaycı %q anahtarı geçersiz: %v", name, err)
		}
		if slices.ContainsFunc(out, func(a trust.Approver) bool { return a.Name == name }) {
			return nil, usageError("onaycı %q iki kez verildi", name)
		}
		out = append(out, trust.Approver{Name: name, Key: k})
	}
	if len(out) == 0 {
		return nil, usageError("en az bir onaycı gerekli")
	}
	if len(out) > trust.MaxApprovers {
		return nil, usageError("en fazla %d onaycı olabilir", trust.MaxApprovers)
	}
	return out, nil
}

func cmdApprovalShow(env *Env, args []string) error {
	fs := newFlagSet(env, "network approval show")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	st, err := n.Approvals()
	if err != nil {
		return err
	}
	printApprovalStatus(env, st)
	return nil
}

func printApprovalStatus(env *Env, st admin.ApprovalStatus) {
	w := env.Stdout
	if st.Policy == nil {
		fmt.Fprintln(w, "Bu belgede onay politikası yok.")
	} else {
		fmt.Fprintf(w, "Onay politikası: %d/%d onaycı\n", st.Policy.Threshold, len(st.Policy.Approvers))
		for _, a := range st.Policy.Approvers {
			mark := "eksik"
			if slices.Contains(st.Approved, a.Name) {
				mark = "onaylı"
			}
			fmt.Fprintf(w, "  %-16s %s  [%s]\n", a.Name, a.Key, mark)
		}
	}
	if len(st.Approved) > 0 {
		fmt.Fprintf(w, "Onaylayanlar: %s\n", strings.Join(st.Approved, ", "))
	}
	if len(st.Missing) > 0 {
		fmt.Fprintf(w, "Onayı eksik olanlar: %s\n", strings.Join(st.Missing, ", "))
	}
	if st.Complete {
		fmt.Fprintln(w, "Durum: tamam; cihazlar bu sürümü kabul eder.")
	} else {
		fmt.Fprintln(w, "Durum: eksik; politikası sabit cihazlar bu sürümü onaylar eklenene kadar kabul etmez.")
	}
}

func cmdApproveKeygen(env *Env, args []string) error {
	fs := newFlagSet(env, "approve keygen")
	out := fs.String("out", "", "onaycı anahtar dosyası (zorunlu; onaycının kendi cihazında kalır)")
	passFile := fs.String("passphrase-file", "", "onaycı anahtarının parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError("--out zorunlu")
	}
	pass, err := newPassphrase(env, *passFile, "Onaycı anahtarı")
	if err != nil {
		return err
	}
	defer wipe(pass)
	pub, priv, err := ed25519.GenerateKey(env.Random)
	if err != nil {
		return err
	}
	defer wipe(priv)
	sealed, err := trust.SealRootKey(priv, pass, env.Argon2, env.Random)
	if err != nil {
		return err
	}
	data, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("onaycı anahtarı yazılamadı: %w", err)
	}
	var k trust.Key
	copy(k[:], pub)
	w := env.Stdout
	fmt.Fprintf(w, "Onaycı anahtarı yazıldı: %s\n", *out)
	fmt.Fprintf(w, "Açık anahtar: %s\n", k)
	fmt.Fprintf(w, "Parmak izi: %s\n", sealed.Fingerprint())
	fmt.Fprintln(w, "Açık anahtarı sahibe iletin: openscale network approval set --threshold k --approvers <ad>=<açık anahtar>,...")
	return nil
}

func cmdApproveSign(env *Env, args []string) error {
	fs := newFlagSet(env, "approve sign")
	document := fs.String("document", "", "onaylanacak imzalı ağ belgesi (network.json, zorunlu)")
	keyFile := fs.String("key", "", "onaycı anahtar dosyası ('approve keygen')")
	passFile := fs.String("passphrase-file", "", "onaycı anahtarının parolasını bu dosyadan oku")
	token := fs.Bool("token", false, "onaycı anahtarı PIV donanım jetonunda (Windows)")
	pf := addPIVFlags(fs)
	pinFile := fs.String("pin-file", "", "jeton PIN'ini bu dosyadan oku")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı (verilmezse --dir veya --state-dir'den okunur)")
	dir := fs.String("dir", "", "yönetici ağ klasörü (kök açık anahtarı buradan okunur)")
	stateDir := fs.String("state-dir", "", "üye durum klasörü (sabitlenmiş kök buradan okunur; varsayılan: kullanıcı klasörü)")
	out := fs.String("out", "", "onay dosyası (zorunlu)")
	dryRun := fs.Bool("dry-run", false, "belgeyi doğrula ve göster ama imzalama")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *document == "" {
		return usageError("--document zorunlu")
	}
	slot, err := parseSlot(*pf.slot)
	if err != nil {
		return err
	}
	if !*dryRun {
		if *out == "" {
			return usageError("--out zorunlu")
		}
		if (*keyFile == "") == !*token {
			return usageError("--key veya --token seçeneklerinden tam olarak biri gerekli")
		}
	}
	data, err := securefile.ReadLimited(*document, trust.MaxEnvelopeSize)
	if err != nil {
		return fmt.Errorf("belge okunamadı: %w", err)
	}
	root, err := trustedRoot(env, *rootText, *dir, *stateDir)
	if err != nil {
		return err
	}
	envl, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return err
	}
	if *dryRun {
		doc, err := trust.VerifyDocumentSignature(envl, root)
		if err != nil {
			return err
		}
		printApprovedDocument(env, doc)
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: onay imzası üretilmedi.")
		return nil
	}
	var c trust.Cosignature
	var doc *trust.Document
	if *keyFile != "" {
		keyData, err := securefile.ReadPrivate(*keyFile, trust.MaxSealedKeySize)
		if err != nil {
			return fmt.Errorf("onaycı anahtarı okunamadı: %w", err)
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
		defer wipe(priv)
		if c, doc, err = trust.ApproveDocument(priv, envl, root); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(env.Stderr, hwUntestedWarning)
		card, err := openPIVCard(*pf.reader)
		if err != nil {
			return err
		}
		defer card.Close()
		client, err := piv.NewClient(card)
		if err != nil {
			return err
		}
		signer, err := piv.NewSigner(client, slot, func() ([]byte, error) {
			return secretFromFileOrTerminal(env, *pinFile, "Jeton PIN'i: ", "--pin-file")
		})
		if err != nil {
			return err
		}
		if c, doc, err = trust.ApproveDocumentWith(signer, envl, root); err != nil {
			return err
		}
	}
	encoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, append(encoded, '\n')); err != nil {
		return fmt.Errorf("onay yazılamadı: %w", err)
	}
	printApprovedDocument(env, doc)
	fmt.Fprintf(env.Stdout, "Onay yazıldı: %s\n", *out)
	fmt.Fprintln(env.Stdout, "Sahip eklemek için: openscale approve add --dir <ağ klasörü> --approval "+*out)
	return nil
}

func printApprovedDocument(env *Env, doc *trust.Document) {
	w := env.Stdout
	fmt.Fprintf(w, "Belge kök anahtarla doğrulandı: ağ %s, sürüm %d, %d cihaz, %d kural, geçerlilik sonu %s\n",
		doc.NetworkID, doc.Version, len(doc.Devices), len(doc.Rules), formatTime(doc.ExpiresAt))
	if doc.Approval != nil {
		fmt.Fprintf(w, "Belgenin onay politikası: %d/%d onaycı\n", doc.Approval.Threshold, len(doc.Approval.Approvers))
	}
}

func cmdApproveAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "approve add")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	approval := fs.String("approval", "", "onaycının ürettiği onay dosyası (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *approval == "" {
		return usageError("--approval zorunlu")
	}
	data, err := securefile.ReadLimited(*approval, maxApprovalFile)
	if err != nil {
		return fmt.Errorf("onay dosyası okunamadı: %w", err)
	}
	c, err := decodeCosignature(data)
	if err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	st, err := n.AddApproval(c)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Onay eklendi (anahtar %s).\n", c.Key)
	printApprovalStatus(env, st)
	return nil
}

func decodeCosignature(data []byte) (trust.Cosignature, error) {
	var c trust.Cosignature
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return trust.Cosignature{}, fmt.Errorf("onay dosyası bozuk: %w", err)
	}
	if dec.More() {
		return trust.Cosignature{}, errors.New("onay dosyası bozuk: fazladan veri")
	}
	if c.Key.IsZero() || len(c.Signature) != ed25519.SignatureSize {
		return trust.Cosignature{}, errors.New("onay dosyası bozuk: anahtar veya imza eksik")
	}
	return c, nil
}

// trustedRoot returns the root public key a document is checked against:
// given explicitly, read from an owner's network directory, or the root a
// member device has pinned.
func trustedRoot(env *Env, rootText, dir, stateDir string) (ed25519.PublicKey, error) {
	switch {
	case rootText != "":
		k, err := trust.ParseKey(strings.TrimSpace(rootText))
		if err != nil {
			return nil, usageError("--root geçersiz: %v", err)
		}
		return ed25519.PublicKey(append([]byte(nil), k[:]...)), nil
	case dir != "":
		sealed, err := readNetworkRootKey(dir)
		if err != nil {
			return nil, err
		}
		return sealed.RootPublicKey(), nil
	}
	sd, err := resolveStateDir(env, stateDir)
	if err != nil {
		return nil, err
	}
	store, err := member.Open(sd)
	if err != nil {
		return nil, fmt.Errorf("güvenilen kök okunamadı (--root, --dir veya --state-dir verin): %w", err)
	}
	root := store.Anchor().RootKey
	if len(root) != ed25519.PublicKeySize {
		return nil, errors.New("bu cihazda sabitlenmiş kök yok; --root verin")
	}
	return append(ed25519.PublicKey(nil), root...), nil
}

func readNetworkRootKey(dir string) (*trust.SealedRootKey, error) {
	if admin.Traveling(dir) {
		return nil, admin.ErrTraveling
	}
	data, err := securefile.ReadPrivate(filepath.Join(dir, p22RootKeyFile), trust.MaxSealedKeySize)
	if err != nil {
		return nil, fmt.Errorf("kök anahtar dosyası okunamadı: %w", err)
	}
	return trust.UnmarshalSealedRootKey(data)
}

// secretFromFileOrTerminal reads a secret from file, or without echo from
// the terminal.
func secretFromFileOrTerminal(env *Env, file, prompt, flagName string) ([]byte, error) {
	if file != "" {
		return readPassphraseFile(file)
	}
	if !env.IsTerminal() {
		return nil, usageError("terminal yok; %s kullan", flagName)
	}
	return env.ReadSecret(prompt)
}

// --- Hardware root key on a PIV token (ADR-0123) ---

// pivCard is a connected token; tests replace openPIVCard.
type pivCard interface {
	piv.Transport
	Close() error
}

var openPIVCard = func(reader string) (pivCard, error) {
	c, err := piv.Open(reader)
	if err != nil {
		return nil, err
	}
	return c, nil
}

type pivFlags struct {
	reader *string
	slot   *string
}

func addPIVFlags(fs *flag.FlagSet) pivFlags {
	return pivFlags{
		reader: fs.String("reader", "", "kart okuyucu adının bir parçası (boş: ilk Yubico okuyucusu)"),
		slot:   fs.String("slot", "9c", "PIV yuvası: 9a, 9c, 9d veya 9e"),
	}
}

func parseSlot(s string) (byte, error) {
	switch strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x")) {
	case "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuth, nil
	}
	return 0, usageError("--slot 9a, 9c, 9d veya 9e olmalı")
}

func parsePINPolicy(s string) (byte, error) {
	switch s {
	case "always":
		return piv.PINPolicyAlways, nil
	case "once":
		return piv.PINPolicyOnce, nil
	case "never":
		return piv.PINPolicyNever, nil
	case "default":
		return piv.PINPolicyDefault, nil
	}
	return 0, usageError("--pin-policy always, once, never veya default olmalı")
}

func parseTouchPolicy(s string) (byte, error) {
	switch s {
	case "always":
		return piv.TouchPolicyAlways, nil
	case "cached":
		return piv.TouchPolicyCached, nil
	case "never":
		return piv.TouchPolicyNever, nil
	case "default":
		return piv.TouchPolicyDefault, nil
	}
	return 0, usageError("--touch-policy always, cached, never veya default olmalı")
}

func parseManagementAlg(s string) (byte, error) {
	switch strings.ToLower(s) {
	case "aes192":
		return piv.AlgAES192, nil
	case "aes128":
		return piv.AlgAES128, nil
	case "aes256":
		return piv.AlgAES256, nil
	case "3des":
		return piv.AlgTDES, nil
	}
	return 0, usageError("--management-alg aes192, aes128, aes256 veya 3des olmalı")
}

func cmdKeyHWImport(env *Env, args []string) error {
	fs := newFlagSet(env, "key hw import")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	pf := addPIVFlags(fs)
	mgmtKey := fs.String("management-key", "", "PIV yönetim anahtarı, onaltılık veya @dosya (zorunlu)")
	mgmtAlg := fs.String("management-alg", "aes192", "yönetim anahtarı türü: aes192 (5.7 varsayılanı), aes128, aes256 veya 3des")
	pinPolicy := fs.String("pin-policy", "always", "PIN politikası: always, once, never veya default")
	touchPolicy := fs.String("touch-policy", "always", "dokunma politikası: always, cached, never veya default")
	confirm := fs.String("confirm", "", "onay metni (betikler için): JETON")
	dryRun := fs.Bool("dry-run", false, "yapılacak işlemi göster ama jetona dokunma")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	slot, err := parseSlot(*pf.slot)
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
	alg, err := parseManagementAlg(*mgmtAlg)
	if err != nil {
		return err
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stderr, hwUntestedWarning)
	if *dryRun {
		fmt.Fprintf(env.Stdout, "Kök anahtar (parmak izi %s) jetonun %02X yuvasına PIN=%s, dokunma=%s politikasıyla aktarılacaktı.\n", n.RootFingerprint(), slot, *pinPolicy, *touchPolicy)
		fmt.Fprintln(env.Stdout, "Kuru çalıştırma: jetona hiçbir şey yazılmadı.")
		return nil
	}
	if *mgmtKey == "" {
		return usageError("--management-key zorunlu")
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
	if err := confirmCritical(env, *confirm, "JETON", fmt.Sprintf("Kök anahtarın bir kopyası jetonun %02X yuvasına aktarılacak; yuvadaki anahtarın üzerine yazılır", slot)); err != nil {
		return err
	}
	passphrase, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	card, err := openPIVCard(*pf.reader)
	if err != nil {
		return err
	}
	defer card.Close()
	client, err := piv.NewClient(card)
	if err != nil {
		return err
	}
	ver, err := client.CheckEd25519Support()
	if err != nil {
		return err
	}
	if err := client.AuthenticateManagementKey(piv.ManagementKey{Algorithm: alg, Key: mk}, env.Random); err != nil {
		return err
	}
	if err := n.ImportRootKeyToToken(passphrase, client, slot, pinPol, touchPol); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Kök anahtar jetonun %02X yuvasına aktarıldı (firmware %s); jetondaki açık anahtar kökle aynı.\n", slot, ver)
	fmt.Fprintln(env.Stdout, "root.key ve yedekleri geçerli kalır; jeton kaybolursa kök rotasyonunu düşünün (openscale network rotate-root).")
	return nil
}

func cmdKeyHWStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "key hw status")
	pf := addPIVFlags(fs)
	dir := fs.String("dir", "", "ağ klasörü; verilirse yuvadaki anahtar kökle karşılaştırılır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	slot, err := parseSlot(*pf.slot)
	if err != nil {
		return err
	}
	var root ed25519.PublicKey
	if *dir != "" {
		sealed, err := readNetworkRootKey(*dir)
		if err != nil {
			return err
		}
		root = sealed.RootPublicKey()
	}
	fmt.Fprintln(env.Stderr, hwUntestedWarning)
	card, err := openPIVCard(*pf.reader)
	if err != nil {
		return err
	}
	defer card.Close()
	client, err := piv.NewClient(card)
	if err != nil {
		return err
	}
	w := env.Stdout
	ver, err := client.Version()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Firmware: %s\n", ver)
	if !ver.AtLeast(piv.MinEd25519Firmware) {
		fmt.Fprintf(w, "Bu jeton PIV'de Ed25519 desteklemiyor (%s veya üstü gerekir).\n", piv.MinEd25519Firmware)
		return nil
	}
	md, err := client.Metadata(slot)
	if err != nil {
		return err
	}
	if md.Algorithm != piv.AlgEd25519 || len(md.PublicKey) != ed25519.PublicKeySize {
		fmt.Fprintf(w, "Yuva %02X: Ed25519 anahtarı yok.\n", slot)
		return nil
	}
	var k trust.Key
	copy(k[:], md.PublicKey)
	origin := "jetonda üretilmiş"
	if md.Imported {
		origin = "içe aktarılmış"
	}
	fmt.Fprintf(w, "Yuva %02X: Ed25519 (%s), PIN politikası %d, dokunma politikası %d\n", slot, origin, md.PINPolicy, md.TouchPolicy)
	fmt.Fprintf(w, "Açık anahtar: %s\n", k)
	if root != nil {
		if subtle.ConstantTimeCompare(root, md.PublicKey) == 1 {
			fmt.Fprintln(w, "Bu yuvadaki anahtar ağın kök anahtarıyla aynı.")
		} else {
			fmt.Fprintln(w, "UYARI: bu yuvadaki anahtar ağın kök anahtarı değil.")
		}
	}
	return nil
}

// --- TPM (ADR-0124), read-only ---

var (
	tpmDetect = tpm.Detect
	tpmOpen   = tpm.Open
)

func cmdTPMStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "tpm status")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	w := env.Stdout
	p, err := tpmDetect()
	if errors.Is(err, tpm.ErrUnsupported) {
		fmt.Fprintln(w, "Bu sistemde TPM erişimi uygulanmadı.")
		return nil
	}
	if errors.Is(err, tpm.ErrNotFound) || (err == nil && !p.Present) {
		fmt.Fprintln(w, "TPM bulunamadı.")
		return nil
	}
	if err != nil {
		return err
	}
	version := p.Version
	if version == "" {
		version = "bilinmiyor"
	}
	fmt.Fprintf(w, "TPM: var, sürüm %s", version)
	if p.Interface != "" {
		fmt.Fprintf(w, " (%s)", p.Interface)
	}
	fmt.Fprintln(w)
	if p.Version != "" && p.Version != "2.0" {
		fmt.Fprintln(w, "Yalnızca TPM 2.0 desteklenir.")
		return nil
	}
	t, err := tpmOpen()
	if err != nil {
		return err
	}
	defer t.Close()
	info, err := tpm.Query(t)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Aile: %s, revizyon %s, yıl %d\n", info.Family, info.Revision, info.Year)
	fmt.Fprintf(w, "Üretici: %s %s\n", info.Manufacturer, info.VendorString)
	fmt.Fprintf(w, "Firmware: %s\n", info.FirmwareVersion)
	fmt.Fprintln(w, "Salt okuma: yalnızca TPM2_GetCapability gönderildi; TPM'de hiçbir şey değiştirilmedi.")
	return nil
}

// --- Quorum backup (ADR-0125) ---

func cmdQuorumBackup(env *Env, args []string) error {
	fs := newFlagSet(env, "network quorum-backup")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	out := fs.String("out", "", "eşikli yedek dosyası (zorunlu; her sahibe bir kopyası verilir)")
	threshold := fs.Int("threshold", 0, "yedeği açmak için gereken sahip sayısı (k)")
	holders := fs.String("holders", "", "sahip adları: a,b,c (en fazla 6)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	holderFiles := fs.String("holder-passphrase-files", "", "sahiplerin parola dosyaları, --holders sırasıyla: pa,pb,pc")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError("--out zorunlu")
	}
	names := splitList(*holders)
	if len(names) < 2 || len(names) > trust.MaxQuorumHolders {
		return usageError("--holders 2 ile %d arasında ad içermeli", trust.MaxQuorumHolders)
	}
	if *threshold < 1 || *threshold > len(names) {
		return usageError("--threshold 1 ile sahip sayısı (%d) arasında olmalı", len(names))
	}
	files := splitList(*holderFiles)
	if len(files) != 0 && len(files) != len(names) {
		return usageError("--holder-passphrase-files her sahip için bir dosya içermeli")
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	sealed, err := readNetworkRootKey(*dir)
	if err != nil {
		return err
	}
	if sealed.Fingerprint() != n.RootFingerprint() {
		return errors.New("root.key bu ağın kök anahtarı değil")
	}
	pass, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	priv, err := sealed.Open(pass)
	wipe(pass)
	if err != nil {
		return err
	}
	defer wipe(priv)
	passphrases := make([][]byte, len(names))
	defer func() {
		for _, p := range passphrases {
			wipe(p)
		}
	}()
	for i, name := range names {
		file := ""
		if len(files) > 0 {
			file = files[i]
		}
		if passphrases[i], err = newPassphrase(env, file, fmt.Sprintf("Sahip %q", name)); err != nil {
			return err
		}
	}
	qb, err := trust.SealQuorum(priv, names, passphrases, *threshold, env.Argon2, env.Random)
	if err != nil {
		return err
	}
	data, err := trust.MarshalQuorumBackup(qb)
	if err != nil {
		return err
	}
	if err := securefile.WriteNew(*out, data); err != nil {
		return fmt.Errorf("eşikli yedek yazılamadı: %w", err)
	}
	// Read back and open with the first k holders.
	written, err := securefile.ReadPrivate(*out, trust.MaxQuorumBackupSize)
	if err != nil {
		return fmt.Errorf("eşikli yedek yazıldı ama geri okunamadı (%s): %w", *out, err)
	}
	check, err := trust.UnmarshalQuorumBackup(written)
	if err != nil {
		return fmt.Errorf("eşikli yedek yazıldı ama doğrulanamadı (%s): %w", *out, err)
	}
	subset := map[int][]byte{}
	for i := range *threshold {
		subset[i] = passphrases[i]
	}
	opened, err := check.OpenQuorum(subset)
	if err != nil {
		return fmt.Errorf("eşikli yedek yazıldı ama açılamadı (%s): %w", *out, err)
	}
	same := subtle.ConstantTimeCompare(opened, priv) == 1
	wipe(opened)
	if !same {
		return fmt.Errorf("eşikli yedek yazıldı ama başka bir anahtar içeriyor (%s)", *out)
	}
	fmt.Fprintf(env.Stdout, "Eşikli yedek yazıldı ve geri açılarak doğrulandı: %s\n", *out)
	fmt.Fprintf(env.Stdout, "%d sahipten herhangi %d tanesi parolalarıyla birlikte kök anahtarı açar (%d mühürlü kopya).\n", len(names), *threshold, len(qb.Copies))
	fmt.Fprintln(env.Stdout, "Her sahip dosyanın bir kopyasını ve yalnızca kendi parolasını saklar. Geri yüklemek için: openscale network quorum-restore")
	return nil
}

func cmdQuorumRestore(env *Env, args []string) error {
	fs := newFlagSet(env, "network quorum-restore")
	dir := fs.String("dir", "", "ağ klasörü; network.json burada olmalı (zorunlu)")
	from := fs.String("from", "", "eşikli yedek dosyası (zorunlu)")
	holders := fs.String("holders", "", "parolasını girecek sahipler: a,c")
	holderFiles := fs.String("holder-passphrase-files", "", "bu sahiplerin parola dosyaları, aynı sırayla")
	newPassFile := fs.String("new-passphrase-file", "", "geri yüklenen kök anahtarın yeni parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *from == "" {
		return usageError("--dir ve --from zorunlu")
	}
	names := splitList(*holders)
	if len(names) == 0 {
		return usageError("--holders zorunlu")
	}
	files := splitList(*holderFiles)
	if len(files) != 0 && len(files) != len(names) {
		return usageError("--holder-passphrase-files her sahip için bir dosya içermeli")
	}
	data, err := securefile.ReadPrivate(*from, trust.MaxQuorumBackupSize)
	if err != nil {
		return fmt.Errorf("eşikli yedek okunamadı: %w", err)
	}
	qb, err := trust.UnmarshalQuorumBackup(data)
	if err != nil {
		return err
	}
	passphrases := map[int][]byte{}
	defer func() {
		for _, p := range passphrases {
			wipe(p)
		}
	}()
	for i, name := range names {
		idx := slices.Index(qb.Holders, name)
		if idx < 0 {
			return usageError("%q bu yedeğin sahiplerinden değil (sahipler: %s)", name, strings.Join(qb.Holders, ", "))
		}
		if _, dup := passphrases[idx]; dup {
			return usageError("%q iki kez verildi", name)
		}
		file := ""
		if len(files) > 0 {
			file = files[i]
		}
		p, err := secretFromFileOrTerminal(env, file, fmt.Sprintf("%s parolası: ", name), "--holder-passphrase-files")
		if err != nil {
			return err
		}
		passphrases[idx] = p
	}
	priv, err := qb.OpenQuorum(passphrases)
	if err != nil {
		return err
	}
	defer wipe(priv)
	newPass, err := newPassphrase(env, *newPassFile, "Geri yüklenen kök anahtar")
	if err != nil {
		return err
	}
	defer wipe(newPass)
	sealed, err := trust.SealRootKey(priv, newPass, env.Argon2, env.Random)
	if err != nil {
		return err
	}
	keyData, err := trust.MarshalSealedRootKey(sealed)
	if err != nil {
		return err
	}
	if err := admin.Restore(*dir, keyData, newPass, env.adminOptions()); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Kök anahtar eşikli yedekten geri yüklendi ve yeni parolayla mühürlendi.")
	fmt.Fprintln(env.Stdout, "Yeni bir yedek alın: openscale network backup")
	return nil
}

// --- Travel mode (ADR-0129) ---

func cmdTravelStart(env *Env, args []string) error {
	fs := newFlagSet(env, "travel start")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	backup := fs.String("backup", "", "kök anahtarın yedeği ('network backup'; dönüş için gerekli, zorunlu)")
	backupPassFile := fs.String("backup-passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	out := fs.String("out", "", "şifreli seyahat arşivi; ağ klasörünün dışında olmalı (zorunlu)")
	confirm := fs.String("confirm", "", "onay metni (betikler için): SEYAHAT")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *backup == "" || *out == "" {
		return usageError("--dir, --backup ve --out zorunlu")
	}
	if admin.Traveling(*dir) {
		return admin.ErrTraveling
	}
	data, err := securefile.ReadPrivate(*backup, trust.MaxSealedKeySize)
	if err != nil {
		return fmt.Errorf("yedek okunamadı: %w", err)
	}
	if err := confirmCritical(env, *confirm, "SEYAHAT", "Kök anahtar ve yönetim dosyaları şifreli arşive taşınıp bu bilgisayardan silinecek"); err != nil {
		return err
	}
	pass, err := secretFromFileOrTerminal(env, *backupPassFile, "Yedek parolası: ", "--backup-passphrase-file")
	if err != nil {
		return err
	}
	defer wipe(pass)
	rep, err := admin.PrepareTravel(*dir, data, pass, *out, env.Random, env.Now())
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintf(w, "Seyahat kipi açık: %d dosya şifreli arşive taşındı ve bu bilgisayardan silindi.\n", rep.Files)
	fmt.Fprintf(w, "Arşiv: %s\nArşiv SHA-256: %s\n", *out, rep.ArchiveSHA256)
	fmt.Fprintln(w, "Arşivi ve yedeği bu bilgisayardan ayrı saklayın. SSD'lerde silme en iyi çabadır.")
	fmt.Fprintf(w, "Dönüşte: openscale travel end --dir %s --backup <yedek> --from <arşiv>\n", *dir)
	return nil
}

func cmdTravelEnd(env *Env, args []string) error {
	fs := newFlagSet(env, "travel end")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	backup := fs.String("backup", "", "kök anahtarın yedeği (zorunlu)")
	backupPassFile := fs.String("backup-passphrase-file", "", "yedeğin parolasını bu dosyadan oku")
	from := fs.String("from", "", "seyahat arşivi (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *backup == "" || *from == "" {
		return usageError("--dir, --backup ve --from zorunlu")
	}
	data, err := securefile.ReadPrivate(*backup, trust.MaxSealedKeySize)
	if err != nil {
		return fmt.Errorf("yedek okunamadı: %w", err)
	}
	archive, err := securefile.ReadLimited(*from, admin.MaxTravelArchive)
	if err != nil {
		return fmt.Errorf("seyahat arşivi okunamadı: %w", err)
	}
	pass, err := secretFromFileOrTerminal(env, *backupPassFile, "Yedek parolası: ", "--backup-passphrase-file")
	if err != nil {
		return err
	}
	defer wipe(pass)
	rep, err := admin.ReturnFromTravel(*dir, data, pass, archive)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Seyahat kipi kapandı: %d dosya geri yüklendi (arşiv SHA-256 %s).\n", rep.Files, rep.ArchiveSHA256)
	fmt.Fprintln(env.Stdout, "Arşivi artık güvenle silebilirsiniz.")
	return nil
}

func cmdTravelStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "travel status")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	if admin.Traveling(*dir) {
		fmt.Fprintln(env.Stdout, "Seyahat kipi: açık (kök anahtar ve yönetim dosyaları bu bilgisayarda değil).")
	} else {
		fmt.Fprintln(env.Stdout, "Seyahat kipi: kapalı.")
	}
	return nil
}

// --- Air-gapped owner device (ADR-0126) ---

func printOfflineCheck(w io.Writer) (bool, error) {
	ifaces, err := admin.OfflineCheck()
	if err != nil {
		return false, err
	}
	if len(ifaces) == 0 {
		fmt.Fprintln(w, "Ağa bağlanabilen etkin arayüz yok: bu bilgisayar çevrimdışı görünüyor.")
		return true, nil
	}
	fmt.Fprintln(w, "UYARI: bu bilgisayarın etkin ağ arayüzleri var; çevrimdışı yönetici cihazda hiçbiri olmamalı:")
	for _, ifc := range ifaces {
		fmt.Fprintf(w, "  %s: %s\n", ifc.Name, strings.Join(ifc.Addrs, ", "))
	}
	return false, nil
}

func cmdAirgapCheck(env *Env, args []string) error {
	fs := newFlagSet(env, "airgap check")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	_, err := printOfflineCheck(env.Stdout)
	return err
}

func cmdAirgapExport(env *Env, args []string) error {
	fs := newFlagSet(env, "airgap export")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	out := fs.String("out", "", "aktarım klasörü, ör. USB bellek; ağ klasörünün dışında olmalı (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError("--out zorunlu")
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	if _, err := printOfflineCheck(env.Stderr); err != nil {
		return err
	}
	names, err := n.ExportTransfer(*out)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("aktarılacak dosya yok")
	}
	fmt.Fprintf(env.Stdout, "Doğrulanıp kopyalandı: %s -> %s\n", strings.Join(names, ", "), *out)
	fmt.Fprintln(env.Stdout, "Bu dosyalar açık ve imzalıdır; gizli hiçbir şey içermez. Çevrimiçi cihazda: openscale airgap import --from <klasör> --network-dir <servisin ağ klasörü>")
	return nil
}

func cmdAirgapImport(env *Env, args []string) error {
	fs := newFlagSet(env, "airgap import")
	from := fs.String("from", "", "aktarım klasörü (zorunlu)")
	networkDir := fs.String("network-dir", "", "servisin izlediği ağ klasörü (zorunlu)")
	rootText := fs.String("root", "", "güvenilen kök açık anahtarı (verilmezse --state-dir'deki sabitlenmiş kök)")
	stateDir := fs.String("state-dir", "", "üye durum klasörü (varsayılan: kullanıcı klasörü)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *from == "" || *networkDir == "" {
		return usageError("--from ve --network-dir zorunlu")
	}
	root, err := trustedRoot(env, *rootText, "", *stateDir)
	if err != nil {
		return err
	}
	doc, err := admin.ImportTransfer(*from, *networkDir, root)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Belge sürüm %d (ağ %s) kökle doğrulandı ve %s klasörüne yerleştirildi.\n", doc.Version, doc.NetworkID, filepath.Join(*networkDir, p22DocumentFile))
	fmt.Fprintln(env.Stdout, "Servis yeni belgeyi algılayıp koordinatöre yayınlar.")
	return nil
}

// --- Coordinator limits (ADR-0111, P15) ---

type coordinatorLimitFlags struct {
	controlRate     *int
	controlBurst    *int
	controlTotal    *int
	relayMaxPeers   *int
	relayTotalRate  *int64
	requireSessions *bool
}

func addCoordinatorLimitFlags(fs *flag.FlagSet) coordinatorLimitFlags {
	return coordinatorLimitFlags{
		controlRate:     fs.Int("control-rate", 0, fmt.Sprintf("cihaz başına kontrol isteği sınırı, istek/sn (0: varsayılan %d; %d-%d)", coordinator.DefaultControlRate, coordinator.MinControlRate, coordinator.MaxControlRate)),
		controlBurst:    fs.Int("control-burst", 0, fmt.Sprintf("cihaz başına kontrol isteği ani yük sınırı (0: varsayılan %d; %d-%d)", coordinator.DefaultControlBurst, coordinator.MinControlRate, coordinator.MaxControlBurst)),
		controlTotal:    fs.Int("control-total-rate", 0, fmt.Sprintf("bütün cihazlar için toplam kontrol isteği sınırı, istek/sn (0: varsayılan %d; %d-%d)", coordinator.DefaultControlTotalRate, coordinator.MinControlRate, coordinator.MaxControlRate*10)),
		relayMaxPeers:   fs.Int("relay-max-peers", 0, fmt.Sprintf("aktarıcıda bir cihazın dakikada ulaşabileceği farklı eş sayısı (0: varsayılan %d; en fazla %d)", coordinator.DefaultRelayMaxPeers, coordinator.MaxRelayMaxPeers)),
		relayTotalRate:  fs.Int64("relay-total-rate", 0, "aktarıcının toplam bant sınırı, bayt/sn (0: sınırsız; en az 65536)"),
		requireSessions: fs.Bool("relay-require-sessions", false, "yalnızca cihaz imzalı oturum açmış cihazlar için aktar (eski istemciler aktarıcıyı kullanamaz)"),
	}
}

func (f coordinatorLimitFlags) resolve() error {
	check := func(v, lo, hi int, name string) error {
		if v != 0 && (v < lo || v > hi) {
			return usageError("--%s %d ile %d arasında olmalı", name, lo, hi)
		}
		return nil
	}
	if err := check(*f.controlRate, coordinator.MinControlRate, coordinator.MaxControlRate, "control-rate"); err != nil {
		return err
	}
	if err := check(*f.controlBurst, coordinator.MinControlRate, coordinator.MaxControlBurst, "control-burst"); err != nil {
		return err
	}
	if err := check(*f.controlTotal, coordinator.MinControlRate, coordinator.MaxControlRate*10, "control-total-rate"); err != nil {
		return err
	}
	if err := check(*f.relayMaxPeers, 1, coordinator.MaxRelayMaxPeers, "relay-max-peers"); err != nil {
		return err
	}
	if r := *f.relayTotalRate; r != 0 && (r < coordinator.MinRelayRate || r > coordinator.MaxRelayRate) {
		return usageError("--relay-total-rate %d ile %d bayt/sn arasında olmalı", coordinator.MinRelayRate, int64(coordinator.MaxRelayRate))
	}
	return nil
}
