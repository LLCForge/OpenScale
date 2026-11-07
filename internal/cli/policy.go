package cli

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

// Commands for the edits of ADR-0019, ADR-0020, ADR-0021, ADR-0024 and
// F-160. Every edit of the signed document goes through runEdit: the
// difference is printed first and --dry-run stops before the passphrase.

const maxRotationFile = 8 << 10

// --- devices (ADR-0019, ADR-0021) ---

func cmdDeviceExtend(env *Env, args []string) error {
	fs := newFlagSet(env, "device extend")
	common := addEditFlags(fs)
	name := fs.String("name", "", "cihaz adı (zorunlu)")
	days := fs.Int("days", int(trust.DefaultDeviceLife.Hours()/24), "üyelik bugünden itibaren kaç gün sürsün (1-3650)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	life, err := daysFlag(*days, 1, int(trust.MaxDeviceLife.Hours()/24), "days")
	if err != nil {
		return err
	}
	now := env.Now()
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error {
		_, err := doc.ExtendDevice(*name, now, life)
		return err
	}, *name))
}

func cmdDeviceExpire(env *Env, args []string) error {
	fs := newFlagSet(env, "device expire")
	common := addEditFlags(fs)
	name := fs.String("name", "", "cihaz adı (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	now := env.Now()
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error {
		_, err := doc.ExpireDevice(*name, now)
		return err
	}, *name))
}

func cmdDeviceRename(env *Env, args []string) error {
	fs := newFlagSet(env, "device rename")
	common := addEditFlags(fs)
	name := fs.String("name", "", "cihazın şimdiki adı (zorunlu)")
	newName := fs.String("new-name", "", "yeni ad: küçük harf, rakam ve tire (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *newName == "" {
		return usageError("--name ve --new-name zorunlu")
	}
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error {
		return doc.RenameDevice(*name, strings.TrimSpace(*newName))
	}, *name))
}

func cmdDeviceTag(env *Env, args []string) error {
	fs := newFlagSet(env, "device tag")
	common := addEditFlags(fs)
	name := fs.String("name", "", "cihaz adı (zorunlu)")
	tags := fs.String("tags", "", "etiketler, virgülle ayrılmış (ör. sunucu,ev); mevcut etiketlerin yerine geçer")
	clear := fs.Bool("clear", false, "cihazın bütün etiketlerini kaldır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	list := splitList(*tags)
	switch {
	case *name == "":
		return usageError("--name zorunlu")
	case *clear && len(list) > 0:
		return usageError("--tags ve --clear birlikte kullanılamaz")
	case !*clear && len(list) == 0:
		return usageError("--tags veya --clear gerekli")
	case len(list) > trust.MaxTags:
		return usageError("en fazla %d etiket verilebilir", trust.MaxTags)
	}
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error {
		return doc.SetDeviceTags(*name, list)
	}, *name))
}

// --- key rotation (ADR-0020) ---

// cmdDeviceRotateKey runs on the device: it creates new keys and the
// request the owner approves. The new keys wait in device.key.next until
// the owner's new document lists them.
func cmdDeviceRotateKey(env *Env, args []string) error {
	flags := newFlagSet(env, "device rotate-key")
	stateDir := flags.String("state-dir", "", "cihazın durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	replace := flags.Bool("replace", false, "bekleyen bir yenileme isteği varsa onu atıp yeni anahtar üret")
	finish := flags.Bool("finish", false, "onaylanmış yenilemeyi bitir: belge yeni anahtarı listeliyorsa ona geç")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	store, err := member.Open(dir)
	if err != nil {
		return err
	}
	doc := store.Document()
	if *finish {
		_, ok, err := service.PromoteRotatedKey(dir, doc)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("belge yeni anahtarı henüz listelemiyor; yönetici yenilemeyi onayladıktan sonra yeni belgeyi alın (ör. 'openscale join --bundle ...') ve tekrar deneyin")
		}
		fmt.Fprintln(env.Stdout, "Yeni anahtarlara geçildi. Eski anahtar dosyası device.key.old-* olarak saklandı.")
		return nil
	}
	nextPath := filepath.Join(dir, service.NextKeyFile)
	if _, err := readSecrets(nextPath); err == nil && !*replace {
		return errors.New("bekleyen bir anahtar yenileme isteği var; yeni bir istek için --replace kullan (eski istek geçersiz olur)")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("bekleyen anahtar okunamadı: %w", err)
	}
	secrets, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	if _, err := selfDevice(doc, secrets); err != nil {
		return err
	}
	next, signed, req, err := secrets.NewKeyRotation(env.Random, doc.NetworkID, env.Now())
	if err != nil {
		return err
	}
	line, err := trust.EncodeKeyRotation(signed)
	if err != nil {
		return err
	}
	data, err := trust.MarshalDeviceSecrets(next)
	if err != nil {
		return err
	}
	defer wipe(data)
	if err := securefile.Replace(nextPath, data); err != nil {
		return fmt.Errorf("yeni anahtar yazılamadı: %w", err)
	}
	w := env.Stdout
	fmt.Fprintln(w, "Yeni anahtarlar üretildi; eskileri yönetici onaylayana kadar kullanılmaya devam eder.")
	fmt.Fprintln(w, "\nAnahtar yenileme isteği (yönetici cihazda panele veya 'openscale device approve-rotation --request ...' komutuna ver):")
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "\nParmak izi: %s\n", req.Fingerprint())
	fmt.Fprintln(w, "Yönetici bu parmak izini kendisi yazmalı; eşleşmezse yenileme imzalanmaz.")
	fmt.Fprintf(w, "İstek %d saat geçerlidir. Anahtarın çalındığından şüpheleniyorsan yenileme yerine cihazı iptal edip yeniden kaydet.\n", int(trust.KeyRotationMaxAge.Hours()))
	return nil
}

func cmdDeviceApproveRotation(env *Env, args []string) error {
	fs := newFlagSet(env, "device approve-rotation")
	common := addEditFlags(fs)
	request := fs.String("request", "", "cihazdaki anahtar yenileme isteği satırı veya @dosya (zorunlu)")
	fingerprint := fs.String("fingerprint", "", "cihaz ekranındaki parmak izi (terminal yoksa zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *common.dir == "" || *request == "" {
		return usageError("--dir ve --request zorunlu")
	}
	line := *request
	if path, ok := strings.CutPrefix(line, "@"); ok {
		data, err := securefile.ReadLimited(path, maxRotationFile)
		if err != nil {
			return fmt.Errorf("istek dosyası okunamadı: %w", err)
		}
		line = string(data)
	}
	n, err := admin.Load(*common.dir, env.adminOptions())
	if err != nil {
		return err
	}
	pending, err := n.InspectKeyRotation(line, env.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Anahtarı yenilenecek cihaz: %s\n", pending.Device.Name)
	// The owner types the fingerprint shown on the device; it is not
	// printed here, so it cannot just be copied (ADR-0020).
	typed := *fingerprint
	if typed == "" {
		if !env.IsTerminal() {
			return usageError("terminal yok; cihazdaki parmak izini --fingerprint ile ver")
		}
		if typed, err = env.ReadLine("Cihazda görünen parmak izini yaz: "); err != nil {
			return err
		}
	}
	got := trust.NormalizeFingerprint(typed)
	if got == "" {
		return admin.ErrFingerprintMismatch
	}
	signed := pending.Signed
	now := env.Now()
	return runEdit(env, common, func(doc *trust.Document) error {
		rot, err := trust.OpenKeyRotation(doc, signed, now)
		if err != nil {
			return err
		}
		want := trust.NormalizeFingerprint(rot.Fingerprint())
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return admin.ErrFingerprintMismatch
		}
		_, err = doc.ApplyKeyRotation(signed, now)
		return err
	})
}

// --- groups (ADR-0021) ---

func cmdGroupSet(env *Env, args []string) error {
	fs := newFlagSet(env, "group set")
	common := addEditFlags(fs)
	name := fs.String("name", "", "grup adı: küçük harf, rakam ve tire (zorunlu)")
	members := fs.String("members", "", "üyeler, virgülle ayrılmış cihaz adları, tag:<etiket>, IP/CIDR veya host:<ad>; boş grup için boş bırak")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	list := normalizeAddrList(splitList(*members)) // IP -> /32 (#277, f4a_commands.go)
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error { return doc.SetGroup(*name, list) }, list...))
}

func cmdGroupRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "group rm")
	common := addEditFlags(fs)
	name := fs.String("name", "", "silinecek grup (zorunlu); kurallarda kullanılan grup silinemez")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error { return doc.RemoveGroup(*name) }, trust.GroupPrefix+*name))
}

func cmdGroupList(env *Env, args []string) error {
	doc, err := loadDocument(env, args, "group list")
	if err != nil || doc == nil {
		return err
	}
	if len(doc.Groups) == 0 {
		fmt.Fprintln(env.Stdout, "Grup yok.")
		return nil
	}
	for _, g := range doc.Groups {
		members := strings.Join(g.Members, ", ")
		if members == "" {
			members = "(boş: hiçbir cihazla eşleşmez)"
		}
		fmt.Fprintf(env.Stdout, "group:%s  %s\n", g.Name, members)
	}
	printTagWarnings(env, doc)
	return nil
}

// --- rules (ADR-0021) ---

func cmdRuleDisable(env *Env, args []string) error { return ruleState(env, args, "rule disable", true) }
func cmdRuleEnable(env *Env, args []string) error  { return ruleState(env, args, "rule enable", false) }

func ruleState(env *Env, args []string, name string, disabled bool) error {
	fs := newFlagSet(env, name)
	common := addEditFlags(fs)
	number := fs.String("number", "", "kuralın numarası ('network show' çıktısındaki) (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	idx, err := strconv.Atoi(*number)
	if err != nil || idx < 1 {
		return usageError("--number 1 veya daha büyük bir sayı olmalı")
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetRuleDisabled(idx-1, disabled) })
}

// parseRuleAction accepts allow/izin and deny/reddet.
func parseRuleAction(s string) (trust.RuleAction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "allow", "izin":
		return "", nil
	case "deny", "reddet":
		return trust.RuleDeny, nil
	}
	return "", usageError("--action allow veya deny olmalı")
}

// --- exit node users (ADR-0021, F-036) ---

func cmdExitUsersSet(env *Env, args []string) error {
	fs := newFlagSet(env, "exit users set")
	common := addEditFlags(fs)
	users := fs.String("users", "", "çıkış düğümünü kullanabilecekler: cihaz adları, tag:<etiket>, group:<grup>, IP/CIDR veya host:<ad>, virgülle ayrılmış")
	none := fs.Bool("none", false, "hiçbir cihaz çıkış düğümü kullanamasın")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	list := normalizeAddrList(splitList(*users)) // #277, f4a_commands.go
	switch {
	case *none && len(list) > 0:
		return usageError("--users ve --none birlikte kullanılamaz")
	case !*none && len(list) == 0:
		return usageError("--users veya --none gerekli; herkese açmak için 'openscale exit users clear'")
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetExitUsers(list) })
}

func cmdExitUsersClear(env *Env, args []string) error {
	fs := newFlagSet(env, "exit users clear")
	common := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.ClearExitUsers() })
}

func cmdExitUsersShow(env *Env, args []string) error {
	doc, err := loadDocument(env, args, "exit users show")
	if err != nil || doc == nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "Çıkış düğümü kullanıcıları: "+exitUsersText(doc))
	return nil
}

func exitUsersText(doc *trust.Document) string {
	users, set := doc.ExitUsersList()
	switch {
	case !set:
		return "herkes (kısıtlama yok)"
	case len(users) == 0:
		return "hiçbir cihaz"
	}
	return strings.Join(users, ", ")
}

// --- network DNS (ADR-0024) ---

// splitFlag collects repeated --split domain=addr,addr values.
type splitFlag []trust.SplitDNS

func (s *splitFlag) String() string { return "" }

func (s *splitFlag) Set(v string) error {
	if len(*s) >= trust.MaxSplitDomains {
		return fmt.Errorf("en fazla %d alan adı", trust.MaxSplitDomains)
	}
	domain, list, ok := strings.Cut(v, "=")
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !ok || domain == "" {
		return errors.New("biçim alan=adres[,adres] olmalı, ör. ev.lan=100.80.0.5")
	}
	addrs, err := parseAddrList(list)
	if err != nil {
		return err
	}
	*s = append(*s, trust.SplitDNS{Domain: domain, Nameservers: addrs})
	return nil
}

func parseAddrList(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range splitList(s) {
		a, err := netip.ParseAddr(part)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("%q geçerli bir IP adresi değil", part)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

func cmdNetworkDNSSet(env *Env, args []string) error {
	fs := newFlagSet(env, "network dns set")
	common := addEditFlags(fs)
	nameservers := fs.String("nameservers", "", "ağ geneli çözücüler: ağdaki cihazların OpenScale adresleri, virgülle ayrılmış")
	var split splitFlag
	fs.Var(&split, "split", "alan adını belirli çözücülere gönder: alan=adres[,adres] (tekrarlanabilir), ör. ev.lan=100.80.0.5")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	ns, err := parseAddrList(*nameservers)
	if err != nil {
		return usageError("--nameservers: %v", err)
	}
	if len(ns) == 0 && len(split) == 0 {
		return usageError("--nameservers veya --split gerekli; kaldırmak için 'openscale network dns clear'")
	}
	settings := &trust.DNSSettings{Nameservers: ns, Split: split}
	fmt.Fprintln(env.Stdout, "Not: eski sürümlü cihazlar dns bölümü olan belgeyi reddeder; önce bütün cihazları güncelle.")
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetDNS(settings) })
}

func cmdNetworkDNSClear(env *Env, args []string) error {
	fs := newFlagSet(env, "network dns clear")
	common := addEditFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetDNS(nil) })
}

func cmdNetworkDNSShow(env *Env, args []string) error {
	doc, err := loadDocument(env, args, "network dns show")
	if err != nil || doc == nil {
		return err
	}
	printDNS(env, doc)
	printZone(env, doc)
	return nil
}

func printDNS(env *Env, doc *trust.Document) {
	w := env.Stdout
	if doc.DNS == nil {
		fmt.Fprintln(w, "Ağ DNS ayarı yok: yalnızca MagicDNS adları ağ üzerinden çözülür.")
		return
	}
	if len(doc.DNS.Nameservers) > 0 {
		fmt.Fprintf(w, "Ağ geneli çözücüler: %s (çıkış düğümü kullanılırken uygulanmaz)\n", joinAddrs(doc.DNS.Nameservers))
	}
	for _, e := range doc.DNS.Split {
		fmt.Fprintf(w, "  %s => %s\n", e.Domain, joinAddrs(e.Nameservers))
	}
	for _, msg := range resolverWarnings(doc) {
		fmt.Fprintf(w, "UYARI: %s\n", msg)
	}
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// resolverWarnings names resolver devices other devices cannot reach on
// 53/udp under the current rules.
func resolverWarnings(doc *trust.Document) []string {
	if doc.DNS == nil {
		return nil
	}
	byAddr := map[netip.Addr]string{}
	for _, d := range doc.Devices {
		byAddr[d.IPv4], byAddr[d.IPv6] = d.Name, d.Name
	}
	seen := map[string]bool{}
	var out []string
	check := func(addrs []netip.Addr) {
		for _, a := range addrs {
			res, ok := byAddr[a]
			if !ok || seen[res] {
				continue
			}
			seen[res] = true
			var blocked []string
			for _, d := range doc.Devices {
				if d.Name != res && !doc.Allows(d.Name, res, trust.ProtocolUDP, 53) {
					blocked = append(blocked, d.Name)
				}
			}
			if len(blocked) > 0 {
				out = append(out, fmt.Sprintf("%s çözücüsüne 53/udp kuralı yok; şu cihazların sorguları yanıtsız kalır: %s", res, strings.Join(blocked, ", ")))
			}
		}
	}
	check(doc.DNS.Nameservers)
	for _, e := range doc.DNS.Split {
		check(e.Nameservers)
	}
	return out
}

// --- network display name (F-160) ---

func cmdNetworkNameSet(env *Env, args []string) error {
	fs := newFlagSet(env, "network name set")
	common := addEditFlags(fs)
	name := fs.String("name", "", "ağın görünen adı, 1-64 karakter (ör. \"Ev ağı\")")
	clear := fs.Bool("clear", false, "görünen adı kaldır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	value := strings.TrimSpace(*name)
	switch {
	case *clear && value != "":
		return usageError("--name ve --clear birlikte kullanılamaz")
	case !*clear && value == "":
		return usageError("--name veya --clear gerekli")
	}
	if value != "" {
		if err := trust.ValidateDisplayName(value); err != nil {
			return usageError("%s", admin.Describe(err))
		}
	}
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetDisplayName(value) })
}

// --- invites (ADR-0014, F-133) ---

func cmdInviteCreate(env *Env, args []string) error {
	fs := newFlagSet(env, "invite create")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	hours := fs.Int("hours", int(trust.DefaultInviteLife.Hours()), "davetin geçerlilik süresi (saat)")
	tags := fs.String("tags", "", "katılan cihaza verilecek etiketler, virgülle ayrılmış (ör. sunucu)")
	passFile := fs.String("passphrase-file", "", "parolayı bu dosyadan oku")
	// Multi-use invites and local notes (ADR-0028, F-184, F-132).
	uses := fs.Int("uses", 1, "davetle katılabilecek cihaz sayısı; her katılım yine onay ister")
	note := fs.String("note", "", "davetin kime verildiğini anımsatan açıklama (yalnızca bu bilgisayarda tutulur)")
	// QR registration (#182, P27): the phone's camera reads the code.
	showCodeQR := fs.Bool("qr", false, "davet kodunu telefon kamerası için QR olarak da çiz")
	codePNG := fs.String("png", "", "davet kodunun QR kodunu bu PNG dosyasına da yaz (davet sırrını içerir)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	if *uses < 1 || *uses > trust.MaxInviteUses {
		return usageError("--uses 1 ile %d arasında olmalı", trust.MaxInviteUses)
	}
	maxHours := int(trust.MaxInviteLife.Hours())
	if *hours < 1 || *hours > maxHours {
		return usageError("--hours 1 ile %d arasında olmalı", maxHours)
	}
	list := splitList(*tags)
	if len(list) > trust.MaxTags {
		return usageError("en fazla %d etiket verilebilir", trust.MaxTags)
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	if doc, err := n.Document(); err != nil {
		return err
	} else if doc.Coordinator == nil {
		return errors.New("ağ belgesinde koordinatör yok; davet için önce 'openscale network set-coordinator' çalıştır")
	}
	passphrase, err := existingPassphrase(env, *passFile)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	created, err := n.CreateInviteWith(passphrase, env.Now(), admin.InviteRequest{Life: time.Duration(*hours) * time.Hour, Tags: list, MaxUses: *uses, Note: *note})
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintln(w, "Davet kodu (yeni cihazda uygulamaya veya 'openscale invite-join --code ...' komutuna ver):")
	if *showCodeQR || *codePNG != "" {
		if err := showInviteQR(env, created.Code, *showCodeQR, *codePNG); err != nil {
			return err
		}
	}
	fmt.Fprintln(w, created.Code)
	fmt.Fprintf(w, "\nGeçerlilik sonu: %s\n", formatTime(created.Invite.ExpiresAt))
	if len(created.Invite.Tags) > 0 {
		fmt.Fprintf(w, "Katılan cihaza verilecek etiketler: %s\n", strings.Join(created.Invite.Tags, ", "))
	}
	if created.Invite.MultiUse() {
		fmt.Fprintf(w, "Kod en fazla %d cihaz için kullanılabilir; her cihazı panelde dört haneli kodu karşılaştırarak ayrı ayrı onayla.\n", created.Invite.MaxUses)
		return nil
	}
	fmt.Fprintln(w, "Kod tek kullanımlıktır; katılan cihazı panelde dört haneli kodu karşılaştırarak onayla.")
	return nil
}

// --- helpers ---

// loadDocument parses a read-only command's flags (--dir) and returns the
// owner's current document.
func loadDocument(env *Env, args []string, name string) (*trust.Document, error) {
	fs := newFlagSet(env, name)
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return nil, err
	}
	if *dir == "" {
		return nil, usageError("--dir zorunlu")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return nil, err
	}
	return n.Document()
}

// printTagWarnings lists tag references that match no device (TagUsage).
func printTagWarnings(env *Env, doc *trust.Document) {
	for _, t := range doc.TagUsage() {
		fmt.Fprintf(env.Stdout, "UYARI: tag:%s hiçbir cihazda yok; bu başvuru hiçbir şeyle eşleşmez (yazım hatası olabilir).\n", t)
		printTagSuggestion(env.Stdout, doc, t) // #798
	}
}
