package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

const maxRequestFile = 16 * 1024

func cmdKeygen(env *Env, args []string) error {
	fs := newFlagSet(env, "keygen")
	stateDir := fs.String("state-dir", "", "cihaz anahtarlarının klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	hostname := fs.String("hostname", "", "önerilen cihaz adı (varsayılan: bilgisayar adı)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	dir := *stateDir
	if dir == "" {
		d, err := env.DefaultStateDir()
		if err != nil {
			return fmt.Errorf("varsayılan klasör bulunamadı, --state-dir kullan: %w", err)
		}
		dir = d
	}
	name := *hostname
	if name == "" {
		if h, err := env.Hostname(); err == nil {
			name = h
		}
	}

	secrets, created, err := loadOrCreateDeviceSecrets(env, filepath.Join(dir, "device.key"))
	if err != nil {
		return err
	}
	envl, req, err := secrets.NewEnrollmentRequest(name, env.Now())
	if err != nil {
		return err
	}
	line, err := trust.EncodeEnrollment(envl)
	if err != nil {
		return err
	}

	w := env.Stdout
	if created {
		fmt.Fprintf(w, "Cihaz anahtarları oluşturuldu: %s\n", filepath.Join(dir, "device.key"))
	} else {
		fmt.Fprintln(w, "Mevcut cihaz anahtarları kullanıldı.")
	}
	fmt.Fprintln(w, "\nKayıt isteği (yönetici cihazda panele veya 'openscale device add --request ...' komutuna ver):")
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "\nParmak izi: %s\n", req.Fingerprint())
	fmt.Fprintln(w, "Yönetici cihazda bu parmak izini yazman istenecek; eşleşmezse cihaz eklenmez.")
	fmt.Fprintf(w, "İstek %d saat geçerlidir. Özel anahtarlar bu cihazdan hiç çıkmaz.\n", int(trust.EnrollmentMaxAge.Hours()))
	return nil
}

func loadOrCreateDeviceSecrets(env *Env, path string) (*trust.DeviceSecrets, bool, error) {
	data, err := securefile.ReadPrivate(path, trust.MaxDeviceKeySize)
	if err == nil {
		s, err := trust.UnmarshalDeviceSecrets(data)
		wipe(data)
		return s, false, err
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("cihaz anahtarı okunamadı: %w", err)
	}
	s, err := trust.GenerateDeviceSecrets(env.Random, env.Now())
	if err != nil {
		return nil, false, err
	}
	encoded, err := trust.MarshalDeviceSecrets(s)
	if err != nil {
		return nil, false, err
	}
	defer wipe(encoded)
	if err := securefile.WriteNew(path, encoded); err != nil {
		return nil, false, fmt.Errorf("cihaz anahtarı yazılamadı: %w", err)
	}
	return s, true, nil
}

func cmdDeviceAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "device add")
	common := addEditFlags(fs)
	request := fs.String("request", "", "kayıt isteği satırı veya @dosya (zorunlu; --request-image verilmediyse)")
	requestImage := fs.String("request-image", "", "telefonun gösterdiği kayıt isteği QR kodunun fotoğrafı veya ekran görüntüsü (PNG/JPEG)")
	name := fs.String("name", "", "cihaz adı (varsayılan: istekteki bilgisayar adı)")
	fingerprint := fs.String("fingerprint", "", "yeni cihazda görünen parmak izi (terminal yoksa zorunlu)")
	exitNode := fs.Bool("exit-node", false, "cihaz çıkış düğümü olabilsin")
	lifetimeDays := fs.Int("lifetime", int(trust.DefaultDeviceLife.Hours()/24), "cihaz üyeliğinin süresi (gün)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *request != "" && *requestImage != "" {
		return usageError("--request ve --request-image birlikte verilemez")
	}
	if *common.dir == "" || (*request == "" && *requestImage == "") {
		return usageError("--dir ve --request (veya --request-image) zorunlu")
	}
	lifetime, err := daysFlag(*lifetimeDays, 1, 3650, "lifetime")
	if err != nil {
		return err
	}
	line := *request
	if *requestImage != "" {
		if line, err = readQRImage(*requestImage); err != nil {
			return err
		}
	}
	// SECURITY FIX: CWE-73 only the owner's own flag may name a file; text
	// read from a QR code starting with "@" is not a path.
	if *requestImage == "" && strings.HasPrefix(line, "@") {
		data, err := securefile.ReadLimited(strings.TrimPrefix(line, "@"), maxRequestFile)
		if err != nil {
			return fmt.Errorf("istek dosyası okunamadı: %w", err)
		}
		line = string(data)
	}

	n, err := admin.Load(*common.dir, env.adminOptions())
	if err != nil {
		return err
	}
	pending, err := n.InspectRequest(line, env.Now())
	if err != nil {
		return err
	}
	deviceName := *name
	if deviceName == "" {
		deviceName = pending.Request.Hostname
	}
	if deviceName == "" {
		return usageError("istekte bilgisayar adı yok; --name ver")
	}
	fmt.Fprintf(env.Stdout, "Eklenecek cihaz: %s\n", deviceName)

	// The owner types the fingerprint shown on the new device; the
	// expected value is not printed here, so it cannot just be copied.
	typed := *fingerprint
	if typed == "" {
		if !env.IsTerminal() {
			return usageError("terminal yok; yeni cihazdaki parmak izini --fingerprint ile ver")
		}
		if typed, err = env.ReadLine("Yeni cihazda görünen parmak izini yaz: "); err != nil {
			return err
		}
	}
	if err := pending.ConfirmFingerprint(typed); err != nil {
		return err
	}

	var roles []trust.Role
	if *exitNode {
		roles = append(roles, trust.RoleExitNode)
	}
	return runEdit(env, common, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, deviceName, roles, env.Now(), lifetime)
		return err
	})
}

func cmdDeviceRevoke(env *Env, args []string) error {
	fs := newFlagSet(env, "device revoke")
	common := addEditFlags(fs)
	name := fs.String("name", "", "iptal edilecek cihaz (zorunlu)")
	confirm := fs.String("confirm", "", "betikler için açık onay: cihazın adı (--yes yerine; iptal geri alınamaz)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageError("--name zorunlu")
	}
	if !*common.dryRun {
		// Revocation is permanent (F-134): the owner names the device.
		if err := confirmCritical(env, *confirm, *name, *name+" kalıcı olarak iptal edilecek ve geri alınamaz"); err != nil {
			return err
		}
	}
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error {
		_, err := doc.RevokeDevice(*name, env.Now())
		return err
	}, *name))
}

func cmdRuleAdd(env *Env, args []string) error {
	fs := newFlagSet(env, "rule add")
	common := addEditFlags(fs)
	from := fs.String("from", "", "kaynaklar: cihaz adları, tag:<etiket>, group:<grup> (virgülle) veya * (zorunlu)")
	to := fs.String("to", "", "hedefler: cihaz adları, tag:<etiket>, group:<grup> (virgülle) veya * (zorunlu)")
	proto := fs.String("proto", "tcp", "protokol: tcp, udp, icmp, any veya IANA numarası 0-255 (ör. 47 GRE, 50 ESP)")
	ports := fs.String("ports", "", "portlar, ör. 3389 veya 5900-5910,22 (tcp/udp için zorunlu)")
	action := fs.String("action", "allow", "allow (izin) veya deny (reddet); reddet kuralı her zaman izinden önce gelir")
	description := fs.String("description", "", "kısa açıklama")
	svc := fs.String("service", "", "servis kuralı: ssh, files, wake, speedtest, rdesk, sync, panel, serve (tünel içi yayın, ADR-0139) veya cert (iç CA, ADR-0138) (--proto ve --ports yerine)")
	users := fs.String("users", "", "ssh: izinli yerel kullanıcılar (virgülle; Windows cihazlar için system)")
	allowRoot := fs.Bool("allow-root", false, "ssh: root (uid 0) girişine ayrıca izin ver")
	allowForward := fs.Bool("allow-forward", false, "ssh: yerel port yönlendirmeye (ssh -L) izin ver")
	via := fs.String("via", "", "wake: hedefin LAN'ındaki aracı cihazlar (virgülle; zorunlu)")
	confirm := fs.String("confirm", "", "herkesten herkese geniş izin kuralı için betiklerde açık onay: "+wideRuleWord)
	ext := addRuleExtFlags(fs)  // ADR-0120 (p09.go)
	w2 := addRuleWave2Flags(fs) // rdesk and sync fields (rule_wave2.go, ADR-0110)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return usageError("--from ve --to zorunlu")
	}
	act, err := parseRuleAction(*action)
	if err != nil {
		return err
	}
	rule := trust.Rule{
		From:        splitList(*from),
		To:          splitList(*to),
		Protocol:    trust.Protocol(strings.ToLower(strings.TrimSpace(*proto))),
		Ports:       splitList(*ports),
		Description: *description,
		Action:      act,
	}
	if s := strings.ToLower(strings.TrimSpace(*svc)); s != "" {
		if *ports != "" {
			return usageError("--service ile --ports yazılmaz; servis kendi portunu kullanır")
		}
		rule.Service, rule.Protocol, rule.Ports = trust.RuleService(s), "", nil
		rule.Users, rule.AllowRoot, rule.AllowForward, rule.Via = splitList(*users), *allowRoot, *allowForward, splitList(*via)
		if rule.Service == trust.ServiceSSH && (rule.AllowRoot || slices.Contains(rule.Users, trust.SSHWindowsUser)) {
			fmt.Fprintln(env.Stderr, "uyarı: root veya system hesabı cihazda tam yetki verir.")
		}
		if err := w2.apply(env, &rule); err != nil {
			return err
		}
		if err := ext.apply(env, &rule, env.Now()); err != nil {
			return err
		}
		return runEdit(env, common, suggestingChange(func(doc *trust.Document) error { return doc.AddRule(rule) }, slices.Concat(rule.From, rule.To, rule.Via)...))
	}
	if *users != "" || *allowRoot || *allowForward || *via != "" || w2.used() {
		return usageError("--users, --allow-root, --allow-forward, --via, --allow-control, --allow-unattended, --folders, --backup, --quota ve --allow-prune yalnızca --service ile kullanılır")
	}
	if n, ok := trust.ProtocolNumber(rule.Protocol); ok && (n == 1 || n == 6 || n == 17 || n == 58) {
		return usageError("protokol %d adıyla yazılmalı: tcp, udp veya icmp", n)
	}
	if err := ext.apply(env, &rule, env.Now()); err != nil {
		return err
	}
	if wideRule(rule) && !*common.dryRun {
		if err := confirmCritical(env, *confirm, wideRuleWord, "Bu kural bütün cihazlardan bütün cihazlara erişim açar"); err != nil {
			return err
		}
	}
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error { return doc.AddRule(rule) }, slices.Concat(rule.From, rule.To, rule.Via)...))
}

func cmdRuleRemove(env *Env, args []string) error {
	fs := newFlagSet(env, "rule remove")
	common := addEditFlags(fs)
	number := fs.String("number", "", "silinecek kuralın numarası ('network show' çıktısındaki) (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	idx, err := strconv.Atoi(*number)
	if err != nil || idx < 1 {
		return usageError("--number 1 veya daha büyük bir sayı olmalı")
	}
	return runEdit(env, common, func(doc *trust.Document) error {
		_, err := doc.RemoveRule(idx - 1)
		return err
	})
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
