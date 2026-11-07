package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/srvaudit"
	"github.com/openscale/openscale/internal/trust"
)

// G2 commands (ADR-0180..ADR-0184): coordinator hardening options, RAM mode
// seed, port knock, warrant canary, SSH through the tunnel only and
// provider intervention traces.

func init() { registerCommands(g2Commands()...) } // g4_registry.go

func g2Commands() []command {
	return []command{
		{"coordinator harden", "Koordinatör sertleştirme seçenekleri: --spa, --no-metadata, --ram-only, --blind, --clone-quarantine, --emergency-priority (on|off), --show", cmdCoordinatorHarden},
		{"coordinator ram-seed", "RAM kipi için tmpfs durum klasörünü salt okunur tohumdan doldurur: --seed KLASÖR --state-dir KLASÖR", cmdCoordinatorRAMSeed},
		{"coordinator knock", "Koordinatörün gizli UDP portuna tek paket yetkilendirme (SPA) paketi gönderir: --state-dir CİHAZ [--to adres:port]", cmdCoordinatorKnock},
		{"coordinator independence", "Belgedeki koordinatörlerin birbirini denetleyebilecek kadar bağımsız olup olmadığını gösterir: --dir AĞ veya --state-dir CİHAZ", cmdCoordinatorIndependence},
		{"canary sign", "Kök anahtarla tarihli kanarya beyanı imzalar: --dir AĞ --statement-file DOSYA --days 30 --out DOSYA", cmdCanarySign},
		{"canary verify", "Kanarya beyanını sabitlenmiş köke göre doğrular: --file DOSYA (--dir AĞ veya --state-dir CİHAZ)", cmdCanaryVerify},
		{"server ssh-tunnel-only", "sshd'yi yalnızca tünel adresine bağlar (önce erişim doğrulanır, onaylanmazsa geri alınır): [--apply | --confirm | --revert] --state-dir CİHAZ", cmdServerSSHTunnelOnly},
		{"server provider-check", "VPS sağlayıcısı müdahale izlerini raporlar (yeniden başlatma, çekirdek, konsol oturumu, misafir ajanı): [--state DOSYA] [--json]", cmdServerProviderCheck},
	}
}

// onOffFlag is an optional on|off flag.
type onOffFlag struct {
	set   bool
	value bool
}

func (f *onOffFlag) String() string {
	if !f.set {
		return ""
	}
	return onOff(f.value)
}

func (f *onOffFlag) Set(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "açık", "true", "1":
		f.set, f.value = true, true
	case "off", "kapalı", "false", "0":
		f.set, f.value = true, false
	default:
		return errors.New("on veya off olmalı")
	}
	return nil
}

func cmdCoordinatorHarden(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator harden")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu)")
	var spa, noMeta, ram, blind, quarantine, emergency onOffFlag
	fs.Var(&spa, "spa", "UDP portunu ve TCP taşımasını geçerli tek paket yetkilendirmesi görene kadar sessiz tut (#614; eski istemciler bağlanamaz)")
	fs.Var(&noMeta, "no-metadata", "bağlantı meta verisini diske ve günlüğe yazma, bellekte en çok --retention dakika tut (#630)")
	retention := fs.Int("retention", 0, fmt.Sprintf("kayıt tutmama kipinde bellekte tutma süresi, dakika (1-%d; 0: %d)", coordinator.MaxMetadataRetention, coordinator.DefaultMetadataRetention))
	fs.Var(&ram, "ram-only", "durum klasörü tmpfs değilse başlama (#633)")
	fs.Var(&blind, "blind", "politika üyelere mühürlüyse ad/etiket/kural kullanmadan çalış (#629)")
	fs.Var(&quarantine, "clone-quarantine", "aynı anda iki yerde görülen cihaz kimliğine bir saat yanıt verme (#603)")
	fs.Var(&emergency, "emergency-priority", "acil durum (kilit) belgesini öncelikli yay (#681; varsayılan açık)")
	show := fs.Bool("show", false, "yalnızca geçerli seçenekleri göster")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	h, err := coordinator.LoadHardening(*stateDir)
	if err != nil {
		return err
	}
	if !*show {
		changed := false
		apply := func(f onOffFlag, dst *bool, invert bool) {
			if f.set {
				*dst = f.value != invert
				changed = true
			}
		}
		apply(spa, &h.SPA, false)
		apply(noMeta, &h.NoMetadata, false)
		apply(ram, &h.RAMOnly, false)
		apply(blind, &h.Blind, false)
		apply(quarantine, &h.CloneQuarantine, false)
		apply(emergency, &h.NoEmergencyPriority, true)
		if *retention != 0 {
			h.RetentionMinutes, changed = *retention, true
		}
		if !h.NoMetadata {
			h.RetentionMinutes = 0
		}
		if !changed {
			return usageError("değiştirilecek bir seçenek verin veya --show kullanın")
		}
		if err := coordinator.SaveHardening(*stateDir, h); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Sertleştirme dosyası yazıldı; koordinatörü yeniden başlatın (systemctl restart openscale-coordinator).")
		if spa.set && spa.value {
			fmt.Fprintln(env.Stdout, "UYARI: tek paket yetkilendirmesini desteklemeyen eski istemciler bu koordinatöre bağlanamaz; önce bütün cihazları güncelleyin ('network min-version').")
		}
	}
	w := env.Stdout
	fmt.Fprintf(w, "Port gizleme (SPA):        %s\n", onOff(h.SPA))
	fmt.Fprintf(w, "Kayıt tutmama:             %s", onOff(h.NoMetadata))
	if h.NoMetadata {
		fmt.Fprintf(w, " (bellekte en çok %d dakika)", h.Retention())
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Yalnızca RAM:              %s\n", onOff(h.RAMOnly))
	fmt.Fprintf(w, "Kör koordinatör:           %s\n", onOff(h.Blind))
	fmt.Fprintf(w, "Klon karantinası:          %s\n", onOff(h.CloneQuarantine))
	fmt.Fprintf(w, "Acil durum önceliği:       %s\n", onOff(!h.NoEmergencyPriority))
	return nil
}

func cmdCoordinatorRAMSeed(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator ram-seed")
	seed := fs.String("seed", "", "salt okunur tohum klasörü, ör. $CREDENTIALS_DIRECTORY veya /etc/openscale/coordinator-seed (zorunlu)")
	stateDir := fs.String("state-dir", "", "tmpfs üzerindeki durum klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *seed == "" || *stateDir == "" {
		return usageError("--seed ve --state-dir zorunlu")
	}
	copied, err := coordinator.SeedStateDir(*seed, *stateDir)
	if err != nil {
		return err
	}
	if len(copied) == 0 {
		fmt.Fprintln(env.Stdout, "Durum klasörü zaten dolu; hiçbir dosya kopyalanmadı.")
		return nil
	}
	fmt.Fprintf(env.Stdout, "Kopyalandı: %s\n", strings.Join(copied, ", "))
	return nil
}

func cmdCoordinatorKnock(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator knock")
	stateDir := fs.String("state-dir", "", "bu cihazın durum klasörü (zorunlu)")
	to := fs.String("to", "", "koordinatörün UDP adresi (boş: belgedeki birincil koordinatör)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	store, err := member.Open(*stateDir)
	if err != nil {
		return err
	}
	doc := store.Document()
	if doc.Coordinator == nil {
		return errors.New("belgede koordinatör yok")
	}
	target, key := *to, doc.Coordinator.WireGuardKey
	if target == "" {
		target = doc.Coordinator.Endpoint
	}
	packet, err := coordinator.SPAKnock(coordinator.SPAKey(key, doc.NetworkID), env.Now(), env.Random)
	if err != nil {
		return err
	}
	c, err := net.Dial("udp", target)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write(packet); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Yetkilendirme paketi %s adresine gönderildi; kaynak adres %s boyunca açık kalır.\n", target, coordinator.SPAOpen)
	return nil
}

// docAndRoot returns the document and the trusted root of a network
// directory (--dir) or a device state directory (--state-dir).
func docAndRoot(env *Env, dir, stateDir string) (*trust.Document, ed25519.PublicKey, error) {
	switch {
	case dir != "":
		n, err := loadNetwork(env, dir)
		if err != nil {
			return nil, nil, err
		}
		doc, err := n.Document()
		if err != nil {
			return nil, nil, err
		}
		sk, err := readNetworkRootKey(dir)
		if err != nil {
			return nil, nil, err
		}
		return doc, sk.RootPublicKey(), nil
	case stateDir != "":
		store, err := member.Open(stateDir)
		if err != nil {
			return nil, nil, err
		}
		return store.Document(), store.Anchor().RootKey, nil
	}
	return nil, nil, usageError("--dir (ağ klasörü) veya --state-dir (cihaz) verin")
}

func cmdCoordinatorIndependence(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator independence")
	dir := fs.String("dir", "", "ağ klasörü")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	doc, _, err := docAndRoot(env, *dir, *stateDir)
	if err != nil {
		return err
	}
	cs := doc.UsableCoordinators(env.Now())
	fmt.Fprintf(env.Stdout, "Kullanılabilir koordinatör: %d\n", len(cs))
	for _, c := range cs {
		region := c.Region
		if region == "" {
			region = "bölge yok"
		}
		fmt.Fprintf(env.Stdout, "  %s (%s)\n", c.CoordinatorLabel(), region)
	}
	adv := coordinator.IndependenceAdvice(doc, env.Now())
	if len(adv) == 0 {
		fmt.Fprintln(env.Stdout, "Koordinatörler farklı bölgelerde; cihazlar belgeleri birbirine karşı denetleyebilir.")
	}
	for _, a := range adv {
		fmt.Fprintln(env.Stdout, "- "+a.Message)
	}
	return nil
}

func cmdCanarySign(env *Env, args []string) error {
	fs := newFlagSet(env, "canary sign")
	dir := fs.String("dir", "", "ağ klasörü (kök anahtar burada; zorunlu)")
	statementFile := fs.String("statement-file", "", "beyan metni dosyası (UTF-8, en çok 2000 bayt; zorunlu)")
	days := fs.Int("days", 30, "geçerlilik, gün (1-90)")
	out := fs.String("out", "", "imzalı kanarya dosyası (zorunlu)")
	passFile := fs.String("passphrase-file", "", "kök anahtar parolasını bu dosyadan oku")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || *statementFile == "" || *out == "" {
		return usageError("--dir, --statement-file ve --out zorunlu")
	}
	if *days < 1 || *days > 90 {
		return usageError("--days 1 ile 90 arasında olmalı")
	}
	statement, err := securefile.ReadLimited(*statementFile, coordinator.MaxCanaryStatement)
	if err != nil {
		return fmt.Errorf("beyan dosyası: %w", err)
	}
	n, err := loadNetwork(env, *dir)
	if err != nil {
		return err
	}
	doc, err := n.Document()
	if err != nil {
		return err
	}
	sk, err := readNetworkRootKey(*dir)
	if err != nil {
		return fmt.Errorf("%w (kök anahtar donanım jetonundaysa kanarya henüz imzalanamaz)", err)
	}
	pass, err := secretFromFileOrTerminal(env, *passFile, "Kök anahtar parolası: ", "--passphrase-file")
	if err != nil {
		return err
	}
	defer clear(pass)
	root, err := sk.Open(pass)
	if err != nil {
		return err
	}
	defer clear(root)
	now := env.Now().UTC().Truncate(time.Second)
	// The sequence is the issue time: always increasing, no state needed.
	c := coordinator.Canary{NetworkID: doc.NetworkID, Seq: uint64(now.Unix()), IssuedAt: now, //nolint:gosec // after 1970
		NotAfter: now.Add(time.Duration(*days) * 24 * time.Hour), Statement: strings.TrimSpace(strings.ReplaceAll(string(statement), "\r\n", "\n"))}
	data, err := coordinator.SignCanary(root, c)
	if err != nil {
		return err
	}
	if err := securefile.Replace(*out, data); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Kanarya imzalandı: %s (geçerli: %s'e kadar).\n", *out, c.NotAfter.Format("2006-01-02"))
	fmt.Fprintln(env.Stdout, "Koordinatöre yüklemek için cihaz servisi kullanılır; koordinatör kanaryayı değiştiremez, yalnızca saklar.")
	return nil
}

func cmdCanaryVerify(env *Env, args []string) error {
	fs := newFlagSet(env, "canary verify")
	file := fs.String("file", "", "kanarya dosyası (zorunlu)")
	dir := fs.String("dir", "", "ağ klasörü")
	stateDir := fs.String("state-dir", "", "cihazın durum klasörü")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *file == "" {
		return usageError("--file zorunlu")
	}
	data, err := securefile.ReadLimited(*file, 128<<10)
	if err != nil {
		return err
	}
	doc, root, err := docAndRoot(env, *dir, *stateDir)
	if err != nil {
		return err
	}
	c, st, err := coordinator.OpenCanary(data, root, doc.NetworkID, env.Now())
	fmt.Fprintln(env.Stdout, st.Label())
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Tarih: %s  Son geçerlilik: %s  Sıra: %d\n\n%s\n", c.IssuedAt.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.Seq, c.Statement)
	if st == coordinator.CanaryExpired {
		return errors.New("kanarya süresi dolmuş")
	}
	return nil
}

// sshSystem is replaced in tests.
var sshSystem = srvaudit.HostSSHSystem

func cmdServerSSHTunnelOnly(env *Env, args []string) error {
	fs := newFlagSet(env, "server ssh-tunnel-only")
	stateDir := fs.String("state-dir", "/var/lib/openscale/device", "bu sunucunun cihaz durum klasörü (tünel aralığı imzalı belgeden okunur)")
	apply := fs.Bool("apply", false, "değişikliği uygula (yoksa yalnızca planı gösterir)")
	confirm := fs.Bool("confirm", false, "tünelden açılan YENİ oturumdan değişikliği onayla (geri alma zamanlayıcısını durdurur)")
	revert := fs.Bool("revert", false, "değişikliği geri al")
	rollback := fs.Duration("rollback", srvaudit.DefaultSSHRollback, "onay gelmezse eski ayara dönme süresi (30s-30m)")
	console := fs.Bool("i-have-console", false, "SSH dışında (seri/VNC konsolda) çalıştığımı biliyorum; tünel oturumu şartını atla")
	root := fs.String("root", "/", "denetlenen kök (testler)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if n := countTrue(*apply, *confirm, *revert); n > 1 {
		return usageError("--apply, --confirm ve --revert birlikte kullanılamaz")
	}
	sys, err := sshSystem()
	if err != nil {
		return err
	}
	ctx := envContext(env)
	fsys := os.DirFS(*root)
	if *revert {
		if err := srvaudit.RevertSSHTunnelOnly(ctx, sys, fsys); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "sshd eski ayarına döndü.")
		return nil
	}
	tunnel, err := tunnelPrefixes(*stateDir)
	if err != nil {
		return err
	}
	if *confirm {
		if err := srvaudit.ConfirmSSHTunnelOnly(ctx, sys, tunnel); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Onaylandı: sshd artık yalnızca tünelden erişilebilir.")
		return nil
	}
	p := srvaudit.PlanSSHTunnelOnly(fsys, sys, tunnel, *console)
	printSSHPlan(env, p)
	if !*apply {
		if p.Ready() {
			fmt.Fprintln(env.Stdout, "Uygulamak için --apply ekleyin.")
		}
		return nil
	}
	if !p.Ready() {
		return errors.New("engeller giderilmeden uygulanmadı")
	}
	if err := srvaudit.ApplySSHTunnelOnly(ctx, sys, p, *rollback); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "sshd yalnızca tünelde dinliyor. %s içinde tünelden YENİ bir SSH oturumu açıp şunu çalıştırın:\n  openscale server ssh-tunnel-only --confirm\nOnay gelmezse eski ayar kendiliğinden geri yüklenir.\n", *rollback)
	return nil
}

func countTrue(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

func printSSHPlan(env *Env, p srvaudit.SSHTunnelPlan) {
	w := env.Stdout
	if len(p.Public) > 0 {
		fmt.Fprintf(w, "sshd şu an genel adreslerde dinliyor: %s\n", strings.Join(p.Public, ", "))
	}
	if len(p.Addrs) > 0 {
		var as []string
		for _, a := range p.Addrs {
			as = append(as, a.String())
		}
		fmt.Fprintf(w, "Yeni dinleme adresleri (port %d): %s\n", p.Port, strings.Join(as, ", "))
	}
	for _, b := range p.Blockers {
		fmt.Fprintln(w, "ENGEL: "+b)
	}
	for _, x := range p.Warnings {
		fmt.Fprintln(w, "UYARI: "+x)
	}
}

// tunnelPrefixes reads the network's address ranges from the device's
// verified document.
func tunnelPrefixes(stateDir string) ([]netip.Prefix, error) {
	store, err := member.Open(stateDir)
	if err != nil {
		return nil, fmt.Errorf("cihaz belgesi okunamadı (--state-dir): %w", err)
	}
	doc := store.Document()
	var out []netip.Prefix
	for _, p := range []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix} {
		if p.IsValid() {
			out = append(out, p.Masked())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("belgede tünel adres aralığı yok")
	}
	return out, nil
}

// DefaultProviderState is where provider-check keeps the last boot.
const DefaultProviderState = "/var/lib/openscale/provider-trace.json"

func cmdServerProviderCheck(env *Env, args []string) error {
	flags := newFlagSet(env, "server provider-check")
	state := flags.String("state", DefaultProviderState, "önceki açılışın kaydı")
	noSave := flags.Bool("no-save", false, "bu açılışı kaydetme")
	asJSON := flags.Bool("json", false, "JSON çıktı")
	root := flags.String("root", "/", "denetlenen kök (testler)")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	fsys := os.DirFS(*root)
	var prev *srvaudit.BootState
	if data, err := securefile.ReadLimited(*state, 64<<10); err == nil {
		if prev, err = srvaudit.ParseBootState(data); err != nil {
			return fmt.Errorf("önceki kayıt bozuk (%s): %w", *state, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	cur := srvaudit.CurrentBoot(fsys, env.Now())
	events := srvaudit.ProviderTraces(fsys, prev, cur)
	if !*noSave {
		if err := saveBootState(*state, cur); err != nil {
			return err
		}
	}
	if *asJSON {
		return writeJSON(env.Stdout, events)
	}
	for _, e := range events {
		label := map[string]string{"info": "BİLGİ", "warning": "UYARI", "critical": "ÖNEMLİ"}[e.Severity]
		fmt.Fprintf(env.Stdout, "%-7s %s\n", label, e.Message)
	}
	fmt.Fprintln(env.Stdout, "Not: tam denetimi olan bir sağlayıcı izleri silebilir; temiz sonuç kanıt değildir (ADR-0109).")
	return nil
}

func saveBootState(path string, s srvaudit.BootState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(path, data)
}
