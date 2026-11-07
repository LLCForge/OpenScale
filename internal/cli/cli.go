// Package cli implements the openscale command line. Output is Turkish;
// every command that changes the network re-signs the document with the
// owner's root key.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

// Version is the program version (internal/version, set by the release
// build).
var Version = version.String()

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Env carries every side effect so commands can be tested.
type Env struct {
	// Ctx is cancelled on Ctrl+C; long-running commands stop on it.
	Ctx    context.Context
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time
	Random io.Reader
	// ReadSecret reads a line without echo from the terminal.
	ReadSecret func(prompt string) ([]byte, error)
	// ReadLine reads a visible line from the terminal.
	ReadLine   func(prompt string) (string, error)
	IsTerminal func() bool
	Hostname   func() (string, error)
	// DefaultStateDir returns the per-user device state directory.
	DefaultStateDir func() (string, error)
	Argon2          trust.Argon2Params
}

type command struct {
	name    string
	summary string
	run     func(*Env, []string) error
}

func commands() []command {
	return append(append([]command{
		{"network init", "Yeni ağ ve kök anahtar oluşturur", cmdNetworkInit},
		{"network show", "Ağ belgesini doğrular ve gösterir", cmdNetworkShow},
		{"network renew", "Ağ belgesinin geçerlilik süresini yeniler", cmdNetworkRenew},
		{"network backup", "Kök anahtarın ayrı parolalı yedeğini alır", cmdNetworkBackup},
		{"network restore", "Kök anahtarı yedekten geri yükler", cmdNetworkRestore},
		{"network passphrase", "Kök anahtar parolasını değiştirir", cmdNetworkPassphrase},
		{"network verify", "Belge geçmişinin tamamını doğrular", cmdNetworkVerify},
		{"network set-coordinator", "Koordinatörü ağ belgesine kaydeder", cmdNetworkSetCoordinator},
		{"bundle", "Yeni üyeler için katılım paketi üretir", cmdBundle},
		{"join", "Katılım paketiyle bu cihazı veya sunucuyu ağa bağlar", cmdJoin},
		{"invite-join", "Davet koduyla bu bilgisayarı ağa katar (sunucular için)", cmdInviteJoin},
		{"up", "Tüneli açar (yönetici/root gerekir)", cmdUp},
		{"coordinator keygen", "Koordinatör anahtarını üretir", cmdCoordinatorKeygen},
		{"coordinator run", "Koordinatörü çalıştırır", cmdCoordinatorRun},
		{"keygen", "Bu cihaz için anahtar ve kayıt isteği üretir", cmdKeygen},
		{"device add", "Kayıt isteğini doğrulayıp cihazı ağa ekler", cmdDeviceAdd},
		{"device revoke", "Cihazı ağdan kalıcı olarak çıkarır", cmdDeviceRevoke},
		{"device extend", "Cihaz üyeliğini bugünden itibaren uzatır", cmdDeviceExtend},
		{"device expire", "Cihaz üyeliğini hemen bitirir (iptal etmeden)", cmdDeviceExpire},
		{"device rename", "Cihazı ve ona yapılan bütün başvuruları yeniden adlandırır", cmdDeviceRename},
		{"device tag", "Cihazın etiketlerini belirler", cmdDeviceTag},
		{"device rotate-key", "Bu cihaz için anahtar yenileme isteği üretir (cihazda)", cmdDeviceRotateKey},
		{"device approve-rotation", "Cihazın anahtar yenileme isteğini parmak iziyle onaylar", cmdDeviceApproveRotation},
		{"group set", "Grup oluşturur veya üyelerini değiştirir", cmdGroupSet},
		{"group rm", "Kullanılmayan bir grubu siler", cmdGroupRemove},
		{"group list", "Grupları listeler", cmdGroupList},
		{"rule add", "Cihazlar arası erişim kuralı (izin veya reddet) ekler", cmdRuleAdd},
		{"rule remove", "Numarasıyla bir erişim kuralını siler", cmdRuleRemove},
		{"rule disable", "Kuralı silmeden devre dışı bırakır", cmdRuleDisable},
		{"rule enable", "Devre dışı kuralı yeniden etkinleştirir", cmdRuleEnable},
		{"exit users set", "Çıkış düğümünü kullanabilecek cihazları sınırlar", cmdExitUsersSet},
		{"exit users clear", "Çıkış düğümü kısıtlamasını kaldırır (herkes kullanabilir)", cmdExitUsersClear},
		{"exit users show", "Çıkış düğümünü kimlerin kullanabileceğini gösterir", cmdExitUsersShow},
		{"exit chain", "İmzalı çift sıçramalı çıkış: set --entry <giriş> --final <son> | clear --entry <giriş> | show", cmdExitChain}, // #618
		{"network dns set", "Ağ geneli DNS çözücülerini ve split DNS'i belirler", cmdNetworkDNSSet},
		{"network dns clear", "Ağ DNS ayarlarını kaldırır", cmdNetworkDNSClear},
		{"network dns show", "Ağ DNS ayarlarını gösterir", cmdNetworkDNSShow},
		{"network dns profile set", "Cihaz/etiket/grup için çıkış DNS süzgeç profili tanımlar: <ad> --members ... [--safe-search] [--no-blocklist]", cmdNetworkDNSProfileSet},
		{"network dns profile rm", "DNS süzgeç profilini siler: <ad>", cmdNetworkDNSProfileRemove},
		{"network dns profile list", "DNS süzgeç profillerini gösterir", cmdNetworkDNSProfileList},
		{"network dns search", "Kısa adlara eklenecek arama alanlarını belirler", cmdNetworkDNSSearch},
		{"network dns subdomains", "Cihaz alt alanlarını (*.cihaz.alan) açar veya kapatır: --state on|off", cmdNetworkDNSSubdomains},
		{"network dns record add", "Ağ alanına DNS kaydı ekler (A, AAAA, CNAME, SRV, TXT)", cmdNetworkDNSRecordAdd},
		{"network dns record rm", "Ağ alanından DNS kaydı siler", cmdNetworkDNSRecordRemove},
		{"device alias", "Cihazın ek MagicDNS adlarını belirler", cmdDeviceAlias},
		{"network name set", "Ağın görünen adını belirler veya kaldırır", cmdNetworkNameSet},
		{"invite create", "Davet kodu oluşturur (isteğe bağlı etiketlerle)", cmdInviteCreate},
		// "panel readonly" must come before "panel", which matches first.
		{"panel readonly", "Masaüstü panelini salt okunur yapar veya açar: on|off|status (yönetici gerekir)", cmdPanelReadOnly},
		{"panel", "Yönetim panelini yerel olarak açar", cmdPanel},
		{"app", "Masaüstü uygulamasını açar: servis, tepsi/menü çubuğu simgesi ve panel (Windows, macOS, Linux)", cmdApp},
		{"service run", "Servis olarak çalışır (Windows servis yöneticisi, macOS launchd veya Linux openscale-app.service başlatır)", cmdServiceRun},
		{"service uninstall", "Servisi kaldırır (Windows: kill switch ve güvenlik duvarı kurallarıyla; Linux: --role birimi)", cmdServiceUninstall},
		{"killswitch off", "Kalıcı kill switch filtrelerini servissiz kaldırır (yönetici gerekir)", cmdKillSwitchOff},
		{"killswitch status", "Kalıcı kill switch filtrelerinin kurulu olup olmadığını gösterir", cmdKillSwitchStatus},
		{"killswitch restore", "Kayıtlı kill switch'i geri yükler (Linux açılış birimi çalıştırır; root gerekir)", cmdKillSwitchRestore},
		{"killswitch boot", "Kill switch'in açılışta ağdan önce geri yüklenmesi: on|off|status (Linux, systemd)", cmdKillSwitchBoot},
		{"killswitch captive", "Otel/havaalanı giriş sayfası için ağ geçidine kısa süreli HTTP/HTTPS izni [--sure 5m] [--off]", cmdKillSwitchCaptive},
		{"exit-node test", "Çıkış düğümü sızıntı testi: görünen IP, DNS, IPv6 ve WebRTC (yalnızca kendi koordinatörüne sorar)", cmdExitNodeTest},
		{"ssh", "Bir cihaza tünel içinden gömülü SSH ile bağlanır: [kullanıcı@]<cihaz> [komut]", cmdSSH},
		{"send", "Bir cihaza dosya gönderir: <dosya> <cihaz>", cmdSend},
		{"wake", "Uyuyan bir cihazı aynı LAN'daki aracı cihaz üzerinden uyandırır (Wake-on-LAN)", cmdWake},
		{"speedtest", "Bir cihazla tünel içi hız testi yapar: <cihaz> [--upload] [--sure 5s]", cmdSpeedtest},
		{"rdesk", "Uzak ekranın görüntüsünü alır (yalnızca izleme): <cihaz> --snapshot dosya.png [--monitor primary|all|N]", cmdRemoteDesktop},
		{"rdesk-helper", "Uzak masaüstü yardımcısı; Windows servisi tarafından kullanıcı oturumunda başlatılır (elle çalıştırılmaz)", cmdRDeskHelper},
		{"rdesk-stats", "Uzak oturum kalitesi: kare hızı, gecikme, bant genişliği, yol türü: <cihaz> [--duration 30s]", cmdRDeskStats},
		{"rdesk-files", "Uzak oturumdan dosya gezgini: <cihaz> [--path kök/alt] | --get kök/dosya --out dosya (files kuralı gerekir)", cmdRDeskFiles},
		{"rdesk-help", "Uzaktan yardım ister: bu cihazı kontrol izni olan cihazlara bildirim gönderir [--to cihaz] [--note metin]", cmdRDeskHelp},
		{"threats", "Tarama/tuzak algılamalarını ve engellenen cihazları gösterir: [unblock <cihaz>]", cmdThreats},
		{"exit-dns", "Çıkış çözücüsü: status | allow <ad> [--for 15m] | revoke <ad> | log on [--for 1h]|off|show", cmdExitDNS},
		{"files", "Gelen dosyalar: list | accept <no> | reject <no> | delete <ad> | auto <cihaz> on|off", cmdFiles},
		{"sync", "Klasör eşitleme ve kaynakta şifreli yedek: serve | pull | versions | backup | snapshots | restore | prune | key", cmdSync},
		// "key hw ..." must come before "key", which matches first (p22.go).
		{"key hw import", "Kök anahtarın bir kopyasını PIV donanım jetonuna aktarır (YubiKey 5.7+, Windows; donanımda denenmedi)", cmdKeyHWImport},
		{"key hw status", "PIV jetonunun sürümünü ve yuvadaki Ed25519 anahtarını gösterir (salt okuma)", cmdKeyHWStatus},
		{"key token", "Donanım jetonu, PIV/OpenPGP otomatik: status|import|sign|approve|session (G1, g1_cli_token.go)", cmdG1KeyToken},
		{"key", "Anahtar ve kripto: status|protect|unprotect|kdf-upgrade|strength|paper-backup|paper-restore|request|sas|log-decrypt|selftest", cmdKey},
	}, append(append(append(append(append(diagCommands(), p28Commands()...), privacyCommands()...), p06Commands()...), p16Commands()...), append(append(append(observeCommands(), p14Commands()...), p08Commands()...), append(append(append(p29Commands(), p17Commands()...), p09Commands()...), append(append(append(append(p15Commands(), p10Commands()...), append(upstreamCommands(), p04Commands()...)...), p18Commands()...), append(append(p22Commands(), serverOpsCommands()...), append(append(p11EdgeCommands(), p02Commands()...), p10PlatformCommands()...)...)...)...)...)...)...), append(p12Commands(), registeredCommands()...)...) // P12: p12.go; init() registry: g4_registry.go
}

// Run executes the command line and returns the process exit code.
func Run(args []string, env *Env) int {
	// Template output (#552, p12.go): the command runs with --json and each
	// JSON value it writes is rendered with the template.
	if tmpl, rest, found, ferr := extractFormat(args); found {
		if ferr != nil {
			fmt.Fprintf(env.Stderr, "hata: %v\n", ferr)
			return exitUsage
		}
		return runFormatted(env, rest, tmpl)
	}
	// Global network profile selection (F-109, p28.go, ADR-0135).
	args, env, perr := selectNetwork(args, env)
	if perr != nil {
		fmt.Fprintf(env.Stderr, "hata: %v\n", perr)
		return exitUsage
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage(env.Stdout)
		return exitOK
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) > 1 && (args[1] == "--json" || args[1] == "-json") {
			fmt.Fprintf(env.Stdout, "{\"schema\":1,\"version\":%q}\n", Version)
			return exitOK
		}
		fmt.Fprintf(env.Stdout, "openscale %s\n", versionText()) // beta label: g4_version.go
		return exitOK
	}
	for _, c := range commands() {
		parts := strings.Fields(c.name)
		if len(args) < len(parts) || strings.Join(args[:len(parts)], " ") != c.name {
			continue
		}
		err := c.run(env, args[len(parts):])
		switch {
		case err == nil:
			return exitOK
		case errors.Is(err, flag.ErrHelp):
			return exitOK
		case errors.As(err, new(exitCodeError)):
			// A remote command's own exit status (openscale ssh).
			var ec exitCodeError
			errors.As(err, &ec)
			return ec.code
		case errors.Is(err, errUsage):
			fmt.Fprintf(env.Stderr, "hata: %v\n", err)
			return exitUsage
		default:
			fmt.Fprintf(env.Stderr, "hata: %s\n", describe(err))
			// Stable error code (#550, ADR-0165, p12.go).
			if line := errorCodeLine(err); line != "" {
				fmt.Fprintln(env.Stderr, line)
			}
			return exitError
		}
	}
	fmt.Fprintf(env.Stderr, "hata: bilinmeyen komut %q\n\n", strings.Join(args, " "))
	printUsage(env.Stderr)
	return exitUsage
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "OpenScale: kişisel, bağımsız ve gizlilik öncelikli mesh VPN")
	fmt.Fprintln(w, "\nKullanım:\n  openscale <komut> [seçenekler]\n\nKomutlar:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-26s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "  version                    Sürümü gösterir")
	fmt.Fprintln(w, "\nBir komutun seçenekleri için: openscale <komut> -h")
}

var errUsage = errors.New("kullanım hatası")

func usageError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

func newFlagSet(env *Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet("openscale "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError("%v", err)
	}
	if fs.NArg() > 0 {
		return usageError("beklenmeyen argüman %q", fs.Arg(0))
	}
	return nil
}

func daysFlag(days int, minimum, maximum int, name string) (time.Duration, error) {
	if days < minimum || days > maximum {
		return 0, usageError("--%s %d ile %d gün arasında olmalı", name, minimum, maximum)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// describe turns well-known errors into Turkish messages.
func describe(err error) string {
	if msg, ok := describeNetError(err); ok {
		return msg
	}
	if errors.Is(err, os.ErrNotExist) {
		return "dosya bulunamadı: " + err.Error()
	}
	if hint := errorHint(err); hint != "" {
		return admin.Describe(err) + "\n" + hint
	}
	return admin.Describe(err)
}
