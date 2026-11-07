package cli

import (
	"fmt"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/openscale/openscale/internal/winapp"
)

// "openscale commands" lists which commands work on which system and the
// equivalent where one is missing (CLI parity, ADR-0195 section 9). The
// table is the reviewed list of platform-specific commands; every command
// not in it runs the same way on Windows, Linux and macOS.

func init() {
	registerCommands(
		command{"commands", "Komutların Windows, Linux ve macOS desteğini ve eksik olanların karşılığını listeler [--json]", cmdCommandsPlatform},
		command{"discreet", "Göze çarpmayan ad kipi: on [--name ad] | off | status (tepsi, pencere, servis görünen adı)", cmdDiscreet},
	)
}

// platformSupport is one platform-specific command.
type platformSupport struct {
	Command string `json:"command"`
	Windows string `json:"windows"`
	Linux   string `json:"linux"`
	MacOS   string `json:"macos"`
	// Note is the equivalent or the reason (Turkish).
	Note string `json:"note"`
}

const (
	supYes = "var"
	supNo  = "yok"
	supAlt = "karşılığı var"
)

// platformCommands is the reviewed list.
var platformCommands = []platformSupport{
	{"app", supYes, supYes, supYes, "macOS: menü çubuğu uygulaması (ADR-0227); Linux: StatusNotifierItem tepsisi ve openscale-app.service (ADR-0234)"},
	{"tray", supYes, supYes, supYes, "Yalnızca tepsi/menü çubuğu simgesi, pencere açmadan; Linux'ta oturum D-Bus'ı gerekir"},
	{"app install-service/restart-service/uninstall-service", supNo, supYes, supYes, "Windows: app servisi kendisi kurar; Linux: openscale-app.service (pkexec ile tepsi çalıştırır)"},
	{"window", supYes, supYes, supYes, "cgo'suz derlemede veya grafik oturumu yoksa tarayıcıya düşer"},
	{"service run", supYes, supYes, supYes, "macOS: com.openscale.service; Linux: openscale-app.service (uygulama servisi); komut satırı birimi 'up --config /etc/openscale/device.json' çalıştırır"},
	{"service install/start/stop/status/uninstall", supYes, supYes, supYes, "Windows servis, systemd, launchd"},
	{"autostart on/off/status", supYes, supYes, supYes, "Run kaydı, XDG autostart, LaunchAgent"},
	{"killswitch boot", supAlt, supYes, supNo, "Windows: kalıcı WFP filtresi açılışta zaten geçerli; macOS: pf açılış kuralı yazılmadı"},
	{"killswitch restore", supAlt, supYes, supYes, "Windows: servis açılışta kendisi geri yükler"},
	{"split-tunnel run/off", supNo, supYes, supNo, "uygulama bazlı tünel yalnızca Linux cgroup ile; Windows/macOS için ayrı tasarım gerekir"},
	{"portable", supYes, supNo, supNo, "Linux/macOS: 'openscale up' zaten servissiz geçici tünel açar"},
	{"rdesk-helper", supYes, supNo, supNo, "Windows servisinin kullanıcı oturumu yardımcısı; Linux 'up --rdesk' süreç içinde çalışır"},
	{"key protect/unprotect", supYes, supNo, supNo, "Windows DPAPI; Linux/macOS dosya izinleri (0600) ve parola"},
	{"key hw import/status", supYes, supYes, supYes, "PC/SC: Windows winscard, Linux pcsc-lite, macOS PCSC.framework (gerçek cihazda yalnızca Windows'ta denendi)"},
	{"server audit", supNo, supYes, supNo, "sunucu sertleştirme denetimi Linux sunucular içindir"},
	{"discreet", supYes, supYes, supYes, "servis görünen adı yalnızca Windows'ta değişir"},
}

func cmdCommandsPlatform(env *Env, args []string) error {
	fs := newFlagSet(env, "commands")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, struct {
			Schema   int               `json:"schema"`
			Current  string            `json:"current"`
			Commands []platformSupport `json:"commands"`
		}{1, runtime.GOOS, platformCommands})
	}
	fmt.Fprintf(env.Stdout, "Bu sistem: %s. Listede olmayan bütün komutlar üç sistemde aynı çalışır.\n\n", runtime.GOOS)
	tw := tabwriter.NewWriter(env.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KOMUT\tWINDOWS\tLINUX\tMACOS\tNOT")
	for _, c := range platformCommands {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.Command, c.Windows, c.Linux, c.MacOS, c.Note)
	}
	return tw.Flush()
}

func cmdDiscreet(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("on [--name ad] | off | status")
	}
	dir := winapp.DataDir()
	if dir == "" {
		d, err := autostartSettingDir(env)
		if err != nil {
			return err
		}
		dir = d
	}
	cur, lerr := winapp.LoadDiscreet(dir)
	switch trimLower(args[0]) {
	case "status":
		if err := parseFlags(newFlagSet(env, "discreet status"), args[1:]); err != nil {
			return err
		}
		if lerr != nil {
			fmt.Fprintf(env.Stderr, "uyarı: %v\n", lerr)
		}
		if !cur.Enabled {
			fmt.Fprintln(env.Stdout, "Göze çarpmayan ad kipi: kapalı")
			return nil
		}
		fmt.Fprintf(env.Stdout, "Göze çarpmayan ad kipi: açık, görünen ad %q\n", cur.NeutralName())
		return nil
	case "on":
		fs := newFlagSet(env, "discreet on")
		name := fs.String("name", "", "görünen nötr ad (boşsa \""+winapp.DefaultNeutralName+"\")")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		n := strings.TrimSpace(*name)
		if n != "" {
			if err := winapp.ValidNeutralName(n); err != nil {
				return usageError("--name: %v", err)
			}
		}
		if runtime.GOOS == "windows" && !winapp.IsElevated() {
			return fmt.Errorf("bu ayar yönetici klasöründe durur; yönetici olarak çalıştırın")
		}
		d := winapp.Discreet{Enabled: true, Name: n}
		if err := winapp.SaveDiscreet(dir, d); err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Göze çarpmayan ad kipi açık: %q. Servis görünen adı bir sonraki uygulama açılışında güncellenir.\n", d.NeutralName())
		fmt.Fprintln(env.Stdout, "Not: servis adı, tünel arayüzü ve kill switch kuralları 'OpenScale' adıyla kalır (korumalar bu adlara bağlı).")
		return nil
	case "off":
		if err := parseFlags(newFlagSet(env, "discreet off"), args[1:]); err != nil {
			return err
		}
		if runtime.GOOS == "windows" && !winapp.IsElevated() {
			return fmt.Errorf("bu ayar yönetici klasöründe durur; yönetici olarak çalıştırın")
		}
		if err := winapp.SaveDiscreet(dir, winapp.Discreet{}); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Göze çarpmayan ad kipi kapalı.")
		return nil
	}
	return usageError("on [--name ad] | off | status")
}
