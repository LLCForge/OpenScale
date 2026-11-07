package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/openscale/openscale/internal/desktop"
	"github.com/openscale/openscale/internal/svcmgr"
)

// The app service of macOS (ADR-0227) and Linux (ADR-0234). OpenScale.app
// and the Linux tray (through pkexec) run these as root
// after the administrator password dialog; they can also be run by hand
// with sudo from the app bundle:
//
//	sudo /Applications/OpenScale.app/Contents/MacOS/openscale app install-service
//	sudo openscale app install-service   (Linux)

func init() {
	registerCommands(
		command{"app install-service", "Uygulamanın arka plan servisini bu programdan kurar veya günceller (macOS, Linux; root; uygulama parola penceresiyle çalıştırır)", cmdAppInstallService},
		command{"app restart-service", "Uygulamanın arka plan servisini yeniden başlatır (macOS, Linux; root)", cmdAppRestartService},
		command{"app uninstall-service", "Uygulamanın arka plan servisini ve kill switch'i kaldırır; anahtarlar ve ağ kalır (macOS, Linux; root)", cmdAppUninstallService},
	)
}

func appServiceOnly() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return usageError("bu komut yalnızca macOS ve Linux'ta; Windows'ta 'openscale app' servisi kendisi kurar")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: sudo ile çalıştırın veya OpenScale uygulamasını (tepsiyi) açın", svcmgr.ErrNeedsRoot)
	}
	return nil
}

func cmdAppInstallService(env *Env, args []string) error {
	if err := parseFlags(newFlagSet(env, "app install-service"), args); err != nil {
		return err
	}
	if err := appServiceOnly(); err != nil {
		return err
	}
	notes, err := desktop.InstallService(env.Ctx)
	for _, n := range notes {
		fmt.Fprintln(env.Stdout, n)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "OpenScale servisi kuruldu ve başlatıldı ("+appServiceName()+").")
	return nil
}

func cmdAppRestartService(env *Env, args []string) error {
	if err := parseFlags(newFlagSet(env, "app restart-service"), args); err != nil {
		return err
	}
	if err := appServiceOnly(); err != nil {
		return err
	}
	return desktop.RestartService(env.Ctx)
}

func cmdAppUninstallService(env *Env, args []string) error {
	if err := parseFlags(newFlagSet(env, "app uninstall-service"), args); err != nil {
		return err
	}
	if err := appServiceOnly(); err != nil {
		return err
	}
	if err := desktop.Uninstall(); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "OpenScale uygulama servisi ve kill switch kaldırıldı. Anahtarlar ve ağ verisi "+appServiceStateDir()+" altında duruyor.")
	return nil
}

// appServiceName is the app service of this system.
func appServiceName() string {
	if runtime.GOOS == "linux" {
		return svcmgr.LinuxAppUnit
	}
	return svcmgr.DarwinAppLabel
}

// appServiceStateDir is where the app service keeps keys and the network.
func appServiceStateDir() string {
	if runtime.GOOS == "linux" {
		return svcmgr.LinuxAppStateDir
	}
	return svcmgr.DarwinAppStateDir
}
