package cli

import (
	"errors"
	"fmt"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/winapp"
)

// killSwitchOps are the operating system calls behind the killswitch
// commands; tests replace them.
type killSwitchOps struct {
	supported func() bool
	elevated  func() bool
	remove    func() error
	installed func() (bool, error)
}

var killSwitch = killSwitchOps{
	supported: osnet.KillSwitchSupported,
	elevated:  winapp.IsElevated,
	remove:    osnet.RemoveKillSwitch,
	installed: osnet.KillSwitchInstalled,
}

// cmdKillSwitchOff removes the persistent kill switch without the
// service (ADR-0023): the way back to the internet if the filters were
// left behind, for example after OpenScale was deleted by hand.
func cmdKillSwitchOff(env *Env, args []string) error {
	fs := newFlagSet(env, "killswitch off")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !killSwitch.supported() {
		fmt.Fprintln(env.Stdout, "Bu sistemde kalıcı kill switch yok; kaldırılacak bir şey yok.")
		return nil
	}
	if !killSwitch.elevated() {
		return errors.New("kill switch'i kaldırmak için komutu yönetici olarak çalıştırın (Windows: Yönetici PowerShell; Linux: sudo)")
	}
	if err := killSwitch.remove(); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, "OpenScale kill switch filtreleri kaldırıldı; internet trafiği artık engellenmiyor.")
	fmt.Fprintln(env.Stdout, "Servis çalışıyorsa ve bir çıkış düğümü seçiliyse, çıkış düğümü yeniden etkinleştiğinde filtreler tekrar kurulur.")
	fmt.Fprintln(env.Stdout, "Kalıcı olarak kapatmak için panelde veya tepsi menüsünde kill switch'i kapatın ya da çıkış düğümünü \"Yok\" yapın.")
	return nil
}

// cmdKillSwitchStatus reports whether OpenScale's filters are installed.
func cmdKillSwitchStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "killswitch status")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !killSwitch.supported() {
		fmt.Fprintln(env.Stdout, "Bu sistemde kalıcı kill switch yok.")
		return nil
	}
	on, err := killSwitch.installed()
	if err != nil {
		if !killSwitch.elevated() {
			return fmt.Errorf("%w (komutu yönetici olarak çalıştırmayı deneyin)", err)
		}
		return err
	}
	if on {
		fmt.Fprintln(env.Stdout, "Kill switch kurulu: internet trafiği yalnızca OpenScale tünelinden çıkabilir.")
		fmt.Fprintln(env.Stdout, "İnternete erişemiyorsanız ve OpenScale çalışmıyorsa: openscale killswitch off (yönetici olarak)")
		return nil
	}
	fmt.Fprintln(env.Stdout, "Kill switch kurulu değil.")
	return nil
}
