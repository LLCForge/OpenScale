package cli

import (
	"fmt"

	"github.com/openscale/openscale/internal/desktop"
)

func cmdApp(env *Env, args []string) error {
	fs := newFlagSet(env, "app")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return desktop.RunApp(env.Ctx)
}

func cmdServiceRun(env *Env, args []string) error {
	fs := newFlagSet(env, "service run")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return desktop.RunService()
}

func cmdServiceUninstall(env *Env, args []string) error {
	if serviceUninstallElsewhere() {
		return cmdServiceUninstallUnix(env, args)
	}
	fs := newFlagSet(env, "service uninstall")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := desktop.Uninstall(); err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, `OpenScale servisi, kill switch ve güvenlik duvarı kuralları kaldırıldı. Anahtarlar ve ağ verisi %ProgramData%\OpenScale altında duruyor.`)
	return nil
}
