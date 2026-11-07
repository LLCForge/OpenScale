package cli

import (
	"fmt"

	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/version"
)

// "openscale update channel [stable|beta]" (ADR-0193): the updater
// installs a beta only when the beta channel is chosen.

func init() {
	registerCommands(
		command{"update channel", "Güncelleme kanalı: stable (varsayılan) veya beta; argümansız gösterir (değiştirmek yönetici/root ister)", cmdUpdateChannel},
		command{"about", "Sürüm, kanal (kararlı/beta) ve derleme bilgisi", cmdAbout},
	)
}

func cmdUpdateChannel(env *Env, args []string) error {
	fs := newFlagSet(env, "update channel")
	if err := fs.Parse(args); err != nil {
		return usageError("%v", err)
	}
	p, err := updater.DefaultPlatform()
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		ch, err := updater.ReadChannel(p.StateDir)
		if err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: %v; kararlı kanal geçerli\n", err)
		}
		fmt.Fprintf(env.Stdout, "Güncelleme kanalı: %s\n", channelText(ch))
		return nil
	}
	if fs.NArg() > 1 {
		return usageError("tek kanal adı: stable veya beta")
	}
	ch, err := updater.ParseChannel(fs.Arg(0))
	if err != nil {
		return usageError("%v", err)
	}
	if err := updater.RequirePrivileges(); err != nil {
		return err
	}
	if err := updater.WriteChannel(p.StateDir, ch); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Güncelleme kanalı: %s\n", channelText(ch))
	if ch == updater.ChannelBeta {
		fmt.Fprintln(env.Stdout, "Önsürümler (beta) artık kurulabilir; kararlıya dönmek için: openscale update channel stable")
	}
	return nil
}

func channelText(ch string) string {
	if ch == updater.ChannelBeta {
		return "beta (önsürümler dahil)"
	}
	return "kararlı (yalnızca kararlı sürümler)"
}

func cmdAbout(env *Env, args []string) error {
	fs := newFlagSet(env, "about")
	asJSON := fs.Bool("json", false, "JSON çıktı")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	info := struct {
		Schema  int    `json:"schema"`
		Version string `json:"version"`
		Label   string `json:"label"`
		Channel string `json:"channel"`
		Build   string `json:"build,omitempty"`
	}{1, version.Version, version.Label(version.Version), version.Channel(), version.Build}
	if *asJSON {
		return printJSON(env.Stdout, info)
	}
	fmt.Fprintf(env.Stdout, "OpenScale %s\n", info.Label)
	switch info.Channel {
	case version.ChannelBeta:
		fmt.Fprintln(env.Stdout, "Kanal: beta (önsürüm; hata bulursanız bildirin)")
	case version.ChannelDev:
		fmt.Fprintln(env.Stdout, "Kanal: geliştirme derlemesi")
	default:
		fmt.Fprintln(env.Stdout, "Kanal: kararlı")
	}
	if info.Build != "" {
		fmt.Fprintf(env.Stdout, "Derleme: %s\n", info.Build)
	}
	return nil
}
