package cli

import (
	"fmt"

	"github.com/openscale/openscale/internal/admin"
)

// Version chain (#343, ADR-0144): every version names the payload digest
// of the one before it; members refuse a version that forks from theirs.

const versionChainWarning = `UYARI: Sürüm zinciri belgeye "prev_digest" alanını ekler. Bu özelliği
bilmeyen eski OpenScale sürümlerindeki cihazlar ve koordinatör bu sürümden
itibaren ağ belgesini REDDEDER ve son kabul ettikleri belgede kalır.
Açmadan önce bütün cihazları ve koordinatörü güncelleyin; eski istemcilerin
bağlanmasını kesmek için "openscale network min-version" ile asgari sürümü
de yükseltin. Kapatmak eski cihazlarla uyumu geri getirir.`

func cmdNetworkChain(env *Env, args []string) error {
	fs := newFlagSet(env, "network chain")
	f := addEditFlags(fs)
	state := fs.String("state", "", "on (sürüm zincirini açar) veya off (kapatır)")
	yes := fs.Bool("yes", false, "eski cihazların yeni belgeyi reddedeceğini kabul eder (açarken zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *state != "on" && *state != "off" {
		return usageError("--state on|off zorunlu")
	}
	on := *state == "on"
	if on {
		fmt.Fprintln(env.Stderr, versionChainWarning)
		if !*yes && !*f.dryRun {
			return usageError("sürüm zincirini açmak için --yes verin (veya önce --dry-run ile bakın)")
		}
	}
	return runEdit(env, f, admin.SetVersionChain(on))
}
