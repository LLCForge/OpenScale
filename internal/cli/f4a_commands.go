package cli

import (
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// Faz 4A/4E commands (ADR-0232): device icons (#233) and the support rule
// (#852). Ranges in groups, exit_users and via (#277) need no command of
// their own; group set and exit users set accept them.

func init() { registerCommands(f4aCommands()...) } // g4_registry.go

func f4aCommands() []command {
	return []command{
		{"device icon", "Cihazın simgesini belirler: --dir AĞ --name CİHAZ (--icon " + iconList() + " | --clear)", cmdDeviceIcon},
		{"support allow", "Uzaktan destek kuralı ekler (salt okunur; --kill ile süreç sonlandırma da): --dir AĞ --from YARDIMCI --to HEDEF [--kill]", cmdSupportAllow},
	}
}

func iconList() string {
	icons := trust.DeviceIcons()
	names := make([]string, len(icons))
	for i, ic := range icons {
		names[i] = string(ic)
	}
	return strings.Join(names, "|")
}

// normalizeAddrList turns bare IP addresses into single-address CIDRs.
func normalizeAddrList(list []string) []string {
	for i, e := range list {
		list[i] = trust.NormalizeAddrEntry(e)
	}
	return list
}

func cmdDeviceIcon(env *Env, args []string) error {
	fs := newFlagSet(env, "device icon")
	common := addEditFlags(fs)
	name := fs.String("name", "", "cihaz adı (zorunlu)")
	icon := fs.String("icon", "", "simge türü: "+iconList())
	clear := fs.Bool("clear", false, "simgeyi kaldır")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	ic := trust.DeviceIcon(strings.ToLower(strings.TrimSpace(*icon)))
	switch {
	case *name == "":
		return usageError("--name zorunlu")
	case *clear && ic != "":
		return usageError("--icon ve --clear birlikte kullanılamaz")
	case !*clear && ic == "":
		return usageError("--icon veya --clear gerekli")
	case ic != "" && !ic.Valid():
		return usageError("bilinmeyen simge %q; şunlardan biri olmalı: %s", ic, iconList())
	}
	if ic != "" {
		fmt.Fprintf(env.Stderr, "not: simge, asgari istemci sürümünü %s yapar (yoksa veya daha düşükse); eski cihazlar yeni belgeyi reddeder.\n", trust.SchemaV2MinClientVersion)
	}
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error { return doc.SetDeviceIcon(*name, ic) }, *name))
}

func cmdSupportAllow(env *Env, args []string) error {
	fs := newFlagSet(env, "support allow")
	common := addEditFlags(fs)
	from := fs.String("from", "", "yardım eden cihaz, tag:<etiket> veya group:<grup> (zorunlu)")
	to := fs.String("to", "", "destek verilen cihaz, tag:<etiket> veya group:<grup> (zorunlu)")
	kill := fs.Bool("kill", false, "süreç sonlandırmaya da izin ver (support.kill)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return usageError("--from ve --to zorunlu")
	}
	rule := trust.Rule{From: splitList(*from), To: splitList(*to), Service: trust.ServiceSupport, AllowKill: *kill,
		Description: "Uzaktan destek: " + *from + " -> " + *to}
	fmt.Fprintln(env.Stderr, "not: hedefteki kişi her oturumu onaylar ve oturum boyunca \"uzaktan bağlı\" göstergesini görür.")
	return runEdit(env, common, suggestingChange(func(doc *trust.Document) error { return doc.AddRule(rule) }, append(rule.From, rule.To...)...))
}
