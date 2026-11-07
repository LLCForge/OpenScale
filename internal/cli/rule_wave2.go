package cli

import (
	"flag"
	"fmt"

	"github.com/openscale/openscale/internal/trust"
)

// Fields of rdesk (ADR-0055) and sync (ADR-0104, ADR-0110) rules for
// "openscale rule add".
type ruleWave2Flags struct {
	allowControl    *bool
	allowUnattended *bool
	folders         *string
	backup          *bool
	quota           *string
	allowPrune      *bool
}

func addRuleWave2Flags(fs *flag.FlagSet) ruleWave2Flags {
	return ruleWave2Flags{
		allowControl:    fs.Bool("allow-control", false, "rdesk: izlemeye ek olarak klavye, fare ve pano kontrolüne izin ver"),
		allowUnattended: fs.Bool("allow-unattended", false, "rdesk: hedefteki kişinin onayı olmadan bağlanmaya izin ver (gösterge yine görünür)"),
		folders:         fs.String("folders", "", "sync: kaynağın hedeften salt okunur çekebileceği klasör kimlikleri (virgülle)"),
		backup:          fs.Bool("backup", false, "sync: kaynağın hedefte şifreli yedek tutmasına izin ver (hedef içeriği göremez)"),
		quota:           fs.String("quota", "", "sync: yedek kotası, ör. 50GiB (boş: 50 GiB)"),
		allowPrune:      fs.Bool("allow-prune", false, "sync: kaynağın eski yedeklerini silmesine izin ver (varsayılan: yalnızca ekleme)"),
	}
}

func (f ruleWave2Flags) used() bool {
	return *f.allowControl || *f.allowUnattended || *f.folders != "" || *f.backup || *f.quota != "" || *f.allowPrune
}

// apply copies the fields into a service rule; trust validation refuses
// them on the wrong service.
func (f ruleWave2Flags) apply(env *Env, r *trust.Rule) error {
	r.AllowControl, r.AllowUnattended = *f.allowControl, *f.allowUnattended
	r.Folders, r.Backup, r.AllowPrune = splitList(*f.folders), *f.backup, *f.allowPrune
	if *f.quota != "" {
		q, err := parseSyncSize(*f.quota)
		if err != nil {
			return usageError("--quota: %v", err)
		}
		r.Quota = q
	}
	if r.Service == trust.ServiceRemoteDesktop && r.AllowUnattended {
		fmt.Fprintln(env.Stderr, "uyarı: gözetimsiz erişim hedefteki kişiye sormadan oturum açar; ekrandaki gösterge yine görünür.")
	}
	if r.Service == trust.ServiceSync && r.AllowPrune {
		fmt.Fprintln(env.Stderr, "uyarı: allow-prune ile ele geçirilen bir kaynak eski yedeklerini silebilir.")
	}
	return nil
}
