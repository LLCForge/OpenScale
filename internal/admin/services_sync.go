package admin

import (
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// syncRuleParts spells out what a sync rule grants (ADR-0104, ADR-0110),
// for example "klasörler (salt okunur): belgeler,fotograflar" and
// "şifreli yedek (kota 50.0 GiB; eski yedekleri silebilir)".
func syncRuleParts(r trust.Rule) []string {
	var parts []string
	if len(r.Folders) > 0 {
		parts = append(parts, "klasörler (salt okunur): "+strings.Join(r.Folders, ","))
	}
	if r.Backup {
		q := r.Quota
		if q == 0 {
			q = trust.DefaultBackupQuota
		}
		s := "şifreli yedek (kota " + quotaText(q)
		if r.AllowPrune {
			s += "; eski yedekleri silebilir"
		} else {
			s += "; yalnızca ekleme"
		}
		parts = append(parts, s+")")
	}
	return parts
}

func quotaText(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
