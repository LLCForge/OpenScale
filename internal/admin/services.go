package admin

import (
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// ServiceRuleDetail renders the service part of a service rule (ADR-0030,
// ADR-0031), for example "ssh(kullanıcılar: ali,system; root; port yönlendirme)"
// or "wake(aracı: nas)". Every permission a rule grants is spelled out so
// the owner sees it in the change list before signing.
func ServiceRuleDetail(r trust.Rule) string {
	var parts []string
	if len(r.Users) > 0 {
		parts = append(parts, "kullanıcılar: "+strings.Join(r.Users, ","))
	}
	if r.AllowRoot {
		parts = append(parts, "root")
	}
	if r.AllowForward {
		parts = append(parts, "port yönlendirme")
	}
	if len(r.Via) > 0 {
		parts = append(parts, "aracı: "+strings.Join(r.Via, ","))
	}
	if r.Service == trust.ServiceRemoteDesktop && !r.IsDeny() {
		if r.AllowControl {
			parts = append(parts, "izleme ve kontrol")
		} else {
			parts = append(parts, "yalnızca izleme")
		}
	}
	if r.AllowUnattended {
		parts = append(parts, "gözetimsiz (onaysız)")
	}
	if r.Service == trust.ServiceSupport && !r.IsDeny() { // #852, ADR-0232
		if r.AllowKill {
			parts = append(parts, "okuma ve süreç sonlandırma (support.kill)")
		} else {
			parts = append(parts, "salt okunur")
		}
	}
	parts = append(parts, syncRuleParts(r)...)
	s := string(r.Service)
	if len(parts) > 0 {
		s += "(" + strings.Join(parts, "; ") + ")"
	}
	return s
}
