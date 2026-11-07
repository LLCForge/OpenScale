package service

import (
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
)

// DNS health alerts (F-062, ADR-0034): network DNS that could not be
// applied, settings another program keeps changing (F-061), Group Policy
// NRPT rules that hide OpenScale's own (F-063) and network resolvers that
// do not answer.

const (
	// dnsRepairShown keeps a repair visible for a while after it happened.
	dnsRepairShown = 10 * time.Minute
	// dnsStatusEvery spaces the system status checks.
	dnsStatusEvery = time.Minute
	// dnsForwardRecent is how recent a forwarding failure must be to show.
	dnsForwardRecent = 2 * time.Minute
)

// dnsHealthState is guarded by Runtime.mu.
type dnsHealthState struct {
	repairs    int
	lastRepair time.Time
	repairErr  string
	status     osnet.DNSSystemStatus
	statusAt   time.Time
}

// noteDNSRepair records that the DNS settings were applied again because
// another program had changed them.
func (r *Runtime) noteDNSRepair(err error) {
	r.logger.Warn("DNS settings were changed by another program; applying them again", "error", err.Error())
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dnsHealth.repairs++
	r.dnsHealth.lastRepair = r.cfg.Now()
	r.dnsHealth.repairErr = err.Error()
}

// dnsAlertsLocked returns the DNS alerts; r.mu is held.
func (r *Runtime) dnsAlertsLocked(now time.Time) []panel.HealthAlert {
	var out []panel.HealthAlert
	add := func(code, level, msg string) {
		out = append(out, panel.HealthAlert{Code: code, Level: level, Message: msg})
	}
	if r.netDNSErr != "" {
		add(panel.HealthDNSNetworkFailed, panel.LevelWarning, r.netDNSErr)
	}
	h := &r.dnsHealth
	if h.repairs > 0 && now.Sub(h.lastRepair) < dnsRepairShown {
		add(panel.HealthDNSOverwritten, panel.LevelInfo, fmt.Sprintf(
			"Başka bir program DNS ayarlarını değiştirdi; OpenScale ayarları yeniden uyguladı (bu oturumda %d kez). Sürekli tekrarlanıyorsa o programın DNS yönetimini bu arayüz için kapatın.", h.repairs))
	}
	if r.cfg.Hooks.DNSStatus != nil {
		if now.Sub(h.statusAt) >= dnsStatusEvery || h.statusAt.IsZero() {
			h.status, h.statusAt = r.cfg.Hooks.DNSStatus(""), now
		}
		if h.status.GroupPolicyNRPT {
			add(panel.HealthDNSGroupPolicy, panel.LevelWarning, r.groupPolicyDNSMessageLocked())
		}
	}
	if e := r.engine; e != nil {
		st := e.DNSForwardStats()
		if !st.LastErrorAt.IsZero() && now.Sub(st.LastErrorAt) < dnsForwardRecent && st.LastErrorAt.After(st.LastOKAt) {
			add(panel.HealthDNSResolverUnreachable, panel.LevelWarning,
				"Ağın DNS çözücüsüne tünel üzerinden ulaşılamıyor; bu alanlardaki adlar çözülmüyor. Çözücü cihazın açık olduğundan ve kuralların 53 numaralı porta izin verdiğinden emin olun. Ayrıntı: "+st.LastError)
		}
	}
	return out
}

// groupPolicyDNSMessageLocked explains the Group Policy NRPT rules for the
// network domain (#272): whether a policy rule covers it and whether that
// rule reaches OpenScale's resolver. r.mu is held.
func (r *Runtime) groupPolicyDNSMessageLocked() string {
	const generic = "Grup İlkesi ile tanımlı NRPT kuralları var; Windows bu durumda OpenScale'in DNS kurallarını yok sayar ve cihaz adları çözülmeyebilir. BT yöneticinizden ağ alan adı için Grup İlkesi'ne bir NRPT kuralı eklemesini isteyin."
	if r.engine == nil {
		return generic
	}
	doc := r.engine.Document()
	if doc == nil || doc.DNSDomain == "" {
		return generic
	}
	c := osnet.NRPTGroupPolicyConflict(r.dnsHealth.status, doc.DNSDomain, doc.DNSResolverIPv4().String())
	if msg := c.Message(doc.DNSDomain); msg != "" {
		return msg
	}
	return generic
}
