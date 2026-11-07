package service

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/geoip"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Thresholds of the health alerts (F-193).
const (
	// healthGrace lets a fresh tunnel finish its first sync and set up the
	// exit node routes before their absence counts as a problem.
	healthGrace = time.Minute
	// clockSkewLimit: a document signed further in the future than this
	// means this computer's clock is behind.
	clockSkewLimit   = 10 * time.Minute
	expiryWarnDays   = 14
	expiryDangerDays = 3
	documentWarnDays = 7
)

// healthLocked turns the service state into coded, graded alerts; the
// panel and the tray show these instead of reading single error fields.
// It is called with r.mu held; doc is nil without a membership.
func (r *Runtime) healthLocked(st *panel.AppStatus, doc *trust.Document) []panel.HealthAlert {
	now := r.cfg.Now()
	var out []panel.HealthAlert
	add := func(code, level, msg string) {
		out = append(out, panel.HealthAlert{Code: code, Level: level, Message: msg})
	}
	if st.Error != "" {
		add(panel.HealthJoinFailed, panel.LevelWarning, "Ağa katılım tamamlanamadı: "+st.Error)
	}
	if c := st.Coordinator; c != nil && c.Error != "" {
		add(panel.HealthCoordinatorFailed, panel.LevelDanger, "Bu bilgisayardaki koordinatör çalışmıyor: "+c.Error)
	}
	ds := st.Device
	if ds == nil {
		return sortHealth(out)
	}
	if ds.Removed {
		add(panel.HealthDeviceRemoved, panel.LevelDanger, "Bu bilgisayar ağdan çıkarılmış. Sıfırlayıp yeni bir davet koduyla yeniden katılın.")
		return sortHealth(out)
	}
	if ds.KillSwitchError != "" {
		add(panel.HealthKillSwitchFailed, panel.LevelDanger, ds.KillSwitchError)
	}
	if !ds.Connected {
		msg := "Bağlantı kapalı. Diğer cihazlara ulaşılamaz."
		if ds.DisconnectedUntil != nil {
			msg = "Bağlantı süreli olarak kesik; " + ds.DisconnectedUntil.Local().Format("02.01.2006 15:04") + " sonrasında kendiliğinden açılır."
		}
		add(panel.HealthTunnelPaused, panel.LevelInfo, msg)
	} else if ds.Error != "" {
		add(panel.HealthTunnelDown, panel.LevelDanger, "Tünel çalışmıyor: "+ds.Error)
	}
	settled := ds.Running && now.Sub(r.engineSince) > healthGrace
	if ds.Connected && ds.Running {
		switch {
		case ds.LastSyncError != "":
			add(panel.HealthCoordinatorUnreachable, panel.LevelWarning, "Koordinatöre ulaşılamıyor; yeni cihazlar ve kural değişiklikleri gelmez. Ayrıntı: "+ds.LastSyncError)
		case ds.LastSync == nil && settled:
			add(panel.HealthCoordinatorUnreachable, panel.LevelWarning, "Koordinatörle henüz eşitlenilemedi. Koordinatörün çalıştığından ve adresine ulaşılabildiğinden emin olun.")
		}
		if r.dnsErr != "" {
			add(panel.HealthDNSNotApplied, panel.LevelWarning, "MagicDNS ayarlanamadı; cihaz adları çözülmeyebilir, IP adresleri çalışır. Ayrıntı: "+r.dnsErr)
		}
		out = append(out, r.dnsAlertsLocked(now)...)
		if a, ok := exitAlert(ds, settled); ok {
			out = append(out, a)
		}
		if a, ok := r.captiveAlertLocked(); ok {
			out = append(out, a)
		}
		out = append(out, r.guardAlertsLocked(now)...)
		out = append(out, r.wave3AlertsLocked()...)
	}
	if st.Mode != panel.ModeAdmin && doc != nil {
		// The owner's overview already warns about the document and every
		// membership; members learn it here.
		out = append(out, expiryAlerts(ds, doc, now)...)
	}
	if doc != nil && doc.IssuedAt.After(now.Add(clockSkewLimit)) {
		add(panel.HealthClockSkew, panel.LevelWarning, "Bu bilgisayarın saati geride görünüyor: ağ belgesi gelecekteki bir zamanda imzalanmış. Saati düzeltin; yanlış saatle belgeler geçersiz sayılabilir.")
	}
	out = append(out, p01Alerts(ds, doc, now)...) // ADR-0151, p01_health.go
	return sortHealth(out)
}

// exitAlert reports an exit node that was chosen but carries no traffic.
func exitAlert(ds *panel.DeviceStatus, settled bool) (panel.HealthAlert, bool) {
	want := ds.ExitNodeWanted
	if want == "" || !settled {
		return panel.HealthAlert{}, false
	}
	var exit *panel.PeerInfo
	for i := range ds.ExitNodes {
		if ds.ExitNodes[i].Name == want {
			exit = &ds.ExitNodes[i]
		}
	}
	level, effect := panel.LevelWarning, "İnternet trafiği tünelde bekliyor."
	if ds.KillSwitchActive {
		level, effect = panel.LevelDanger, "Kill switch açık olduğu için internete çıkılamıyor."
	}
	var msg string
	switch {
	case exit == nil:
		msg = fmt.Sprintf("%s artık çıkış düğümü değil. %s Başka bir çıkış düğümü seçin veya \"Yok\" yapın.", want, effect)
	case ds.ExitNode != want:
		msg = fmt.Sprintf("%s çıkış düğümü olarak etkinleştirilemedi. %s", want, effect)
	case !exit.Online:
		msg = fmt.Sprintf("%s çıkış düğümü yanıt vermiyor. %s", want, effect)
	default:
		return panel.HealthAlert{}, false
	}
	return panel.HealthAlert{Code: panel.HealthExitUnreachable, Level: level, Message: msg}, true
}

// expiryAlerts warns before this device's membership or the document runs
// out.
func expiryAlerts(ds *panel.DeviceStatus, doc *trust.Document, now time.Time) []panel.HealthAlert {
	var out []panel.HealthAlert
	if exp := ds.MembershipExpiresAt; exp != nil {
		days := int(exp.Sub(now).Hours() / 24)
		switch {
		case !exp.After(now):
			out = append(out, panel.HealthAlert{Code: panel.HealthMembershipExpiring, Level: panel.LevelDanger, Message: "Bu bilgisayarın üyelik süresi dolmuş. Yöneticiden üyeliği yenilemesini isteyin."})
		case days <= expiryDangerDays:
			out = append(out, panel.HealthAlert{Code: panel.HealthMembershipExpiring, Level: panel.LevelDanger, Message: fmt.Sprintf("Bu bilgisayarın üyeliği %d gün içinde bitiyor. Yöneticiden yenilemesini isteyin.", days)})
		case days <= expiryWarnDays:
			out = append(out, panel.HealthAlert{Code: panel.HealthMembershipExpiring, Level: panel.LevelWarning, Message: fmt.Sprintf("Bu bilgisayarın üyeliği %d gün içinde bitiyor.", days)})
		}
	}
	if !doc.ExpiresAt.IsZero() {
		switch left := doc.ExpiresAt.Sub(now); {
		case left <= 0:
			out = append(out, panel.HealthAlert{Code: panel.HealthDocumentExpiring, Level: panel.LevelDanger, Message: "Ağ belgesinin süresi dolmuş; yeni bağlantılar kurulmaz. Yöneticinin belgeyi yenilemesi gerekiyor."})
		case left <= documentWarnDays*24*time.Hour:
			out = append(out, panel.HealthAlert{Code: panel.HealthDocumentExpiring, Level: panel.LevelWarning, Message: fmt.Sprintf("Ağ belgesinin süresi %d gün içinde doluyor.", int(left.Hours()/24))})
		}
	}
	return out
}

// sortHealth puts the most severe alerts first, keeping the order within a
// level, and never returns nil (the panel expects a list).
func sortHealth(in []panel.HealthAlert) []panel.HealthAlert {
	rank := map[string]int{panel.LevelDanger: 0, panel.LevelWarning: 1, panel.LevelInfo: 2}
	slices.SortStableFunc(in, func(a, b panel.HealthAlert) int { return rank[a.Level] - rank[b.Level] })
	if in == nil {
		return []panel.HealthAlert{}
	}
	return in
}

// peerCountry is the country of an exit node's public address: from its
// system report when this computer has one, otherwise from the address
// WireGuard reaches it at directly (a relayed path shows the coordinator).
func peerCountry(d trust.Device, stats map[trust.Key]wgconf.PeerStatus, inv panel.Inventory) string {
	if rep, ok := inv.Devices[d.Name]; ok {
		if a, err := netip.ParseAddr(rep.Info.PublicIP); err == nil {
			if c := geoip.Country(a); c != "" {
				return c
			}
		}
	}
	if s, ok := stats[d.WireGuardKey]; ok && !s.Relayed && s.Endpoint.IsValid() {
		return geoip.Country(s.Endpoint.Addr())
	}
	return ""
}
