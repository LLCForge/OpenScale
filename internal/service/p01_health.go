package service

import (
	"fmt"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// Device-side alerts of package P01 (ADR-0151): the device itself asks for
// a key rotation once its key is older than the network's key age policy
// (#347), and every member learns that the network is under the emergency
// lock (#361).

// Health codes of the P01 device alerts.
const (
	healthKeyAgeOverdue = "key_age_overdue"
	healthLockdown      = "network_lockdown"
)

func p01Alerts(ds *panel.DeviceStatus, doc *trust.Document, now time.Time) []panel.HealthAlert {
	if ds == nil || doc == nil {
		return nil
	}
	var out []panel.HealthAlert
	if st, overdue := doc.KeyOverdue(ds.Name, now); overdue {
		out = append(out, panel.HealthAlert{Code: healthKeyAgeOverdue, Level: panel.LevelWarning,
			Message: fmt.Sprintf("Bu cihazın anahtarı %d günlük; ağ politikası en çok %d gün. Anahtar yenilemek için bu cihazda 'openscale device rotate-key' çalıştırıp isteği yöneticiye verin.", st.AgeDays, doc.MaxKeyAgeDays)})
	}
	if l := doc.Lockdown; l != nil {
		msg := "Ağ yöneticisi acil kilit açtı: cihazlar arası erişim geçici olarak kapalı."
		if l.Reason != "" {
			msg += " Not: " + l.Reason
		}
		out = append(out, panel.HealthAlert{Code: healthLockdown, Level: panel.LevelDanger, Message: msg})
	}
	return out
}
