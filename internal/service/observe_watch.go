package service

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// securityWatch turns what the tunnel shows into security events (#187):
// document changes, devices added, removed or revoked, documents refused
// for a bad signature, a rollback or another network, and the kill switch
// blocking traffic. The first look only sets the baseline.
type securityWatch struct {
	o       *Observer
	started bool
	version uint64
	epoch   uint64
	devices map[string]bool
	syncErr string
	ksOn    bool
	expired bool
}

// syncErrorClasses map a document refusal to an audit kind. The engine
// keeps the error text, so the trust package's messages are matched.
var syncErrorClasses = []struct {
	err      error
	kind     string
	severity string
	text     string
}{
	{trust.ErrRollback, "document_rollback_refused", audit.SeverityCritical, "Eski sürüm bir ağ belgesi reddedildi (geri alma denemesi)."},
	{trust.ErrEquivocation, "document_equivocation_refused", audit.SeverityCritical, "Aynı sürüm numaralı iki farklı ağ belgesi görüldü; ikincisi reddedildi."},
	{trust.ErrBadSignature, "signature_failed", audit.SeverityCritical, "İmzası doğrulanamayan bir ağ belgesi reddedildi."},
	{trust.ErrUnsupportedAlgorithm, "signature_failed", audit.SeverityCritical, "Desteklenmeyen imza algoritmalı bir ağ belgesi reddedildi."},
	{trust.ErrWrongNetwork, "document_wrong_network", audit.SeverityWarning, "Başka bir ağa ait belge reddedildi."},
	{trust.ErrRootFingerprintMismatch, "root_key_mismatch", audit.SeverityCritical, "Kök anahtar parmak izi tutmayan bir belge reddedildi."},
	{trust.ErrTooLarge, "document_too_large", audit.SeverityWarning, "Boyut sınırını aşan bir ağ belgesi reddedildi."},
	{trust.ErrNotYetValid, "document_not_yet_valid", audit.SeverityWarning, "Henüz geçerli olmayan bir ağ belgesi reddedildi (saat farkı olabilir)."},
}

func classifySyncError(msg string) (kind, severity, text string, ok bool) {
	for _, c := range syncErrorClasses {
		if strings.Contains(msg, c.err.Error()) {
			return c.kind, c.severity, c.text, true
		}
	}
	return "", "", "", false
}

func (w *securityWatch) look() {
	o := w.o
	e := o.cfg.Engine()
	if e != nil {
		w.document(e.Document())
		st := e.Status()
		w.syncError(st.LastSyncError)
		if st.Expired && !w.expired && w.started {
			o.Security("document_expired", audit.SeverityWarning, panel.CategorySecurity, "", "Ağ belgesinin süresi doldu; tünel trafiği durduruldu.", true)
		}
		w.expired = st.Expired
	}
	if o.cfg.Status != nil {
		w.killSwitch(o.cfg.Status())
	}
	w.started = true
}

func (w *securityWatch) document(doc *trust.Document) {
	if doc == nil {
		return
	}
	names := make(map[string]bool, len(doc.Devices))
	for _, d := range doc.Devices {
		names[d.Name] = true
	}
	if w.devices == nil {
		w.version, w.epoch, w.devices = doc.Version, doc.RootEpoch, names
		return
	}
	if doc.Version == w.version && doc.RootEpoch == w.epoch {
		return
	}
	o := w.o
	switch {
	case doc.RootEpoch != w.epoch:
		o.Security("root_key_changed", audit.SeverityCritical, panel.CategorySecurity, "",
			fmt.Sprintf("Ağın kök anahtarı değişti (dönem %d → %d); kurtarma anahtarıyla imzalı geçiş kabul edildi.", w.epoch, doc.RootEpoch), true)
	case doc.Version < w.version:
		o.Security("document_version_lower", audit.SeverityCritical, panel.CategorySecurity, "",
			fmt.Sprintf("Etkin ağ belgesinin sürümü düştü (v%d → v%d).", w.version, doc.Version), true)
	default:
		o.Security("document_changed", audit.SeverityInfo, panel.CategorySecurity, "",
			fmt.Sprintf("Ağ belgesi güncellendi: v%d → v%d.", w.version, doc.Version), false)
	}
	revoked := map[string]bool{}
	for _, r := range doc.Revoked {
		revoked[r.Name] = true
	}
	var added, removed []string
	for n := range names {
		if !w.devices[n] {
			added = append(added, n)
		}
	}
	for n := range w.devices {
		if !names[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	for _, n := range added {
		o.Security("device_added", audit.SeverityInfo, panel.CategoryDevice, n, "Ağa yeni cihaz eklendi: "+n+".", true)
	}
	for _, n := range removed {
		if revoked[n] {
			o.Security("device_revoked", audit.SeverityWarning, panel.CategoryDevice, n, n+" ağdan çıkarıldı ve anahtarları iptal edildi.", true)
		} else {
			o.Security("device_removed", audit.SeverityWarning, panel.CategoryDevice, n, n+" ağ belgesinden kaldırıldı.", true)
		}
	}
	w.version, w.epoch, w.devices = doc.Version, doc.RootEpoch, names
}

func (w *securityWatch) syncError(msg string) {
	kind, sev, text, ok := classifySyncError(msg)
	if !ok {
		w.syncErr = ""
		return
	}
	if kind == w.syncErr {
		return
	}
	w.syncErr = kind
	w.o.Security(kind, sev, panel.CategorySecurity, "", text+" Ayrıntı: "+msg, sev == audit.SeverityCritical)
}

// killSwitch reports the kill switch starting to block traffic: an exit
// node is wanted, the filters are installed and the exit node cannot be
// reached (ADR-0023).
func (w *securityWatch) killSwitch(st panel.AppStatus) {
	engaged := false
	if d := st.Device; d != nil && d.KillSwitchActive && d.ExitNodeWanted != "" {
		for _, a := range st.Health {
			if a.Code == panel.HealthExitUnreachable {
				engaged = true
			}
		}
	}
	switch {
	case engaged && !w.ksOn:
		w.o.Security("killswitch_engaged", audit.SeverityWarning, panel.CategoryKillSwitch, "",
			"Kill switch devrede: çıkış düğümüne ulaşılamıyor, internet trafiği engelleniyor.", true)
	case !engaged && w.ksOn && w.started:
		w.o.Security("killswitch_released", audit.SeverityInfo, panel.CategoryKillSwitch, "",
			"Kill switch artık trafiği engellemiyor.", false)
	}
	w.ksOn = engaged
}
