package service

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
)

// Exit node resolver hardening settings and controls (P05). The settings
// live in settings.json under "tunnel"."exit_dns_guard"; the zero value is
// the engine default, so older settings files keep their behaviour.

// exitDNSGuardPrefSpecs are appended to prefSpecs.
var exitDNSGuardPrefSpecs = []prefSpec{
	{"exit-dns-rebind-protect", "true", "Çıkış çözücüsü genel adların özel/ağ içi adreslere çözülmesini engeller (DNS yeniden bağlama)", func(s settings) string { return boolText(!s.tunnel().ExitDNSGuard.RebindOff) }},
	{"exit-dns-rebind-allow", "", "Özel adrese çözülebilecek alanlar, virgülle (alt alanlar dahil), ör. ev.example.com", func(s settings) string { return strings.Join(s.tunnel().ExitDNSGuard.RebindAllow, ",") }},
	{"exit-dns-serve-stale", "false", "Üst çözücü yanıt vermezken süresi geçmiş kaydı 30 sn ömürle sun ve sık kayıtları önceden yenile (RFC 8767)", func(s settings) string { return boolText(s.tunnel().ExitDNSGuard.ServeStale) }},
	{"exit-dns-rate-limit", "0", fmt.Sprintf("Cihaz başına saniyede sorgu sınırı (0: %d, -1: kapalı, en çok %d)", node.DefaultExitDNSRate, node.MaxExitDNSRate), func(s settings) string { return strconv.Itoa(s.tunnel().ExitDNSGuard.RateLimit) }},
	{"exit-dns-tunnel-detect", "true", "Uzun, rastgele alt adlarla yoğun sorgu yapan cihazı olay olarak bildir (DNS tünelleme)", func(s settings) string { return boolText(!s.tunnel().ExitDNSGuard.TunnelDetectOff) }},
	{"exit-dns-tunnel-block", "false", "İşaretlenen cihazın şüpheli sorgularını 10 dakika reddet (yanlış pozitif olabilir)", func(s settings) string { return boolText(s.tunnel().ExitDNSGuard.TunnelBlock) }},
	{"exit-dns-aaaa", "auto", "Üyelere AAAA kayıtları: auto (bu makinede genel IPv6 yoksa boş), keep veya filter", func(s settings) string { return orAuto(s.tunnel().ExitDNSGuard.AAAA) }},
	{"exit-dns-profile-lists", "", "DNS profillerinin yerel engel listeleri: profil=/mutlak/yol, virgülle (profil belgede tanımlanır)", func(s settings) string { return joinProfileLists(s.tunnel().ExitDNSGuard.ProfileLists) }},
	{"exit-dns-safe-search-map", "", "Güvenli arama eşlemesi dosyası (satır: kaynak hedef); safe_search profilleri bunu kullanır, yoksa zorlanmaz", func(s settings) string { return s.tunnel().ExitDNSGuard.SafeSearchMap }},
}

func init() { prefSpecs = append(prefSpecs, exitDNSGuardPrefSpecs...) }

func orAuto(s string) string {
	if s == "" {
		return "auto"
	}
	return s
}

func joinProfileLists(m map[string]string) string {
	keys := slices.Sorted(maps.Keys(m))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return strings.Join(out, ",")
}

// cloneExitDNSGuard deep-copies the settings; empty lists become nil so a
// saved and a parsed value compare equal.
func cloneExitDNSGuard(g node.ExitDNSGuardConfig) node.ExitDNSGuardConfig {
	g.RebindAllow = slices.Clone(g.RebindAllow)
	if len(g.RebindAllow) == 0 {
		g.RebindAllow = nil
	}
	if len(g.ProfileLists) == 0 {
		g.ProfileLists = nil
	} else {
		g.ProfileLists = maps.Clone(g.ProfileLists)
	}
	return g
}

// validExitDNSGuard checks the settings and that every profile list file
// exists now.
func validExitDNSGuard(g node.ExitDNSGuardConfig) error {
	if err := g.Validate(); err != nil {
		return fmt.Errorf("çıkış DNS koruması: %w", err)
	}
	for name, p := range g.ProfileLists {
		if err := ValidLocalFile("profil "+name+" engel listesi", p); err != nil {
			return err
		}
	}
	if err := ValidLocalFile("güvenli arama eşlemesi", g.SafeSearchMap); err != nil {
		return err
	}
	return nil
}

// applyExitDNSGuardPref changes one key of "openscale set"; ok is false
// for other keys.
func applyExitDNSGuardPref(g *node.ExitDNSGuardConfig, key, v string) (bool, error) {
	var err error
	v = strings.TrimSpace(v)
	switch key {
	case "exit-dns-rebind-protect":
		var on bool
		on, err = parseBoolPref(key, v)
		g.RebindOff = !on
	case "exit-dns-rebind-allow":
		list := splitList(strings.ToLower(v))
		next := *g
		next.RebindAllow = list
		if err = next.Validate(); err == nil {
			g.RebindAllow = list
		}
	case "exit-dns-serve-stale":
		g.ServeStale, err = parseBoolPref(key, v)
	case "exit-dns-rate-limit":
		n, perr := strconv.Atoi(v)
		if v == "" {
			n, perr = 0, nil
		}
		if perr != nil || n < -1 || n > node.MaxExitDNSRate {
			return true, fmt.Errorf("%s: -1 (kapalı), 0 (varsayılan) veya 1-%d yazın", key, node.MaxExitDNSRate)
		}
		g.RateLimit = n
	case "exit-dns-tunnel-detect":
		var on bool
		on, err = parseBoolPref(key, v)
		g.TunnelDetectOff = !on
	case "exit-dns-tunnel-block":
		g.TunnelBlock, err = parseBoolPref(key, v)
	case "exit-dns-aaaa":
		s := strings.ToLower(v)
		if s == "auto" {
			s = ""
		}
		next := *g
		next.AAAA = s
		if err = next.Validate(); err == nil {
			g.AAAA = s
		}
	case "exit-dns-profile-lists":
		m := map[string]string{}
		for _, part := range splitList(v) {
			name, path, ok := strings.Cut(part, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !ok || name == "" {
				return true, fmt.Errorf("%s: biçim profil=/mutlak/yol olmalı", key)
			}
			if _, dup := m[name]; dup {
				return true, fmt.Errorf("%s: %s profili iki kez yazılmış", key, name)
			}
			m[name] = strings.TrimSpace(path)
		}
		next := *g
		next.ProfileLists = m
		if err = validExitDNSGuard(next); err == nil {
			g.ProfileLists = m
			if len(m) == 0 {
				g.ProfileLists = nil
			}
		}
	case "exit-dns-safe-search-map":
		next := *g
		next.SafeSearchMap = v
		if err = validExitDNSGuard(next); err == nil {
			g.SafeSearchMap = v
		}
	default:
		return false, nil
	}
	return true, err
}

// usableExitDNSGuard is the saved setting, or the default with a warning
// when it is not usable now (e.g. a profile list file is gone).
func (r *Runtime) usableExitDNSGuard(g node.ExitDNSGuardConfig) node.ExitDNSGuardConfig {
	if err := validExitDNSGuard(g); err != nil {
		r.logger.Warn("saved exit DNS guard settings are not usable; defaults are used", "error", err.Error())
		return node.ExitDNSGuardConfig{}
	}
	return cloneExitDNSGuard(g)
}

// --- local API (panel.ExitDNSDiagnostics) ---

// DiagExitDNS implements panel.ExitDNSDiagnostics.
func (d *EngineDiag) DiagExitDNS() (panel.ExitDNSReply, error) {
	return panel.ExitDNSStatus(d.now()), nil
}

// DiagExitDNSAllow implements panel.ExitDNSDiagnostics.
func (d *EngineDiag) DiagExitDNSAllow(name string, dur time.Duration) (node.ExitDNSException, error) {
	if _, err := d.engine(); err != nil {
		return node.ExitDNSException{}, err
	}
	return node.ExitDNSAllowFor(name, dur, d.now())
}

// DiagExitDNSRevoke implements panel.ExitDNSDiagnostics.
func (d *EngineDiag) DiagExitDNSRevoke(name string) error {
	if !node.ExitDNSRevokeException(name) {
		return fmt.Errorf("%s için süreli istisna yok", name)
	}
	return nil
}

// DiagExitDNSLog implements panel.ExitDNSDiagnostics.
func (d *EngineDiag) DiagExitDNSLog() (panel.ExitDNSLogReply, error) {
	return panel.ExitDNSLogNow(d.now()), nil
}

// DiagExitDNSSetLog implements panel.ExitDNSDiagnostics.
func (d *EngineDiag) DiagExitDNSSetLog(dur time.Duration) (panel.ExitDNSLogReply, error) {
	if dur > 0 {
		if _, err := d.engine(); err != nil {
			return panel.ExitDNSLogReply{}, err
		}
	}
	if _, err := node.SetExitDNSQueryLog(dur, d.now()); err != nil {
		return panel.ExitDNSLogReply{}, err
	}
	return panel.ExitDNSLogNow(d.now()), nil
}

// DiagExitDNS implements panel.ExitDNSDiagnostics.
func (r *Runtime) DiagExitDNS() (panel.ExitDNSReply, error) { return r.engineDiag().DiagExitDNS() }

// DiagExitDNSAllow implements panel.ExitDNSDiagnostics.
func (r *Runtime) DiagExitDNSAllow(name string, dur time.Duration) (node.ExitDNSException, error) {
	ex, err := r.engineDiag().DiagExitDNSAllow(name, dur)
	if err != nil {
		return ex, err
	}
	r.auditLocal("exit_dns_exception", fmt.Sprintf("Engel listesinde süreli istisna: %s, %s saatine kadar", ex.Name, ex.Until.Local().Format("15:04")))
	return ex, nil
}

// DiagExitDNSRevoke implements panel.ExitDNSDiagnostics.
func (r *Runtime) DiagExitDNSRevoke(name string) error {
	if err := r.engineDiag().DiagExitDNSRevoke(name); err != nil {
		return err
	}
	r.auditLocal("exit_dns_exception_revoked", "Süreli DNS istisnası kapatıldı: "+name)
	return nil
}

// DiagExitDNSLog implements panel.ExitDNSDiagnostics.
func (r *Runtime) DiagExitDNSLog() (panel.ExitDNSLogReply, error) {
	return r.engineDiag().DiagExitDNSLog()
}

// DiagExitDNSSetLog implements panel.ExitDNSDiagnostics. Turning the log
// on or off is audited; the entries never are (ADR-0008).
func (r *Runtime) DiagExitDNSSetLog(dur time.Duration) (panel.ExitDNSLogReply, error) {
	rep, err := r.engineDiag().DiagExitDNSSetLog(dur)
	if err != nil {
		return rep, err
	}
	if dur > 0 {
		r.auditLocal("exit_dns_log_on", "Çıkış DNS sorgu günlüğü açıldı (yalnızca bellekte): "+dur.String())
	} else {
		r.auditLocal("exit_dns_log_off", "Çıkış DNS sorgu günlüğü kapatıldı ve silindi")
	}
	return rep, nil
}

// exitDNSThreatText describes the resolver's detections; ok is false for
// other kinds.
func exitDNSThreatText(k string, peer string, count int) (string, bool) {
	switch k {
	case string(node.ThreatDNSRateLimit):
		return fmt.Sprintf("%s çıkış çözücüsüne saniyede %d sorgu sınırını aştı", peer, count), true
	case string(node.ThreatDNSTunnel):
		return fmt.Sprintf("%s bir dakikada %d uzun ve rastgele alt adlı sorgu yaptı (olası DNS tünelleme)", peer, count), true
	}
	return "", false
}
