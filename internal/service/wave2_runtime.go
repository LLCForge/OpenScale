package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/dohcheck"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
)

// Connection wave 2 glue of the desktop service (ADR-0110): the panel
// interfaces of the remote desktop, sync, traffic shaping and threat
// detection, and the health alerts they add.

type rdeskEvent = rdesk.SessionEvent

// wave2Runtime is the wave 2 state of Runtime.
type wave2Runtime struct {
	once   sync.Once
	helper *helperHost

	mu      sync.Mutex
	dohAt   time.Time
	doh     []dohcheck.Finding
	dohErr  string
	threats []filter.ThreatEvent
}

const (
	dohRescan         = 10 * time.Minute
	maxKeptThreats    = 64
	threatAlertWindow = time.Hour
)

var (
	_ panel.RemoteDesktopControl   = (*Runtime)(nil)
	_ panel.RemoteDesktopHelperAPI = (*Runtime)(nil)
	_ panel.SyncControl            = (*Runtime)(nil)
	_ panel.TrafficControl         = (*Runtime)(nil)
	_ panel.GuardControl           = (*Runtime)(nil)
)

// --- remote desktop ---

// RDeskStatus implements panel.RemoteDesktopControl.
func (r *Runtime) RDeskStatus() panel.RDeskStatus {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.RDeskStatus{Error: err.Error(), Sessions: []panel.RDeskSession{}, Recent: []panel.RDeskSession{}}
	}
	st := a.RDeskStatus()
	if h := r.helperHost(); h != nil && st.Error == "" {
		st.Error = h.lastError()
	}
	return st
}

// SetRDeskSettings implements panel.RemoteDesktopControl.
func (r *Runtime) SetRDeskSettings(c panel.RDeskSettingsChange) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	if err := a.SetRDeskSettings(c); err != nil {
		return err
	}
	r.auditLocal("rdesk_settings_changed", "Uzak masaüstü ayarları değiştirildi (kayıt, karartma veya yeniden başlatma).")
	return nil
}

// RDeskHelperAllowed implements panel.RemoteDesktopHelperAPI.
func (r *Runtime) RDeskHelperAllowed(token, remote, local string) bool {
	h := r.helperHost()
	return h != nil && h.Allowed(token, remote, local)
}

// RDeskHelperAuthorize implements panel.RemoteDesktopHelperAPI.
func (r *Runtime) RDeskHelperAuthorize(remote netip.Addr, mode string) panel.RDeskHelperDecision {
	if h := r.helperHost(); h != nil {
		return h.Authorize(remote, mode)
	}
	return panel.RDeskHelperDecision{Reason: "desteklenmiyor"}
}

// RDeskHelperState implements panel.RemoteDesktopHelperAPI.
func (r *Runtime) RDeskHelperState() panel.RDeskHelperState {
	if h := r.helperHost(); h != nil {
		return h.State()
	}
	return panel.RDeskHelperState{Stop: true}
}

// RDeskHelperEvent implements panel.RemoteDesktopHelperAPI.
func (r *Runtime) RDeskHelperEvent(ev panel.RDeskHelperEvent) {
	if h := r.helperHost(); h != nil {
		h.Event(ev)
	}
}

// RDeskHelperPower implements panel.RemoteDesktopHelperAPI.
func (r *Runtime) RDeskHelperPower(req panel.RDeskHelperPower) error {
	h := r.helperHost()
	if h == nil {
		return errors.New("desteklenmiyor")
	}
	if err := h.Power(req); err != nil {
		return err
	}
	r.auditLocal("rdesk_restart", "Uzak masaüstü oturumu bu bilgisayarı yeniden başlattı: "+req.Peer)
	return nil
}

// --- sync ---

func (r *Runtime) syncApps() (*Apps, error) { return r.appsOrErr() }

// SyncStatus implements panel.SyncControl.
func (r *Runtime) SyncStatus() panel.SyncStatus {
	a, err := r.syncApps()
	if err != nil {
		return panel.SyncStatus{Error: err.Error(), Folders: []panel.SyncFolderView{}, BackupTargets: []string{}, Outbox: []panel.OutboxView{}}
	}
	return a.SyncStatus()
}

// SetSyncFolder implements panel.SyncControl.
func (r *Runtime) SetSyncFolder(c panel.SyncFolderChange) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	if err := a.SetSyncFolder(c); err != nil {
		return err
	}
	r.auditLocal("sync_folder_changed", "Eşitleme klasörü kaydedildi: "+c.ID)
	return nil
}

// RemoveSyncFolder implements panel.SyncControl.
func (r *Runtime) RemoveSyncFolder(id string) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	return a.RemoveSyncFolder(id)
}

// SyncNow implements panel.SyncControl.
func (r *Runtime) SyncNow(ctx context.Context) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	return a.SyncNow(ctx)
}

// SyncVersions implements panel.SyncControl.
func (r *Runtime) SyncVersions(id string) ([]panel.SyncVersionView, error) {
	a, err := r.syncApps()
	if err != nil {
		return nil, err
	}
	return a.SyncVersions(id)
}

// RestoreSyncVersion implements panel.SyncControl.
func (r *Runtime) RestoreSyncVersion(id, stored string) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	return a.RestoreSyncVersion(id, stored)
}

// SetSyncBackup implements panel.SyncControl.
func (r *Runtime) SetSyncBackup(c panel.SyncBackupChange) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	if err := a.SetSyncBackup(c); err != nil {
		return err
	}
	r.auditLocal("backup_schedule_changed", "Şifreli yedek ayarı değiştirildi.")
	return nil
}

// ExportBackupKey implements panel.SyncControl.
func (r *Runtime) ExportBackupKey(passphrase []byte) (string, error) {
	a, err := r.syncApps()
	if err != nil {
		return "", err
	}
	text, err := a.ExportBackupKey(passphrase)
	if err == nil {
		r.auditLocal("backup_key_exported", "Yedek anahtarı parolayla dışa aktarıldı.")
	}
	return text, err
}

// BackupNow implements panel.SyncControl.
func (r *Runtime) BackupNow(ctx context.Context) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	return a.BackupNow(ctx)
}

// BackupSnapshots implements panel.SyncControl.
func (r *Runtime) BackupSnapshots(ctx context.Context) ([]panel.SyncSnapshotView, error) {
	a, err := r.syncApps()
	if err != nil {
		return nil, err
	}
	return a.BackupSnapshots(ctx)
}

// QueueFile implements panel.SyncControl.
func (r *Runtime) QueueFile(device, name string, body io.Reader, size int64, strip string) (string, error) {
	a, err := r.syncApps()
	if err != nil {
		return "", err
	}
	return a.QueueFile(device, name, body, size, strip)
}

// RemoveOutbox implements panel.SyncControl.
func (r *Runtime) RemoveOutbox(id string) error {
	a, err := r.syncApps()
	if err != nil {
		return err
	}
	return a.RemoveOutbox(id)
}

// --- traffic shaping (P20) ---

func (r *Runtime) liveEngine() *node.Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engine
}

// TrafficStatus implements panel.TrafficControl.
func (r *Runtime) TrafficStatus() panel.TrafficStatus {
	st, _ := r.currentSettings()
	t := st.tunnel()
	out := panel.TrafficStatus{Settings: panel.TrafficSettings{PortMap: t.PortMap, PortMapDisable: append([]string{}, t.PortMapDisable...),
		Padding: orOff(t.Padding), CoverTraffic: t.CoverTraffic, InteractivePriority: t.InteractivePriority, TorSOCKS: t.TorSOCKS}}
	if c, err := panel.ComputeTrafficCost(out.Settings.Padding, t.CoverTraffic, st.MTU); err == nil {
		out.Cost = c
	}
	if e := r.liveEngine(); e != nil {
		pm, sh := TrafficViews(e)
		out.PortMap, out.Shaping, out.TorActive = &pm, &sh, e.TorActive()
	}
	return out
}

// TrafficViews converts the engine's port mapping and shaping state.
func TrafficViews(e *node.Engine) (panel.PortMapView, panel.ShapingView) {
	s := e.PortMapStatus()
	pm := panel.PortMapView{Enabled: s.Enabled, Active: s.Active, Protocol: s.Protocol, LastError: s.LastError}
	if s.External.IsValid() {
		pm.External = s.External.String()
	}
	if !s.RenewAt.IsZero() {
		t := s.RenewAt
		pm.RenewAt = &t
	}
	ts := e.TrafficShaping()
	sh := panel.ShapingView{Padding: orOff(PaddingName(ts.Padding)), PaddedPackets: ts.PaddedPackets, PaddingBytes: ts.PaddingBytes,
		CoverRate: ts.CoverRate, CoverPackets: ts.CoverPackets, CoverBytes: ts.CoverBytes, InteractivePriority: ts.InteractivePriority}
	return pm, sh
}

// SetTraffic implements panel.TrafficControl through the same checked
// path as "openscale set".
func (r *Runtime) SetTraffic(c panel.TrafficChange) error {
	change := map[string]string{}
	if c.PortMap != nil {
		change["port-map"] = strconv.FormatBool(*c.PortMap)
	}
	if c.PortMapDisable != nil {
		change["port-map-disable"] = strings.Join(*c.PortMapDisable, ",")
	}
	if c.Padding != nil {
		change["padding"] = orOff(*c.Padding)
	}
	if c.CoverTraffic != nil {
		change["cover-traffic"] = strconv.Itoa(*c.CoverTraffic)
	}
	if c.InteractivePriority != nil {
		change["interactive-priority"] = strconv.FormatBool(*c.InteractivePriority)
	}
	if c.TorSOCKS != nil {
		change["tor-socks"] = strings.TrimSpace(*c.TorSOCKS)
	}
	if len(change) == 0 {
		return nil
	}
	_, err := r.DiagSetPrefs(change)
	return err
}

// --- resolver and threat detection (P21) ---

// onThreat is node.Config.OnThreat: the event goes to the event list, the
// audit log and the health alerts.
func (r *Runtime) onThreat(ev filter.ThreatEvent) {
	r.w2.mu.Lock()
	r.w2.threats = append(r.w2.threats, ev)
	if len(r.w2.threats) > maxKeptThreats {
		r.w2.threats = r.w2.threats[len(r.w2.threats)-maxKeptThreats:]
	}
	r.w2.mu.Unlock()
	msg := ThreatText(ev)
	r.logger.Warn("threat detected", "kind", string(ev.Kind), "peer", ev.Peer, "count", ev.Count)
	r.eventLog().Add(panel.DiagEvent{At: r.cfg.Now(), Kind: "threat_detected", Peer: ev.Peer, Message: msg})
	r.observer().Security("threat_detected", audit.SeverityWarning, panel.CategorySecurity, ev.Peer, msg, true)
}

// ThreatText describes a detection in Turkish.
func ThreatText(ev filter.ThreatEvent) string {
	var s string
	switch ev.Kind {
	case filter.ThreatInboundScan:
		s = fmt.Sprintf("%s bu cihazda %d farklı porta bağlanmayı denedi (port taraması)", ev.Peer, ev.Count)
	case filter.ThreatOutboundScan:
		s = fmt.Sprintf("Bu cihazdaki bir program %d farklı cihaza bağlanmayı denedi (ağ taraması)", ev.Count)
	case filter.ThreatCanaryAddress:
		s = "Hiçbir cihazın kullanmadığı tuzak adrese (" + ev.Canary + ") erişim denendi"
		if ev.Peer != "" {
			s += ": " + ev.Peer
		}
	case filter.ThreatCanaryPort:
		s = fmt.Sprintf("%s tuzak porta (%d) bağlanmayı denedi", ev.Peer, ev.Port)
	default:
		s = "Tehdit algılandı: " + string(ev.Kind)
		if t, ok := exitDNSThreatText(string(ev.Kind), ev.Peer, ev.Count); ok { // P05
			s = t
		}
	}
	if !ev.BlockedUntil.IsZero() {
		s += "; yeni bağlantıları " + ev.BlockedUntil.Local().Format("15:04") + " saatine kadar reddediliyor"
	}
	return s + "."
}

func guardSettingsOf(t tunnelOptions) panel.GuardSettings {
	g := panel.GuardSettings{ExitDNSUpstream: t.ExitDNSUpstream, ExitDNSBlocklist: t.ExitDNSBlocklist, DNSSECTrustAnchors: t.DNSSECTrustAnchors,
		ThreatScan: !t.Threats.DisableScan, ThreatBlock: !t.Threats.DisableBlock, BlockForSec: int64(t.Threats.BlockFor / time.Second), CanaryPorts: []int{}}
	for _, p := range t.Threats.CanaryPorts {
		g.CanaryPorts = append(g.CanaryPorts, int(p))
	}
	return g
}

// GuardViews converts the engine's threat state.
func GuardViews(e *node.Engine) ([]panel.ThreatView, []panel.BlockedPeer) {
	threats := []panel.ThreatView{}
	for _, ev := range e.ThreatEvents() {
		v := panel.ThreatView{Kind: string(ev.Kind), Peer: ev.Peer, Count: ev.Count, Port: int(ev.Port), Canary: ev.Canary, At: ev.At}
		if !ev.BlockedUntil.IsZero() {
			t := ev.BlockedUntil
			v.BlockedUntil = &t
		}
		threats = append(threats, v)
	}
	blocked := []panel.BlockedPeer{}
	for name, until := range e.BlockedPeers() {
		blocked = append(blocked, panel.BlockedPeer{Peer: name, Until: until})
	}
	slices.SortFunc(blocked, func(a, b panel.BlockedPeer) int { return strings.Compare(a.Peer, b.Peer) })
	return threats, blocked
}

// DNSSECView returns the validation counters.
func DNSSECView() panel.DNSSECView {
	s, i, b := node.DNSSECStats()
	return panel.DNSSECView{Secure: s, Insecure: i, Bogus: b}
}

// GuardStatus implements panel.GuardControl.
func (r *Runtime) GuardStatus() panel.GuardStatus {
	st, _ := r.currentSettings()
	out := panel.GuardStatus{Settings: guardSettingsOf(st.tunnel()), DNSSEC: DNSSECView(), Threats: []panel.ThreatView{}, Blocked: []panel.BlockedPeer{}}
	if e := r.liveEngine(); e != nil {
		out.Running = true
		out.Threats, out.Blocked = GuardViews(e)
	}
	return out
}

// SetGuards implements panel.GuardControl.
func (r *Runtime) SetGuards(c panel.GuardChange) error {
	change := map[string]string{}
	if c.ExitDNSUpstream != nil {
		change["exit-dns-upstream"] = strings.TrimSpace(*c.ExitDNSUpstream)
	}
	if c.ExitDNSBlocklist != nil {
		change["exit-dns-blocklist"] = strings.TrimSpace(*c.ExitDNSBlocklist)
	}
	if c.DNSSECTrustAnchors != nil {
		change["dnssec-trust-anchors"] = strings.TrimSpace(*c.DNSSECTrustAnchors)
	}
	if c.ThreatScan != nil {
		change["threat-scan"] = strconv.FormatBool(*c.ThreatScan)
	}
	if c.ThreatBlock != nil {
		change["threat-block"] = strconv.FormatBool(*c.ThreatBlock)
	}
	if c.BlockForSec != nil {
		if *c.BlockForSec < 0 {
			return errors.New("engelleme süresi negatif olamaz")
		}
		change["threat-block-for"] = (time.Duration(*c.BlockForSec) * time.Second).String()
	}
	if c.CanaryPorts != nil {
		ps := make([]string, 0, len(*c.CanaryPorts))
		for _, p := range *c.CanaryPorts {
			ps = append(ps, strconv.Itoa(p))
		}
		change["canary-ports"] = strings.Join(ps, ",")
	}
	if len(change) == 0 {
		return nil
	}
	_, err := r.DiagSetPrefs(change)
	return err
}

// UnblockPeer implements panel.GuardControl.
func (r *Runtime) UnblockPeer(name string) error {
	e := r.liveEngine()
	if e == nil {
		return ErrTunnelNotRunning
	}
	e.UnblockPeer(name)
	r.auditLocal("peer_unblocked", "Tarama nedeniyle engellenen cihazın engeli kaldırıldı: "+name)
	return nil
}

// DoHScan implements panel.GuardControl: the browsers of the user at the
// console (the service's own profile has none) are checked for DNS over
// HTTPS settings that bypass MagicDNS and the exit node's resolver.
func (r *Runtime) DoHScan(ctx context.Context) ([]panel.DoHFinding, error) {
	found, err := r.scanDoH(ctx, true)
	out := make([]panel.DoHFinding, 0, len(found))
	for _, f := range found {
		out = append(out, panel.DoHFinding{Browser: f.Browser, Profile: f.Profile, Mode: f.Mode, Resolver: f.Resolver, Bypass: f.Bypass})
	}
	return out, err
}

func (r *Runtime) scanDoH(ctx context.Context, force bool) ([]dohcheck.Finding, error) {
	r.w2.mu.Lock()
	if !force && !r.w2.dohAt.IsZero() && r.cfg.Now().Sub(r.w2.dohAt) < dohRescan {
		out, errText := slices.Clone(r.w2.doh), r.w2.dohErr
		r.w2.mu.Unlock()
		if errText != "" {
			return out, errors.New(errText)
		}
		return out, nil
	}
	r.w2.mu.Unlock()
	type result struct {
		f   []dohcheck.Finding
		err error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := dohcheck.ScanDirs(consoleUserDirs())
		ch <- result{f, err}
	}()
	var res result
	select {
	case res = <-ch:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.w2.mu.Lock()
	r.w2.dohAt, r.w2.doh, r.w2.dohErr = r.cfg.Now(), res.f, ""
	if res.err != nil {
		r.w2.dohErr = res.err.Error()
	}
	r.w2.mu.Unlock()
	return res.f, res.err
}

// guardAlertsLocked adds the resolver and threat alerts; called with r.mu
// held (it only reads r.engine and its own state).
func (r *Runtime) guardAlertsLocked(now time.Time) []panel.HealthAlert {
	var out []panel.HealthAlert
	if _, _, bogus := node.DNSSECStats(); bogus > 0 {
		out = append(out, panel.HealthAlert{Code: panel.HealthDNSSECBogus, Level: panel.LevelWarning,
			Message: fmt.Sprintf("DNSSEC doğrulaması %d yanıtı reddetti (sahte veya bozuk imza). Çıkış düğümünün üst çözücüsünü denetleyin.", bogus)})
	}
	r.w2.mu.Lock()
	var recent []filter.ThreatEvent
	for _, ev := range r.w2.threats {
		if now.Sub(ev.At) < threatAlertWindow {
			recent = append(recent, ev)
		}
	}
	doh := slices.Clone(r.w2.doh)
	r.w2.mu.Unlock()
	if len(recent) > 0 {
		out = append(out, panel.HealthAlert{Code: panel.HealthThreatDetected, Level: panel.LevelDanger,
			Message: ThreatText(recent[len(recent)-1]) + " Ayrıntı: Tanılama > Tehditler."})
	}
	for _, f := range doh {
		if f.Bypass {
			out = append(out, panel.HealthAlert{Code: panel.HealthDoHBypass, Level: panel.LevelInfo,
				Message: f.Browser + " tarayıcısı DNS'i kendi DoH sunucusuna gönderiyor; MagicDNS adları ve çıkış düğümü çözücüsü atlanıyor. Tarayıcının güvenli DNS ayarını kapatın veya sistem çözücüsünü seçin."})
			break
		}
	}
	return out
}

// refreshDoH keeps the browser check fresh for the health alerts.
func (r *Runtime) refreshDoH(ctx context.Context) {
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, _ = r.scanDoH(sctx, false)
}

// wave2Loop keeps the browser DNS check fresh while the service runs.
func (r *Runtime) wave2Loop(ctx context.Context) {
	t := time.NewTicker(dohRescan)
	defer t.Stop()
	for {
		r.refreshDoH(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// diagTraffic is the traffic part of the status.
func diagTraffic(e *node.Engine) *panel.DiagTraffic {
	pm, sh := TrafficViews(e)
	return &panel.DiagTraffic{PortMap: pm, Shaping: sh, TorActive: e.TorActive()}
}

// DiagThreats implements panel.ThreatDiagnostics.
func (d *EngineDiag) DiagThreats() (panel.ThreatsReply, error) {
	rep := panel.ThreatsReply{Schema: panel.DiagSchema, DNSSEC: DNSSECView(), Threats: []panel.ThreatView{}, Blocked: []panel.BlockedPeer{}}
	e, err := d.engine()
	if err != nil {
		return rep, err
	}
	rep.Threats, rep.Blocked = GuardViews(e)
	return rep, nil
}

// DiagUnblock implements panel.ThreatDiagnostics.
func (d *EngineDiag) DiagUnblock(peer string) error {
	e, err := d.engine()
	if err != nil {
		return err
	}
	e.UnblockPeer(peer)
	return nil
}

// DiagThreats implements panel.ThreatDiagnostics.
func (r *Runtime) DiagThreats() (panel.ThreatsReply, error) { return r.engineDiag().DiagThreats() }

// DiagUnblock implements panel.ThreatDiagnostics.
func (r *Runtime) DiagUnblock(peer string) error {
	if err := r.engineDiag().DiagUnblock(peer); err != nil {
		return err
	}
	r.auditLocal("peer_unblocked", "Tarama nedeniyle engellenen cihazın engeli kaldırıldı: "+peer)
	return nil
}
