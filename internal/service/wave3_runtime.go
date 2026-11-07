package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/netprofile"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// Connection wave 3: the automatic exit node of the desktop service
// (ADR-0133, #79, #80, #81), the coordinator list and integrity alerts
// (ADR-0111) and the network profile the service runs (ADR-0135).

// exitAutoFile keeps the automatic exit node settings next to
// settings.json; a missing file is "off", so older installations keep
// their behaviour.
const (
	exitAutoFile    = "exit-auto.json"
	maxExitAutoSize = 16 << 10
)

// wave3Runtime is the service state of connection wave 3.
type wave3Runtime struct {
	applyMu sync.Mutex
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	engine  *node.Engine
	ctx     context.Context
	exit    string
	reason  string
	since   time.Time
	// nets is the last network list read for the trust decision.
	nets []string
}

// loadExitAuto reads the saved settings; a missing file is off.
func loadExitAuto(dir string) (panel.ExitAutoSettings, error) {
	var s panel.ExitAutoSettings
	data, err := securefile.ReadPrivate(filepath.Join(dir, exitAutoFile), maxExitAutoSize)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return panel.ExitAutoSettings{}, errors.New("otomatik çıkış ayar dosyası bozuk")
	}
	return NormalizeExitAuto(s)
}

func saveExitAuto(dir string, s panel.ExitAutoSettings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, exitAutoFile), data)
}

// NormalizeExitAuto validates the settings and returns them cleaned up:
// lists trimmed, deduplicated and bounded, ranges in canonical form.
func NormalizeExitAuto(s panel.ExitAutoSettings) (panel.ExitAutoSettings, error) {
	out := panel.ExitAutoSettings{Untrusted: s.Untrusted, TrustWired: s.TrustWired}
	switch m := strings.TrimSpace(s.Mode); m {
	case panel.ExitAutoModeOff, panel.ExitAutoFailover, panel.ExitAutoFastest:
		out.Mode = m
	default:
		return out, errors.New("otomatik seçim kipi failover, fastest veya boş olmalı")
	}
	if len(s.Candidates) > panel.MaxExitCandidates {
		return out, fmt.Errorf("en fazla %d aday çıkış düğümü seçilebilir", panel.MaxExitCandidates)
	}
	for _, c := range s.Candidates {
		c = strings.TrimSpace(c)
		if c == "" || len(c) > 63 || strings.ContainsFunc(c, unicode.IsControl) {
			return out, fmt.Errorf("aday çıkış düğümü adı geçersiz: %q", c)
		}
		if !slices.Contains(out.Candidates, c) {
			out.Candidates = append(out.Candidates, c)
		}
	}
	if len(s.TrustedWiFi) > panel.MaxTrustedWiFi {
		return out, fmt.Errorf("en fazla %d güvenilir Wi-Fi adı yazılabilir", panel.MaxTrustedWiFi)
	}
	for _, n := range s.TrustedWiFi {
		if n == "" || len(n) > panel.MaxTrustedWiFiLen || strings.ContainsFunc(n, unicode.IsControl) {
			return out, errors.New("Wi-Fi adı 1-128 bayt olmalı ve kontrol karakteri içermemeli")
		}
		if !slices.Contains(out.TrustedWiFi, n) {
			out.TrustedWiFi = append(out.TrustedWiFi, n)
		}
	}
	if (len(out.TrustedWiFi) > 0 || out.TrustWired) && !out.Untrusted {
		return out, errors.New("güvenilir ağ listesi yalnızca 'güvenilmeyen ağda aç' ile kullanılır")
	}
	if len(out.Candidates) > 0 && !out.Enabled() {
		return out, errors.New("aday listesi yalnızca otomatik seçim açıkken kullanılır")
	}
	if len(s.Except) > panel.MaxExitExceptions {
		return out, fmt.Errorf("en fazla %d istisna aralığı yazılabilir", panel.MaxExitExceptions)
	}
	for _, e := range s.Except {
		p, err := netip.ParsePrefix(strings.TrimSpace(e))
		if err != nil || !p.Addr().Is4() {
			return out, fmt.Errorf("istisna %q geçerli bir IPv4 CIDR aralığı değil", e)
		}
		if p.Bits() == 0 {
			return out, errors.New("istisna bütün interneti kapsayamaz")
		}
		v := p.Masked().String()
		if !slices.Contains(out.Except, v) {
			out.Except = append(out.Except, v)
		}
	}
	return out, nil
}

// trust returns the network trust list, or nil when the exit node is not
// tied to untrusted networks.
func exitAutoTrust(s panel.ExitAutoSettings) *osnet.NetworkTrust {
	if !s.Untrusted {
		return nil
	}
	return &osnet.NetworkTrust{Trusted: slices.Clone(s.TrustedWiFi), TrustWired: s.TrustWired}
}

// startWave3 runs with each tunnel start: it applies the exit exceptions
// and starts the automatic exit node choice. Both end with ctx.
func (r *Runtime) startWave3(ctx context.Context, engine *node.Engine) {
	r.w3.mu.Lock()
	r.w3.ctx, r.w3.engine = ctx, engine
	r.w3.mu.Unlock()
	r.applyWave3()
}

// applyWave3 (re)applies the saved settings to the running engine.
func (r *Runtime) applyWave3() {
	// applyMu serializes appliers; w3.mu is never held while waiting for
	// the running choice, whose callbacks take it.
	r.w3.applyMu.Lock()
	defer r.w3.applyMu.Unlock()
	r.w3.mu.Lock()
	oldCancel, oldDone := r.w3.cancel, r.w3.done
	r.w3.cancel, r.w3.done = nil, nil
	r.w3.mu.Unlock()
	if oldCancel != nil {
		oldCancel()
		<-oldDone
	}
	r.w3.mu.Lock()
	r.w3.exit, r.w3.reason, r.w3.since, r.w3.nets = "", "", time.Time{}, nil
	engine, parent := r.w3.engine, r.w3.ctx
	r.w3.mu.Unlock()
	if engine == nil || parent == nil || parent.Err() != nil {
		return
	}
	s, err := loadExitAuto(r.cfg.DataDir)
	if err != nil {
		r.logger.Warn("automatic exit node settings are not usable", "error", err.Error())
		return
	}
	var prefixes []netip.Prefix
	for _, e := range s.Except {
		if p, err := netip.ParsePrefix(e); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	if err := engine.SetExitExceptions(prefixes); err != nil {
		r.logger.Warn("exit exceptions not applied", "error", err.Error())
	}
	if !s.Enabled() {
		return
	}
	mode := s.Mode
	if mode == "" {
		mode = node.ExitModeFailover
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	r.w3.mu.Lock()
	r.w3.cancel, r.w3.done = cancel, done
	r.w3.mu.Unlock()
	networks := func() ([]osnet.CurrentNetwork, error) {
		nets, err := osnet.CurrentNetworks()
		names := make([]string, 0, len(nets))
		for _, n := range nets {
			names = append(names, n.Kind+": "+n.Name)
		}
		r.w3.mu.Lock()
		r.w3.nets = names
		r.w3.mu.Unlock()
		return nets, err
	}
	go func() {
		defer close(done)
		engine.RunExitAuto(ctx, node.ExitAutoConfig{
			Candidates: s.Candidates,
			Mode:       mode,
			Untrusted:  exitAutoTrust(s),
			Networks:   networks,
			OnChange: func(exit, reason string) {
				r.w3.mu.Lock()
				r.w3.exit, r.w3.reason, r.w3.since = exit, reason, r.cfg.Now()
				r.w3.mu.Unlock()
				r.logger.Info("automatic exit node", "exit", exit)
			},
		})
	}()
}

// ExitAuto implements panel.Wave3App.
func (r *Runtime) ExitAuto() (panel.ExitAutoState, error) {
	s, err := loadExitAuto(r.cfg.DataDir)
	if err != nil {
		return panel.ExitAutoState{}, err
	}
	st := r.exitAutoState(s)
	return st, nil
}

func (r *Runtime) exitAutoState(s panel.ExitAutoSettings) panel.ExitAutoState {
	st := panel.ExitAutoState{Settings: s, Networks: []string{}}
	if st.Settings.Candidates == nil {
		st.Settings.Candidates = []string{}
	}
	if st.Settings.TrustedWiFi == nil {
		st.Settings.TrustedWiFi = []string{}
	}
	if st.Settings.Except == nil {
		st.Settings.Except = []string{}
	}
	r.w3.mu.Lock()
	defer r.w3.mu.Unlock()
	st.Exit, st.Reason = r.w3.exit, r.w3.reason
	if !r.w3.since.IsZero() {
		t := r.w3.since
		st.Since = &t
	}
	st.Networks = append(st.Networks, r.w3.nets...)
	return st
}

// SetExitAuto implements panel.Wave3App: it validates, saves and applies
// the settings to the running tunnel.
func (r *Runtime) SetExitAuto(s panel.ExitAutoSettings) error {
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	s, err := NormalizeExitAuto(s)
	if err != nil {
		return err
	}
	if s.Enabled() && r.cfg.Hooks.ExitRouter == nil {
		return errors.New("bu sistemde çıkış düğümü kullanılamıyor")
	}
	if err := saveExitAuto(r.cfg.DataDir, s); err != nil {
		return err
	}
	r.applyWave3()
	if !s.Enabled() {
		// Back to the manual choice saved in settings.json.
		r.settingsMu.Lock()
		st, err := loadSettings(r.cfg.DataDir)
		r.settingsMu.Unlock()
		if err == nil {
			r.mu.Lock()
			e := r.engine
			r.mu.Unlock()
			if e != nil {
				if err := e.SetExitNode(st.ExitNode); err != nil {
					r.logger.Warn("manual exit node not restored", "error", err.Error())
				}
			}
		}
	}
	r.logger.Info("automatic exit node settings", "mode", s.Mode, "untrusted", s.Untrusted, "candidates", len(s.Candidates), "exceptions", len(s.Except))
	return nil
}

// wave3StatusLocked fills DeviceStatus.Wave3; called with r.mu held.
func (r *Runtime) wave3StatusLocked() *panel.Wave3Status {
	out := &panel.Wave3Status{Coordinators: []panel.CoordinatorState{}, Integrity: []panel.IntegrityNote{}, Profiles: []panel.ProfileState{}}
	if s, err := loadExitAuto(r.cfg.DataDir); err == nil && s.Enabled() {
		st := r.exitAutoState(s)
		out.ExitAuto = &st
	}
	if r.engine != nil {
		for _, c := range r.engine.Coordinators() {
			cs := panel.CoordinatorState{Name: c.Name, Region: c.Region, Fingerprint: c.Fingerprint, Endpoint: c.Endpoint,
				Primary: c.Primary, Active: c.Active, Relay: c.Relay, RTTMillis: c.RTT.Milliseconds(), Failures: c.Failures}
			if !c.Until.IsZero() {
				t := c.Until
				cs.Until = &t
			}
			if !c.LastReply.IsZero() {
				t := c.LastReply
				cs.LastReply = &t
			}
			out.Coordinators = append(out.Coordinators, cs)
		}
		for _, f := range r.engine.CoordinatorIntegrity().Findings {
			out.Integrity = append(out.Integrity, panel.IntegrityNote{Severity: f.Severity, Coordinator: f.Coordinator, Peer: f.Peer, Text: f.Text, Verified: f.Verified})
		}
	}
	out.Profile, out.Profiles = r.profiles()
	return out
}

// wave3AlertsLocked turns integrity findings into health alerts; called
// with r.mu held.
func (r *Runtime) wave3AlertsLocked() []panel.HealthAlert {
	if r.engine == nil {
		return nil
	}
	var out []panel.HealthAlert
	for _, f := range r.engine.CoordinatorIntegrity().Findings {
		level := panel.LevelWarning
		if f.Severity == "kritik" {
			level = panel.LevelDanger
		}
		msg := "Koordinatör bütünlük uyarısı: " + f.Text
		if f.Coordinator != "" {
			msg = "Koordinatör " + f.Coordinator + " bütünlük uyarısı: " + f.Text
		}
		out = append(out, panel.HealthAlert{Code: panel.HealthCoordinatorIntegrity, Level: level, Message: msg})
		if len(out) >= 5 {
			break
		}
	}
	return out
}

// profileBase is the directory whose profiles the service can run: the
// device state directory, its "networks" subdirectory holding the others
// (ADR-0135).
func (r *Runtime) profileBase() string {
	return filepath.Join(r.cfg.DataDir, DeviceDir)
}

// activeProfileDir returns the device state directory of the active
// profile. A damaged pointer or a profile that has not joined falls back
// to the default directory, which is what the service used before
// profiles existed. "network switch" only points at joined profiles.
func (r *Runtime) activeProfileDir() string {
	base := r.profileBase()
	name, err := netprofile.Active(base)
	if err != nil || name == netprofile.DefaultName {
		return base
	}
	dir, err := netprofile.Resolve(base, name, false)
	if err != nil {
		return base
	}
	return dir
}

// devicePath maps a path under DeviceDir to the active profile.
func (r *Runtime) devicePath(parts []string) (string, bool) {
	if len(parts) == 0 || parts[0] != DeviceDir {
		return "", false
	}
	dir := r.activeProfileDir()
	if dir == r.profileBase() {
		return "", false
	}
	return filepath.Join(append([]string{dir}, parts[1:]...)...), true
}

func (r *Runtime) profiles() (string, []panel.ProfileState) {
	list, err := netprofile.List(r.profileBase())
	out := []panel.ProfileState{}
	active := netprofile.DefaultName
	if err != nil && len(list) == 0 {
		return active, out
	}
	for _, p := range list {
		out = append(out, panel.ProfileState{Name: p.Name, DisplayName: p.DisplayName, Active: p.Active, Joined: p.Joined})
		if p.Active {
			active = p.Name
		}
	}
	return active, out
}

// SwitchProfile implements panel.Wave3App: it makes another joined
// profile active and restarts the tunnel on it.
func (r *Runtime) SwitchProfile(name string) error {
	if err := netprofile.ValidName(name); err != nil {
		return errors.New("geçersiz ağ profili adı")
	}
	r.mu.Lock()
	owner := r.network != nil
	r.mu.Unlock()
	if owner {
		// The owner's own network lives in the default profile; switching
		// would take the tunnel away from the network it manages.
		return errors.New("bu bilgisayar bir ağın yöneticisi; ağ profili değiştirilemez")
	}
	if err := netprofile.Switch(r.profileBase(), name); err != nil {
		switch {
		case errors.Is(err, netprofile.ErrUnknown):
			return fmt.Errorf("%q adlı ağ profili yok", name)
		case errors.Is(err, netprofile.ErrNotJoined):
			return fmt.Errorf("%q profili henüz bir ağa katılmamış", name)
		}
		return err
	}
	r.logger.Info("network profile switched", "profile", name)
	r.startDevice()
	return nil
}

var _ panel.Wave3App = (*Runtime)(nil)
