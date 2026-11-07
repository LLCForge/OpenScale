package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/edgenet"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/surface"
)

// Edge device modes and hardening (P11, ADR-0154).
//
// A mode (travel #464, game #447, metered #385) is a fixed set of
// "openscale set" preferences applied in one DiagSetPrefs call; the values
// it replaced are saved in edge.json and put back when the mode ends.
// A preference the owner changed while the mode was on is left as the
// owner set it and reported. Only one mode is on at a time.
//
// The same file holds the P11 options and whether the shield is on
// because the screen is locked (#501). Nothing here changes the trust
// document or any system setting by itself; every change goes through the
// same paths as the panel and "openscale set".

const (
	edgeFile    = "edge.json"
	maxEdgeFile = 64 << 10
	// edgeTick is how often the gateway and the metered hint are read.
	edgeTick = 30 * time.Second
	// maxEdgeAlerts bounds the alerts kept in memory.
	maxEdgeAlerts = 16
	// meteredPSKRotation: a metered link renews the post-quantum key less
	// often (the setting's allowed range is 2m-24h).
	meteredPSKRotation = "1h"
)

// edgeMode is the active mode.
type edgeMode struct {
	Name  string    `json:"name"`
	Since time.Time `json:"since"`
	// Auto names what started the mode ("metered", "lan-guard"); empty
	// when the owner did.
	Auto     string            `json:"auto,omitempty"`
	Applied  map[string]string `json:"applied,omitempty"`
	Previous map[string]string `json:"previous,omitempty"`
}

// edgeLock records that the shield was turned on by a screen lock.
type edgeLock struct {
	Since time.Time `json:"since"`
}

type edgeFileState struct {
	Options panel.EdgeOptions `json:"options"`
	Mode    *edgeMode         `json:"mode,omitempty"`
	Lock    *edgeLock         `json:"lock,omitempty"`
}

// edgeMu serializes every change of edge.json and of the preferences a
// mode owns.
var edgeMu sync.Mutex

// edgeRuntime is the in-memory part: detector, alerts, metered hint and
// the integrity result. The sources are replaced in tests.
type edgeRuntime struct {
	mu        sync.Mutex
	detector  *edgenet.Detector
	alerts    []panel.EdgeLANAlert
	metered   *bool
	integrity *Finding

	gateways  func() ([]netip.Addr, error)
	neighbors func() []edgenet.Neighbor
	network   func() string
	hint      func() (bool, bool)
}

var edgeRuntimes sync.Map // *Runtime -> *edgeRuntime

// ownSockets lists the service's sockets (tests replace it).
var ownSockets = surface.Own

func (r *Runtime) edge() *edgeRuntime {
	if v, ok := edgeRuntimes.Load(r); ok {
		return v.(*edgeRuntime)
	}
	v, _ := edgeRuntimes.LoadOrStore(r, &edgeRuntime{
		detector:  edgenet.NewDetector(),
		gateways:  osnet.DefaultGateways4,
		neighbors: edgenet.Neighbors,
		network:   currentNetworkName,
		hint:      edgenet.Metered,
	})
	return v.(*edgeRuntime)
}

// currentNetworkName names the networks this computer is on, for the
// gateway watch key (never stored or sent).
func currentNetworkName() string {
	nets, err := osnet.CurrentNetworks()
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(nets))
	for _, n := range nets {
		names = append(names, n.Kind+":"+n.Name)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

func loadEdge(dataDir string) (edgeFileState, error) {
	var st edgeFileState
	data, err := securefile.ReadPrivate(filepath.Join(dataDir, edgeFile), maxEdgeFile)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("edge.json okunamadı: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return edgeFileState{}, fmt.Errorf("edge.json bozuk: %w", err)
	}
	if st.Mode != nil && !validEdgeMode(st.Mode.Name) {
		st.Mode = nil
	}
	return st, nil
}

func saveEdge(dataDir string, st edgeFileState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dataDir, edgeFile), data)
}

func validEdgeMode(name string) bool {
	switch name {
	case panel.EdgeModeTravel, panel.EdgeModeGame, panel.EdgeModeMetered:
		return true
	}
	return false
}

// edgeModeChanges are the preferences a mode sets. Scheduled folder sync,
// backups and backup probes are held by the game and metered modes
// through edge.json (sync_p07.go, ADR-0159), not by a preference.
func edgeModeChanges(name, exit string) (map[string]string, error) {
	switch name {
	case panel.EdgeModeTravel:
		c := map[string]string{
			"kill-switch":           "true",
			"exit-allow-lan":        "false",
			"shields":               "true",
			"hide-local-candidates": "true",
			"port-map":              "false",
		}
		if exit != "" {
			c["exit-node"] = exit
		}
		return c, nil
	case panel.EdgeModeGame:
		return map[string]string{
			"padding":              "off",
			"cover-traffic":        "0",
			"force-relay":          "false",
			"interactive-priority": "true",
		}, nil
	case panel.EdgeModeMetered:
		return map[string]string{
			"padding":       "off",
			"cover-traffic": "0",
			"psk-rotation":  meteredPSKRotation,
		}, nil
	}
	return nil, fmt.Errorf("bilinmeyen kip %q; travel, game, metered veya off yazın", name)
}

func prefMap(p []panel.Pref) map[string]string {
	m := make(map[string]string, len(p))
	for _, x := range p {
		m[x.Key] = x.Value
	}
	return m
}

// EdgeStatus implements panel.EdgeApp.
func (r *Runtime) EdgeStatus() (panel.EdgeStatus, error) {
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		return panel.EdgeStatus{}, err
	}
	return r.edgeStatusOf(st), nil
}

func (r *Runtime) edgeStatusOf(st edgeFileState) panel.EdgeStatus {
	out := panel.EdgeStatus{Options: st.Options, LockShield: st.Lock != nil}
	if m := st.Mode; m != nil {
		since := m.Since
		out.Mode, out.ModeSince, out.ModeAuto = m.Name, &since, m.Auto
		for _, k := range slices.Sorted(maps.Keys(m.Applied)) {
			out.Changes = append(out.Changes, panel.EdgeChange{Key: k, From: m.Previous[k], To: m.Applied[k]})
		}
	}
	e := r.edge()
	e.mu.Lock()
	if e.metered != nil {
		v := *e.metered
		out.Metered = &v
	}
	out.LANAlerts = slices.Clone(e.alerts)
	e.mu.Unlock()
	return out
}

// EdgeSetMode implements panel.EdgeApp.
func (r *Runtime) EdgeSetMode(req panel.EdgeModeRequest) (panel.EdgeStatus, error) {
	name := strings.ToLower(strings.TrimSpace(req.Mode))
	exit := strings.TrimSpace(req.ExitNode)
	edgeMu.Lock()
	defer edgeMu.Unlock()
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		return panel.EdgeStatus{}, err
	}
	if name == panel.EdgeModeOff {
		if st.Mode == nil {
			out := r.edgeStatusOf(st)
			out.Notes = []string{"Açık bir kip yok."}
			return out, nil
		}
		notes, err := r.endModeLocked(&st)
		if err != nil {
			return panel.EdgeStatus{}, err
		}
		out := r.edgeStatusOf(st)
		out.Notes = notes
		return out, nil
	}
	if !validEdgeMode(name) {
		return panel.EdgeStatus{}, fmt.Errorf("bilinmeyen kip %q; travel, game, metered veya off yazın", req.Mode)
	}
	if exit != "" && name != panel.EdgeModeTravel {
		return panel.EdgeStatus{}, errors.New("çıkış düğümü yalnızca seyahat kipinde verilir")
	}
	notes, err := r.startModeLocked(&st, name, exit, "")
	if err != nil {
		return panel.EdgeStatus{}, err
	}
	out := r.edgeStatusOf(st)
	out.Notes = notes
	return out, nil
}

// startModeLocked applies a mode; edgeMu is held.
func (r *Runtime) startModeLocked(st *edgeFileState, name, exit, auto string) ([]string, error) {
	if st.Mode != nil {
		return nil, fmt.Errorf("%q kipi açık; önce kapatın: openscale edge mode off", st.Mode.Name)
	}
	want, err := edgeModeChanges(name, exit)
	if err != nil {
		return nil, err
	}
	before, err := r.DiagPrefs()
	if err != nil {
		return nil, err
	}
	cur := prefMap(before)
	var notes []string
	if name == panel.EdgeModeTravel && exit == "" && cur["exit-node"] == "" {
		notes = append(notes, "Çıkış düğümü seçili değil: internet trafiği bu ağdan doğrudan çıkar; kill switch yalnızca bir çıkış düğümüyle çalışır (--exit <ad>).")
	}
	change := map[string]string{}
	for k, v := range want {
		if cur[k] != v {
			change[k] = v
		}
	}
	m := &edgeMode{Name: name, Since: r.cfg.Now().UTC(), Auto: auto, Applied: map[string]string{}, Previous: map[string]string{}}
	if len(change) > 0 {
		after, err := r.DiagSetPrefs(change)
		if err != nil {
			r.undoPartial(cur, change)
			return nil, err
		}
		got := prefMap(after)
		for k := range change {
			if got[k] != cur[k] {
				m.Applied[k], m.Previous[k] = got[k], cur[k]
			}
		}
	}
	st.Mode = m
	if err := saveEdge(r.cfg.DataDir, *st); err != nil {
		// Without the saved values the mode could not be undone: undo now.
		r.undoPartial(cur, change)
		st.Mode = nil
		return nil, err
	}
	who := "sahip"
	if auto != "" {
		who = "otomatik (" + auto + ")"
	}
	r.auditLocal("edge_mode_started", fmt.Sprintf("%s kipi açıldı (%s): %s.", name, who, strings.Join(slices.Sorted(maps.Keys(m.Applied)), ", ")))
	r.logger.Info("edge mode started", "mode", name, "auto", auto)
	if len(m.Applied) == 0 {
		notes = append(notes, "Ayarlar zaten bu kipteki gibiydi; kapatınca değişen bir şey olmayacak.")
	}
	return notes, nil
}

// undoPartial puts back the keys of change that differ from cur after a
// failed apply; errors are logged, the first error is what the caller
// reports.
func (r *Runtime) undoPartial(cur, change map[string]string) {
	now, err := r.DiagPrefs()
	if err != nil {
		return
	}
	got := prefMap(now)
	back := map[string]string{}
	for k := range change {
		if got[k] != cur[k] {
			back[k] = cur[k]
		}
	}
	if len(back) == 0 {
		return
	}
	if _, err := r.DiagSetPrefs(back); err != nil {
		r.logger.Warn("edge mode: undo failed", "error", err.Error())
	}
}

// endModeLocked restores what the mode replaced; edgeMu is held.
func (r *Runtime) endModeLocked(st *edgeFileState) ([]string, error) {
	m := st.Mode
	now, err := r.DiagPrefs()
	if err != nil {
		return nil, err
	}
	cur := prefMap(now)
	restore := map[string]string{}
	var kept []string
	for _, k := range slices.Sorted(maps.Keys(m.Applied)) {
		if cur[k] == m.Applied[k] {
			restore[k] = m.Previous[k]
		} else {
			kept = append(kept, k)
		}
	}
	if len(restore) > 0 {
		if _, err := r.DiagSetPrefs(restore); err != nil {
			return nil, fmt.Errorf("%s kipi kapatılamadı: %w", m.Name, err)
		}
	}
	st.Mode = nil
	if err := saveEdge(r.cfg.DataDir, *st); err != nil {
		return nil, err
	}
	var notes []string
	if len(kept) > 0 {
		notes = append(notes, "Kip açıkken değiştirdiğiniz ayarlar olduğu gibi bırakıldı: "+strings.Join(kept, ", ")+".")
	}
	r.auditLocal("edge_mode_ended", fmt.Sprintf("%s kipi kapatıldı; geri alınan: %s.", m.Name, strings.Join(slices.Sorted(maps.Keys(restore)), ", ")))
	r.logger.Info("edge mode ended", "mode", m.Name)
	return notes, nil
}

// EdgeSetOptions implements panel.EdgeApp.
func (r *Runtime) EdgeSetOptions(c panel.EdgeOptionsChange) (panel.EdgeStatus, error) {
	edgeMu.Lock()
	defer edgeMu.Unlock()
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		return panel.EdgeStatus{}, err
	}
	o := st.Options
	if c.LockShield != nil {
		o.LockShield = *c.LockShield
	}
	if c.LANGuard != nil {
		o.LANGuardOff = !*c.LANGuard
	}
	if c.LANGuardTravel != nil {
		o.LANGuardTravel = *c.LANGuardTravel
	}
	if c.AutoMetered != nil {
		o.AutoMetered = *c.AutoMetered
	}
	if c.TravelExit != nil {
		o.TravelExit = strings.TrimSpace(*c.TravelExit)
	}
	if o.LANGuardTravel && o.TravelExit == "" {
		return panel.EdgeStatus{}, errors.New("saldırı şüphesinde seyahat kipi için bir çıkış düğümü verin: --travel-exit <ad>")
	}
	var notes []string
	if c.RequireIntegrity != nil {
		if *c.RequireIntegrity && !o.RequireIntegrity {
			f := r.programIntegrity()
			if f.Level != FindingOK {
				return panel.EdgeStatus{}, fmt.Errorf("program şu an imzalı manifestoyla doğrulanamıyor, bu yüzden zorunlu kılınamaz: %s", f.Message)
			}
			notes = append(notes, "Program bütünlüğü doğrulandı; bundan sonra eşleşmezse tünel açılmaz.")
		}
		o.RequireIntegrity = *c.RequireIntegrity
	}
	if c.LockShield != nil && !*c.LockShield && st.Lock != nil {
		// Turning the option off ends a lock shield in progress.
		if err := r.releaseLockShieldLocked(&st); err != nil {
			return panel.EdgeStatus{}, err
		}
	}
	st.Options = o
	if err := saveEdge(r.cfg.DataDir, st); err != nil {
		return panel.EdgeStatus{}, err
	}
	r.auditLocal("edge_options_changed", "Uç cihaz seçenekleri değişti.")
	out := r.edgeStatusOf(st)
	out.Notes = notes
	return out, nil
}

// EdgeSessionLock implements panel.EdgeApp: the tray reports a screen
// lock or unlock (#501). The shield goes on only when it was off, and off
// again only when this lock turned it on and it is still on.
func (r *Runtime) EdgeSessionLock(locked bool) (panel.EdgeStatus, error) {
	edgeMu.Lock()
	defer edgeMu.Unlock()
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		return panel.EdgeStatus{}, err
	}
	switch {
	case locked && st.Options.LockShield && st.Lock == nil:
		cur, err := r.currentSettings()
		if err != nil {
			return panel.EdgeStatus{}, err
		}
		if cur.Shields {
			break
		}
		// Save first: a crash after SetShields still unlocks correctly.
		st.Lock = &edgeLock{Since: r.cfg.Now().UTC()}
		if err := saveEdge(r.cfg.DataDir, st); err != nil {
			return panel.EdgeStatus{}, err
		}
		if err := r.SetShields(true); err != nil {
			st.Lock = nil
			_ = saveEdge(r.cfg.DataDir, st)
			return panel.EdgeStatus{}, err
		}
		r.logger.Info("screen locked: shield on")
	case !locked && st.Lock != nil:
		if err := r.releaseLockShieldLocked(&st); err != nil {
			return panel.EdgeStatus{}, err
		}
		if err := saveEdge(r.cfg.DataDir, st); err != nil {
			return panel.EdgeStatus{}, err
		}
		r.logger.Info("screen unlocked: shield restored")
	}
	return r.edgeStatusOf(st), nil
}

// releaseLockShieldLocked turns the shield off if the lock turned it on;
// the caller saves st.
func (r *Runtime) releaseLockShieldLocked(st *edgeFileState) error {
	cur, err := r.currentSettings()
	if err != nil {
		return err
	}
	// A travel mode that wants the shield keeps it.
	keep := st.Mode != nil && st.Mode.Applied["shields"] == "true"
	if cur.Shields && !keep {
		if err := r.SetShields(false); err != nil {
			return err
		}
	}
	st.Lock = nil
	return nil
}

// programIntegrity compares the running program with the signed manifest
// of its installation once per process (#522, ADR-0095).
func (r *Runtime) programIntegrity() Finding {
	e := r.edge()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.integrity != nil {
		return *e.integrity
	}
	f := Finding{Level: FindingWarn, Area: "program", Message: "program yolu bulunamadı"}
	if exe, err := os.Executable(); err == nil {
		c := &checker{now: r.cfg.Now()}
		c.checkProgram(filepath.Join(r.cfg.DataDir, UpdateDir), exe)
		if len(c.out) > 0 {
			f = c.out[0]
		}
	}
	e.integrity = &f
	return f
}

// edgeIntegrityGate keeps the tunnel down when the owner asked for it and
// the program does not match its signed manifest (#522).
func (r *Runtime) edgeIntegrityGate() error {
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		// An unreadable edge.json must not lift the gate silently.
		return fmt.Errorf("uç cihaz ayarları okunamadı; tünel açılmadı: %w", err)
	}
	if !st.Options.RequireIntegrity {
		return nil
	}
	f := r.programIntegrity()
	if f.Level == FindingOK {
		return nil
	}
	r.observer().Security("program_integrity_gate", audit.SeverityCritical, panel.CategorySecurity, "", "Program imzalı manifestoyla eşleşmedi; tünel açılmadı: "+f.Message, true)
	return fmt.Errorf("program bütünlüğü doğrulanamadı, tünel açılmadı (openscale edge options --require-integrity=false ile kapatılır): %s", f.Message)
}

// edgeLoop watches the gateway and the metered hint until ctx ends.
func (r *Runtime) edgeLoop(ctx context.Context) {
	if f := r.programIntegrity(); f.Level == FindingError {
		r.observer().Security("program_tampered", audit.SeverityCritical, panel.CategorySecurity, "", "Program dosyası imzalı sürümle eşleşmiyor: "+f.Message, true)
	}
	t := time.NewTicker(edgeTick)
	defer t.Stop()
	r.edgeTick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.edgeTick()
		}
	}
}

// edgeTick reads the gateway and the metered hint once.
func (r *Runtime) edgeTick() {
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		r.logger.Warn("edge state", "error", err.Error())
		return
	}
	e := r.edge()
	e.mu.Lock()
	gateways, neighbors, network, hint := e.gateways, e.neighbors, e.network, e.hint
	e.mu.Unlock()
	if !st.Options.LANGuardOff {
		if gws, err := gateways(); err == nil {
			neigh := neighbors()
			network := network()
			now := r.cfg.Now()
			for _, gw := range gws {
				mac, ok := edgenet.GatewayMAC(neigh, gw)
				if !ok {
					continue
				}
				if a, hit := e.detector.Observe(network, gw, mac, now); hit {
					r.edgeLANAlert(a)
				}
			}
		}
	}
	m, known := hint()
	e.mu.Lock()
	if known {
		e.metered = &m
	} else {
		e.metered = nil
	}
	e.mu.Unlock()
	if known && st.Options.AutoMetered {
		r.edgeAutoMetered(m)
	}
}

func (r *Runtime) edgeLANAlert(a edgenet.Alert) {
	msg := a.Message()
	e := r.edge()
	e.mu.Lock()
	e.alerts = append(e.alerts, panel.EdgeLANAlert{At: a.At.UTC(), Kind: a.Kind, Gateway: a.Gateway.String(), Message: msg})
	if len(e.alerts) > maxEdgeAlerts {
		e.alerts = slices.Clone(e.alerts[len(e.alerts)-maxEdgeAlerts:])
	}
	e.mu.Unlock()
	r.logger.Warn("local network attack suspected", "kind", a.Kind, "gateway", a.Gateway.String())
	r.eventLog().Add(panel.DiagEvent{At: a.At, Kind: "lan-guard", Message: msg})
	r.observer().Security("lan_attack_suspected", audit.SeverityWarning, panel.CategorySecurity, "", msg, true)

	edgeMu.Lock()
	defer edgeMu.Unlock()
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil || !st.Options.LANGuardTravel || st.Mode != nil || st.Options.TravelExit == "" {
		return
	}
	if _, err := r.startModeLocked(&st, panel.EdgeModeTravel, st.Options.TravelExit, "lan-guard"); err != nil {
		r.logger.Warn("lan guard: travel mode", "error", err.Error())
	}
}

// edgeAutoMetered starts the metered mode on a metered link and ends the
// mode it started when the link is no longer metered.
func (r *Runtime) edgeAutoMetered(metered bool) {
	edgeMu.Lock()
	defer edgeMu.Unlock()
	st, err := loadEdge(r.cfg.DataDir)
	if err != nil {
		return
	}
	switch {
	case metered && st.Mode == nil:
		if _, err := r.startModeLocked(&st, panel.EdgeModeMetered, "", "metered"); err != nil {
			r.logger.Warn("metered mode", "error", err.Error())
		}
	case !metered && st.Mode != nil && st.Mode.Name == panel.EdgeModeMetered && st.Mode.Auto == "metered":
		if _, err := r.endModeLocked(&st); err != nil {
			r.logger.Warn("metered mode end", "error", err.Error())
		}
	}
}

// EdgeAudit implements panel.EdgeApp: the hardening checks of P11.
func (r *Runtime) EdgeAudit(ctx context.Context) (panel.EdgeAuditReply, error) {
	var out panel.EdgeAuditReply
	add := func(area, level, format string, args ...any) {
		out.Checks = append(out.Checks, panel.EdgeCheck{Area: area, Level: level, Message: fmt.Sprintf(format, args...)})
	}
	f := r.programIntegrity()
	add("program", f.Level, "%s", f.Message)
	add("kripto", FindingOK, "bilinen yanıt testleri bu süreç başlarken geçti (SHA-256, Ed25519, X25519, ChaCha20-Poly1305, Argon2id)")
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	risks, err := osnet.KillSwitchBypassRisks()
	switch {
	case err != nil:
		add("wfp", FindingInfo, "üçüncü taraf filtre denetimi yapılamadı: %v", err)
	case len(risks) == 0:
		add("wfp", FindingOK, "kill switch katmanlarında OpenScale'den önce değerlendirilebilecek üçüncü taraf filtre yok")
	default:
		for _, k := range risks {
			level := FindingInfo
			if k.Level == "high" {
				level = FindingWarn
			}
			add("wfp", level, "%s", k.Message)
		}
	}
	return out, nil
}

// EdgeSurface implements panel.EdgeApp (#521).
func (r *Runtime) EdgeSurface() (panel.SurfaceReply, error) {
	socks, ok := ownSockets()
	if !ok {
		return panel.SurfaceReply{}, errors.New("soket tabloları bu sistemde okunamıyor")
	}
	rep := panel.SurfaceReply{PID: os.Getpid()}
	var tunnel []netip.Addr
	if d := r.Status().Device; d != nil {
		for _, s := range []string{d.IPv4, d.IPv6} {
			if a, err := netip.ParseAddr(s); err == nil {
				tunnel = append(tunnel, a)
			}
		}
	}
	r.mu.Lock()
	coordEP := r.coordEP
	r.mu.Unlock()
	coordPort := uint16(0)
	if _, p, err := net.SplitHostPort(coordEP); err == nil {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			coordPort = uint16(n)
		}
	}
	coordTCP := uint16(0)
	if st, err := r.currentSettings(); err == nil && st.CoordinatorTCPListen != "" {
		if _, p, err := net.SplitHostPort(st.CoordinatorTCPListen); err == nil {
			if n, err := strconv.ParseUint(p, 10, 16); err == nil {
				coordTCP = uint16(n)
			}
		}
	}
	for _, s := range socks {
		rep.Entries = append(rep.Entries, describeSocket(s.Proto, s.Addr, s.Port, r.cfg.PanelPort, coordPort, coordTCP, tunnel))
	}
	rep.Notes = append(rep.Notes, "Liste işletim sisteminin soket tablosundan, yalnızca OpenScale servis sürecinin (PID "+strconv.Itoa(rep.PID)+") soketleri süzülerek çıkarıldı; amaç ve kural sütunları porttan ve adresten çıkarımdır.")
	return rep, nil
}

// describeSocket explains one socket of the service.
func describeSocket(proto string, addr netip.Addr, port uint16, panelPort int, coordPort, coordTCP uint16, tunnel []netip.Addr) panel.SurfaceEntry {
	addr = addr.Unmap()
	e := panel.SurfaceEntry{Proto: proto, Address: addr.String(), Port: port}
	inTunnel := slices.Contains(tunnel, addr)
	switch {
	case addr.IsLoopback():
		e.Reach = "yalnızca bu bilgisayar"
		e.Rule = "loopback; dışarıdan ulaşılamaz"
	case inTunnel:
		e.Reach = "yalnızca tünel (OpenScale cihazları)"
		e.Rule = "ağ belgesindeki erişim kuralları"
	case addr.IsUnspecified():
		e.Reach = "bütün arayüzler"
		e.Rule = "işletim sistemi güvenlik duvarı; tünelden gelen trafik ayrıca ağ belgesi kurallarına tabidir"
	default:
		e.Reach = "bu adresin ağı"
		e.Rule = "işletim sistemi güvenlik duvarı"
	}
	switch {
	case proto == "tcp" && int(port) == panelPort:
		e.Purpose = "yerel panel ve uygulama API'si (oturum veya uygulama jetonu)"
	case port == 53:
		e.Purpose = "MagicDNS / tünel DNS çözücüsü"
	case coordPort != 0 && port == coordPort:
		e.Purpose = "koordinatör (eşleşme ve aktarıcı)"
	case coordTCP != 0 && proto == "tcp" && port == coordTCP:
		e.Purpose = "koordinatör TCP taşıması (ADR-0032)"
	case proto == "udp" && !addr.IsLoopback() && !inTunnel:
		e.Purpose = "WireGuard eş bağlantısı veya yol keşfi"
	case inTunnel:
		e.Purpose = "tünel içi uygulama (SSH, dosya, uzak masaüstü, uyandırma vb.)"
	default:
		e.Purpose = "OpenScale bileşeni (bu listede adı tanımlı değil)"
	}
	return e
}
