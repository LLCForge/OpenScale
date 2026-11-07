package upstream

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/osnet"
)

const (
	// healthInterval is how often the tunnel is checked and settings are
	// read again.
	healthInterval = 5 * time.Second
	// staleAfter is WireGuard's REJECT_AFTER_TIME: older session keys are
	// refused, so a handshake older than this means the tunnel is down.
	staleAfter = 180 * time.Second
	// failOpenGrace is how long a fail-open upstream waits before members'
	// traffic leaves directly; a rekey must not flap the route.
	failOpenGrace = 15 * time.Second
	// Reconnect back-off while the tunnel is down.
	reconnectFirst = 30 * time.Second
	reconnectMax   = 5 * time.Minute
	// retryStart is how often a tunnel that could not start is tried again.
	retryStart = 30 * time.Second
	// statusRefresh bounds how old status.json gets while nothing changes.
	statusRefresh = 20 * time.Second
	routeTimeout  = 30 * time.Second
)

// Overlay is the OpenScale interface and the network prefixes of the
// members whose traffic goes upstream.
type Overlay struct {
	Interface string
	V4, V6    netip.Prefix
	// Self4 is this exit node's own OpenScale address; the Tor exit's
	// health check looks for TransPort there. Invalid when unknown.
	Self4 netip.Addr
}

// ManagerConfig configures a Manager.
type ManagerConfig struct {
	Store *Store
	Deps  Deps
	// Overlay returns the OpenScale interface and prefixes; read whenever
	// routing is installed, so a renumbered network is followed.
	Overlay func() (Overlay, error)
	// Interface is the upstream TUN name; "" is osnet.UpstreamInterface.
	Interface string
}

// Manager runs the upstream tunnel of an exit node: it follows the exit
// node role and the owner's settings, checks the handshake, reconnects,
// and in fail-open mode moves members' traffic between the tunnel and
// this host's own address. All OS changes go through Deps.Router.
type Manager struct {
	cfg ManagerConfig
	log *slog.Logger
	now func() time.Time

	mu       sync.Mutex
	role     bool
	settings Settings
	// running: the profile, MTU and fail-open choice the routing and the
	// tunnel were built for.
	active   string
	mtu      int
	failOpen bool
	routed   bool
	tun      *tunnel

	connected     bool
	direct        bool
	lastStats     tunnelStats
	downSince     time.Time
	lastReconnect time.Time
	backoff       time.Duration
	reconnects    uint64
	lastAttempt   time.Time
	errText       string
	settingsErr   string
	// confMod is the modification time of the running profile's file; a
	// re-import (--replace) rebuilds the tunnel.
	confMod time.Time

	lastStatus  Status
	lastWritten time.Time

	// tor is the Tor exit's state (tor.go).
	tor torState
}

// NewManager returns a stopped manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil || cfg.Overlay == nil || cfg.Deps.NewTUN == nil || cfg.Deps.NewBind == nil || cfg.Deps.Router == nil {
		return nil, errors.New("upstream: eksik yapılandırma")
	}
	if cfg.Interface == "" {
		cfg.Interface = osnet.UpstreamInterface
	}
	m := &Manager{cfg: cfg, log: cfg.Deps.Logger, now: cfg.Deps.Now}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	if m.now == nil {
		m.now = time.Now
	}
	return m, nil
}

// SetRole follows the exit node role in the signed document. Turning it on
// installs the drop routes before it returns, so call it before forwarding
// is turned on: no member packet leaves from this host while the tunnel
// comes up.
func (m *Manager) SetRole(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.role = on
	m.reconcileLocked()
}

// Run checks the tunnel and the settings until ctx ends. It leaves the
// tunnel and its routing in place: the caller turns forwarding off first
// and then calls Close, so no member packet leaves from this host while
// the process stops.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick()
		}
	}
}

// Tick reads the settings, applies a change and checks the tunnel once.
func (m *Manager) Tick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
}

// Close stops the tunnel and removes the routing.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.role = false
	m.teardownLocked()
	m.writeStatusLocked(true)
}

// DNS tells the exit node's DNS forwarder where members' queries go while
// an upstream is in use: the provider's resolver, asked from the tunnel
// address so the query travels inside the tunnel, or Tor's DNSPort on
// loopback. ok is false when no upstream is in use (or a fail-open
// upstream is down and traffic leaves directly): the normal resolver is
// used. ok with an invalid server means the upstream is wanted but cannot
// carry DNS: queries must be dropped.
func (m *Manager) DNS() (server netip.AddrPort, source netip.Addr, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.wantedLocked() {
		return netip.AddrPort{}, netip.Addr{}, false
	}
	if m.settings.TorEnabled() {
		return m.torDNSLocked()
	}
	if !m.routed {
		// Routing failed: fail-closed drops the queries too.
		return netip.AddrPort{}, netip.Addr{}, !m.settings.FailOpen()
	}
	if m.direct {
		return netip.AddrPort{}, netip.Addr{}, false
	}
	if m.tun == nil || !m.tun.server.IsValid() {
		if m.failOpen {
			return netip.AddrPort{}, netip.Addr{}, false
		}
		return netip.AddrPort{}, netip.Addr{}, true
	}
	return netip.AddrPortFrom(m.tun.server, providerDNSPort), m.tun.source, true
}

// providerDNSPort is the port of a WireGuard provider's resolver.
const providerDNSPort = 53

// Ready reports whether members' traffic may be forwarded: nil unless an
// upstream is wanted, fail-closed, and its drop routing could not be
// installed. The exit node must then stay off rather than send members'
// traffic from this host (ADR-0142, like the kill switch in ADR-0023).
func (m *Manager) Ready() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.wantedLocked() && m.settings.TorEnabled() {
		// The Tor exit is always fail-closed.
		return m.torReadyLocked()
	}
	if !m.wantedLocked() || m.routed || m.settings.FailOpen() {
		return nil
	}
	if m.errText != "" {
		return errors.New(m.errText)
	}
	return errors.New("üst çıkış yönlendirmesi kurulamadı")
}

// Status returns what the manager would write to status.json.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *Manager) wantedLocked() bool {
	return m.role && (m.settings.Active != "" || m.settings.TorEnabled())
}

func (m *Manager) reconcileLocked() {
	st, err := m.cfg.Store.Settings()
	if err != nil {
		// Keep running as before; a half-written or damaged file must not
		// turn the upstream off and let traffic leave from this host.
		if m.settingsErr == "" {
			m.log.Warn("upstream settings", "error", err.Error())
		}
		m.settingsErr = err.Error()
	} else {
		m.settings, m.settingsErr = st, ""
	}
	if !m.wantedLocked() {
		if m.routed || m.tun != nil || m.tor.routed {
			m.teardownLocked()
			m.log.Info("upstream exit off")
		}
		m.writeStatusLocked(false)
		return
	}
	if m.settings.TorEnabled() {
		// The WireGuard upstream goes first: its rules would send members
		// into a tunnel the Tor exit does not use.
		if m.routed || m.tun != nil {
			m.wgTeardownLocked()
		}
		m.torReconcileLocked()
		m.writeStatusLocked(false)
		return
	}
	if m.tor.routed {
		m.torTeardownLocked()
	}
	s := m.settings
	if !m.routed || s.Active != m.active || s.FailOpen() != m.failOpen || s.EffectiveMTU() != m.mtu || m.profileChangedLocked() {
		m.switchLocked(s)
	} else if m.tun == nil && m.now().Sub(m.lastAttempt) >= retryStart {
		m.startLocked(s)
	}
	m.healthLocked()
	m.writeStatusLocked(false)
}

// profileChangedLocked reports whether the running profile's file was
// replaced since its tunnel started.
func (m *Manager) profileChangedLocked() bool {
	if m.tun == nil || m.confMod.IsZero() {
		return false
	}
	mod, err := m.cfg.Store.ProfileModTime(m.active)
	return err == nil && !mod.Equal(m.confMod)
}

// switchLocked moves to a new profile or new choices: the drop routes
// first, then the new tunnel.
func (m *Manager) switchLocked(s Settings) {
	if m.tun != nil {
		m.tun.close()
		m.tun = nil
	}
	m.active, m.failOpen, m.mtu = s.Active, s.FailOpen(), s.EffectiveMTU()
	m.connected, m.direct, m.lastStats = false, false, tunnelStats{}
	m.reconnects, m.backoff = 0, reconnectFirst
	ov, err := m.cfg.Overlay()
	if err != nil {
		m.errText = "ağ bilgisi alınamadı: " + err.Error()
		m.routed = false
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
	defer cancel()
	if err := m.cfg.Deps.Router.Apply(ctx, m.blockedRoute(ov)); err != nil {
		// Without the drop rules nothing guarantees fail-closed: do not
		// start a tunnel either; the next tick tries again.
		m.errText = "üst çıkış yönlendirmesi kurulamadı: " + err.Error()
		m.log.Warn("upstream routing", "error", err.Error())
		m.routed = false
		return
	}
	m.routed = true
	m.startLocked(s)
}

func (m *Manager) blockedRoute(ov Overlay) osnet.UpstreamRoute {
	return osnet.UpstreamRoute{Interface: m.cfg.Interface, Overlay: ov.Interface, OverlayV4: ov.V4, OverlayV6: ov.V6, FailOpen: m.failOpen}
}

// startLocked brings the tunnel of the active profile up and routes
// members' traffic into it.
func (m *Manager) startLocked(s Settings) {
	m.lastAttempt = m.now()
	m.downSince = m.now()
	// The first reconnect waits a full back-off: a fresh device is still
	// doing its first handshake.
	m.lastReconnect = m.now()
	m.confMod, _ = m.cfg.Store.ProfileModTime(s.Active)
	cfg, err := m.cfg.Store.Load(s.Active)
	if err != nil {
		m.errText = "profil okunamadı: " + err.Error()
		m.log.Warn("upstream profile", "name", s.Active, "error", err.Error())
		return
	}
	// The provider's MTU (WARP: 1280) unless the owner chose one.
	mtu := m.mtu
	if s.MTU == 0 && cfg.MTU != 0 {
		mtu = cfg.MTU
	}
	t, err := startTunnel(m.cfg.Deps, m.cfg.Interface, mtu, cfg)
	cfg.Wipe()
	if err != nil {
		m.errText = err.Error()
		m.log.Warn("upstream tunnel", "name", s.Active, "error", err.Error())
		return
	}
	ov, err := m.cfg.Overlay()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
		err = m.cfg.Deps.Router.Apply(ctx, t.route(ov, mtu, m.failOpen))
		cancel()
	}
	if err != nil {
		t.close()
		m.errText = "üst tünel yönlendirmesi kurulamadı: " + err.Error()
		m.log.Warn("upstream routing", "error", err.Error())
		// Back to the drop routes: the closed device took its routes.
		if ov.Interface != "" {
			ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
			_ = m.cfg.Deps.Router.Apply(ctx, m.blockedRoute(ov))
			cancel()
		}
		return
	}
	m.tun = t
	m.errText = ""
	m.log.Info("upstream exit started", "profile", s.Active, "interface", t.name)
	m.log.Debug("upstream exit endpoint", "endpoint", t.endpoint.String())
}

// healthLocked reads the handshake age and reacts to a lost tunnel.
func (m *Manager) healthLocked() {
	now := m.now()
	if m.tun == nil {
		m.connected = false
		m.setDirectLocked(m.failOpen && now.Sub(m.downSince) >= failOpenGrace)
		return
	}
	st, err := m.tun.stats()
	if err != nil {
		m.errText = err.Error()
		return
	}
	m.lastStats = st
	was := m.connected
	m.connected = !st.lastHandshake.IsZero() && now.Sub(st.lastHandshake) < staleAfter
	switch {
	case m.connected:
		if !was {
			m.log.Info("upstream exit connected", "profile", m.active)
		}
		m.backoff = reconnectFirst
		m.setDirectLocked(false)
	case was:
		m.downSince = now
		m.log.Warn("upstream exit lost its handshake", "profile", m.active)
		fallthrough
	default:
		m.setDirectLocked(m.failOpen && now.Sub(m.downSince) >= failOpenGrace)
		if now.Sub(m.lastReconnect) >= m.backoff {
			m.lastReconnect = now
			m.reconnects++
			m.backoff = min(2*m.backoff, reconnectMax)
			if err := m.tun.reconnect(); err != nil {
				m.errText = "yeniden bağlanma: " + err.Error()
			}
		}
	}
}

// setDirectLocked switches a fail-open upstream between the tunnel and
// leaving directly. A fail-closed upstream never goes direct.
func (m *Manager) setDirectLocked(direct bool) {
	if direct == m.direct || !m.routed || (direct && !m.failOpen) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
	defer cancel()
	if err := m.cfg.Deps.Router.SetDirect(ctx, direct); err != nil {
		m.errText = err.Error()
		m.log.Warn("upstream fail-open switch", "error", err.Error())
		return
	}
	m.direct = direct
	if direct {
		m.log.Warn("upstream exit down: members' traffic leaves from this host (fail-open)", "profile", m.active)
	} else {
		m.log.Info("upstream exit back: members' traffic uses the tunnel", "profile", m.active)
	}
}

func (m *Manager) teardownLocked() {
	m.wgTeardownLocked()
	m.torTeardownLocked()
}

// wgTeardownLocked stops the WireGuard upstream and removes its routing.
func (m *Manager) wgTeardownLocked() {
	if m.tun != nil {
		m.tun.close()
		m.tun = nil
	}
	if m.routed {
		ctx, cancel := context.WithTimeout(context.Background(), routeTimeout)
		if err := m.cfg.Deps.Router.Remove(ctx); err != nil {
			m.log.Warn("upstream routing removal", "error", err.Error())
		}
		cancel()
	}
	m.routed, m.connected, m.direct, m.active = false, false, false, ""
	m.lastStats = tunnelStats{}
}

func (m *Manager) statusLocked() Status {
	st := Status{Mode: ModeOff, OnDown: OnDownDrop, Error: m.errText, Updated: m.now().Unix()}
	if m.settingsErr != "" {
		st.Error = m.settingsErr
	}
	if m.settings.FailOpen() {
		st.OnDown = OnDownDirect
	}
	if !m.wantedLocked() {
		return st
	}
	st.Kind = m.settings.Kind()
	if m.settings.TorEnabled() {
		m.torStatusLocked(&st)
		return st
	}
	st.Active, st.Label = m.settings.Active, m.settings.Label(m.settings.Active)
	st.Interface = m.cfg.Interface
	st.Connected = m.connected
	st.RxBytes, st.TxBytes = m.lastStats.rx, m.lastStats.tx
	st.Reconnects = m.reconnects
	if !m.lastStats.lastHandshake.IsZero() {
		st.LastHandshake = m.lastStats.lastHandshake.Unix()
	}
	if m.tun != nil {
		st.Interface, st.Endpoint = m.tun.name, m.tun.endpoint.String()
	}
	switch {
	case m.direct:
		st.Mode = ModeDirect
	case m.connected:
		st.Mode = ModeTunnel
	default:
		st.Mode = ModeBlocked
		if !m.routed {
			// Neither routing nor a tunnel: say so, nothing is guaranteed.
			st.Mode = ModeOff
		}
	}
	return st
}

// writeStatusLocked writes status.json when it changed or got old.
func (m *Manager) writeStatusLocked(force bool) {
	st := m.statusLocked()
	cmp := st
	cmp.Updated = m.lastStatus.Updated
	if !force && statusEqual(cmp, m.lastStatus) && m.now().Sub(m.lastWritten) < statusRefresh {
		return
	}
	if !force && m.lastWritten.IsZero() && st.Mode == ModeOff && st.Error == "" {
		// Never used here: no file until there is something to report.
		return
	}
	if err := m.cfg.Store.WriteStatus(st); err != nil {
		m.log.Warn("upstream status file", "error", err.Error())
		return
	}
	m.lastStatus, m.lastWritten = st, m.now()
}
