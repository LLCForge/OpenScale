// Package service is the OpenScale desktop service (ADR-0014). One process
// runs everything this computer does for the network: the local panel, the
// device tunnel, the coordinator when it lives here, and the invite join of
// a new device. State lives in a single machine-wide data directory.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Layout of the data directory.
const (
	NetworkDir     = "network"
	DeviceDir      = "device"
	CoordinatorDir = "coordinator"
	TokenFile      = "app.token"
	deviceKeyFile  = "device.key"
	coordKeyFile   = "coordinator.key"
	// DefaultPanelPort is where the tray finds the panel.
	DefaultPanelPort = 47821
	restartDelay     = 15 * time.Second
	restartDelayMax  = 5 * time.Minute
	// A lost tunnel interface is recreated after tunnelLostRetry, growing
	// to tunnelLostRetryMax while it keeps failing (F-146).
	tunnelLostRetry    = time.Second
	tunnelLostRetryMax = 30 * time.Second
	// stableRun: a tunnel that ran this long resets the restart delays.
	stableRun    = 2 * time.Minute
	feedInterval = 10 * time.Second
	// handoffPeriod is how long a replaced coordinator keeps serving devices
	// that were offline when the owner moved it.
	handoffPeriod = 30 * 24 * time.Hour
	// onlineWindow: WireGuard renews handshakes every two minutes while
	// keepalives flow, so a peer silent for longer counts as offline.
	onlineWindow = 3*time.Minute + 30*time.Second
	tokenBytes   = 32
)

// Hooks are the operating-system specific steps; the defaults in this
// package create a real interface.
type Hooks struct {
	// OpenTunnel creates the OS interface with this device's addresses and
	// the given MTU (the same value the engine clamps TCP MSS to).
	OpenTunnel func(ctx context.Context, self trust.Device, doc *trust.Document, mtu int) (tun.Device, error)
	// AllowTraffic opens the firewall for the program and the overlay.
	AllowTraffic func(overlayIPv4 netip.Prefix) error
	// ReapplyRemoteAccess restores the RDP/SSH firewall choices when the
	// tunnel starts (the Windows service sets it; tests do not).
	ReapplyRemoteAccess bool
	// ConfigureDNS and RemoveDNS route the network domain to MagicDNS
	// (ADR-0016). Nil leaves the system DNS settings alone (tests).
	ConfigureDNS func(ctx context.Context, c osnet.DNSConfig) error
	RemoveDNS    func(ctx context.Context, c osnet.DNSConfig) error
	// ConfigureNetworkDNS applies the document's dns section together with
	// MagicDNS (ADR-0024); RemoveDNS removes both. Nil leaves the network
	// DNS settings unapplied (tests).
	ConfigureNetworkDNS func(ctx context.Context, magic osnet.DNSConfig, n osnet.NetworkDNS) error
	// VerifyNetworkDNS notices DNS settings another program changed
	// (F-061) and DNSStatus describes the system resolver (F-062, F-063);
	// nil skips both (tests).
	VerifyNetworkDNS func(ctx context.Context, magic osnet.DNSConfig, n osnet.NetworkDNS) error
	DNSStatus        func(iface string) osnet.DNSSystemStatus
	// ExitRouter routes internet traffic through an exit node; nil
	// disables exit node use (tests).
	ExitRouter node.ExitRouter
	// InstallKillSwitch and RemoveKillSwitch manage the persistent kill
	// switch (ADR-0023). Nil means this system has none (tests, systems
	// without WFP); then exit node use relies on the routes alone.
	InstallKillSwitch func(osnet.KillSwitchConfig) error
	RemoveKillSwitch  func() error
	DNSEnforce        DNSApplier // #717 DNS zorlama (dnsenforce.go); nil: yok (testler)
	// Recover undoes DNS and route changes a crash left behind, as the
	// change journal lists them (ADR-0051); zero undoes nothing (tests).
	Recover JournalUndo
	// AutoUpdate turns on the automatic updater (ADR-0225, autoupdate.go);
	// only the installed Windows service sets it.
	AutoUpdate bool
}

// Config configures the service.
type Config struct {
	DataDir   string
	PanelPort int
	Hooks     Hooks
	Logger    *slog.Logger
	Now       func() time.Time
	Random    io.Reader
	Argon2    trust.Argon2Params
	Hostname  func() (string, error)
	// PanelFiles overrides the embedded panel (tests).
	PanelFiles fs.FS
	// PollInterval overrides how often the tunnel and the coordinator
	// handoff check for new documents (tests); zero uses the defaults.
	PollInterval time.Duration
	// PeerCheck restricts the app token to authorized processes
	// (ADR-0050); nil trusts the token alone (tests).
	PeerCheck func(remote, local string) error
}

// Runtime is the running service.
type Runtime struct {
	cfg    Config
	bg     background // goroutines Run waits for, background.go
	logger *slog.Logger
	panel  *panel.Server
	ctx    context.Context
	ready  chan struct{}
	wire   wireState       // tunnel-bound G6 parts, wire_g6.go
	auto   autoUpdateState // ADR-0225, autoupdate.go

	mu           sync.Mutex
	settingsMu   sync.Mutex
	invMu        sync.Mutex
	inventory    panel.Inventory
	secMu        sync.Mutex
	secCache     panel.LocalSecurity
	secAt        time.Time
	network      *admin.Network
	engine       *node.Engine
	coord        *coordinator.Server
	engineErr    string
	engineSince  time.Time
	dnsErr       string
	netDNSActive bool
	netDNSErr    string
	// dnsHealth holds the DNS health details (F-062, ADR-0034).
	dnsHealth    dnsHealthState
	coordRun     bool
	coordErr     string
	coordEP      string
	coordHandoff bool
	stopDevice   context.CancelFunc
	stopCoord    context.CancelFunc
	join         *joinState
	lastJoinErr  string
	// exitRouter is Hooks.ExitRouter wrapped with the kill switch; nil
	// when exit nodes cannot be used.
	exitRouter node.ExitRouter
	// ksMu serializes kill switch changes with the settings they follow;
	// ksStateMu guards ks and is never held while taking another lock.
	ksMu      sync.Mutex
	ksStateMu sync.Mutex
	ks        killSwitchState
	// diag holds the event list and diagnostics state (diag_service.go).
	diag diagState
	// apps runs SSH, files, wake and speed test (ADR-0030, ADR-0031).
	apps *Apps
	// journal records DNS and route changes until they are undone
	// (ADR-0051).
	journal *Journal
	// w2 is the connection wave 2 state (wave2_runtime.go, ADR-0110).
	w2 wave2Runtime
	// w3 is the connection wave 3 state (wave3_runtime.go).
	w3 wave3Runtime
	w4 w4Runtime // monitoring (w4_monitor.go)
	// dnsEnf: #717 DNS zorlama (dnsenforce.go).
	dnsEnf dnsEnforceState
	fr     flightState // #836: uçuş kaydedici (flightrec_wire.go)
}

type joinState struct {
	name      string
	shortCode string
	cancel    context.CancelFunc
	err       string
}

// New validates the configuration.
func New(cfg Config) (*Runtime, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("service needs a data directory")
	}
	if cfg.PanelPort == 0 {
		cfg.PanelPort = DefaultPanelPort
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.Argon2 == (trust.Argon2Params{}) {
		cfg.Argon2 = trust.DefaultArgon2
	}
	if cfg.Hostname == nil {
		cfg.Hostname = os.Hostname
	}
	if cfg.Hooks.OpenTunnel == nil {
		cfg.Hooks.OpenTunnel = openTunnel
	}
	if cfg.Hooks.AllowTraffic == nil {
		cfg.Hooks.AllowTraffic = func(netip.Prefix) error { return nil }
	}
	r := &Runtime{cfg: cfg, logger: cfg.Logger, ready: make(chan struct{}), journal: OpenJournal(cfg.DataDir, cfg.Now)}
	if cfg.Hooks.ExitRouter != nil {
		r.exitRouter = &exitGuard{r: r, inner: JournaledExitRouter(r.journal, cfg.Hooks.ExitRouter)}
	}
	return r, nil
}

func (r *Runtime) path(parts ...string) string {
	if p, ok := r.devicePath(parts); ok {
		return p // active network profile (ADR-0135, wave3_runtime.go)
	}
	return filepath.Join(append([]string{r.cfg.DataDir}, parts...)...)
}

func (r *Runtime) adminOptions() admin.Options {
	return admin.Options{Argon2: r.cfg.Argon2, Random: r.cfg.Random}
}

// Run starts every role found in the data directory and the panel, and
// serves until ctx ends.
func (r *Runtime) Run(ctx context.Context) error {
	r.ctx = ctx
	r.startFlightRecorder(ctx) // #836, flightrec_wire.go; first, before anything copies r.logger
	if err := os.MkdirAll(r.cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	token, err := r.writeToken()
	if err != nil {
		return err
	}
	// Undo what a crash left behind before anything new is set up.
	r.recoverChanges(ctx)
	// Repair damaged state, keep the disk reserve and check the
	// installation (selfcheck_p14.go, #172, #205, #206).
	r.startupSelfCheck(ctx)
	// Repair after a major OS update (platform_p10.go, #498).
	r.platformStartup(ctx)
	if n, err := admin.Load(r.path(NetworkDir), r.adminOptions()); err == nil {
		r.network = n
	} else if !errors.Is(err, fs.ErrNotExist) {
		r.logger.Warn("network directory unreadable", "error", err.Error())
	}
	srv, err := panel.New(panel.Config{
		Network:   r.network,
		App:       r,
		AppToken:  token,
		Files:     r.cfg.PanelFiles,
		Logger:    r.logger,
		Now:       r.cfg.Now,
		Random:    r.cfg.Random,
		ReadOnly:  func() bool { return PanelReadOnly(r.cfg.DataDir) },
		PeerCheck: r.cfg.PeerCheck,
	})
	if err != nil {
		return err
	}
	r.panel = srv
	ln, err := panel.Listen(r.cfg.PanelPort)
	if err != nil {
		return fmt.Errorf("panel port %d is busy: %w", r.cfg.PanelPort, err)
	}
	r.prepareDeviceStart()
	r.startCoordinator()
	r.startDevice()
	r.spawn(func() { r.inventoryLoop(ctx) })
	r.spawn(func() { r.reconnectLoop(ctx) })
	r.spawn(func() { r.diagLoop(ctx) })
	r.spawn(func() { r.edgeLoop(ctx) }) // ADR-0154, edge_p11.go
	r.startApps(ctx)
	r.spawn(func() { r.monitorLoop(ctx) })    // W4, w4_monitor.go
	r.spawn(func() { r.idsLoop(ctx) })        // ADR-0221, w8_ids_link.go
	r.spawn(func() { r.runRemotePanel(ctx) }) // ADR-0107, remote_panel_p17.go
	close(r.ready)
	r.logger.Info("service running", "panel", srv.URL(ln.Addr()))
	err = srv.Serve(ctx, ln)
	r.mu.Lock()
	if r.join != nil {
		r.join.cancel()
	}
	r.mu.Unlock()
	// Nothing may write to the data directory after Run returns.
	r.waitBackground()
	r.releaseKillSwitchOnStop()
	return err
}

// prepareDeviceStart settles what changed while the service was not
// running: a timed disconnect that has ended turns the tunnel back on, and
// filters kept across the stop are dropped when no membership is left to
// use an exit node with (ADR-0023).
func (r *Runtime) prepareDeviceStart() {
	if st, err := r.currentSettings(); err == nil && st.Disconnected && st.DisconnectedUntil != nil && !r.cfg.Now().Before(*st.DisconnectedUntil) {
		err := r.updateSettings(func(st *settings) (bool, error) {
			st.Disconnected, st.DisconnectedUntil = false, nil
			return true, nil
		})
		if err != nil {
			r.logger.Warn("end a timed disconnect", "error", err.Error())
		} else {
			r.logger.Info("timed disconnect ended while the service was stopped")
		}
	}
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		if err := r.removeKillSwitch(); err != nil {
			r.logger.Warn("kill switch without a membership", "error", err.Error())
		}
	}
}

// Ready is closed once the panel listens and the roles were started.
func (r *Runtime) Ready() <-chan struct{} { return r.ready }

// writeToken creates a fresh app token on every start. The data directory
// is readable only by SYSTEM and administrators (ADR-0014).
func (r *Runtime) writeToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := io.ReadFull(r.cfg.Random, b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	if err := securefile.Replace(r.path(TokenFile), []byte(token)); err != nil {
		return "", fmt.Errorf("write app token: %w", err)
	}
	return token, nil
}

// ReadToken reads the app token for the tray.
func ReadToken(dataDir string) (string, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dataDir, TokenFile), 256)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// startDevice runs the tunnel if this computer is a member, restarting it
// after failures until the service stops or the device is removed.
func (r *Runtime) startDevice() {
	store, err := member.Open(r.path(DeviceDir))
	if err != nil {
		return
	}
	if st, err := loadSettings(r.cfg.DataDir); err == nil && st.Disconnected {
		r.logger.Info("tunnel is turned off by the owner")
		return
	}
	// Start-up integrity gate, when the owner asked for it (#522).
	if err := r.edgeIntegrityGate(); err != nil {
		r.logger.Error("integrity gate", "error", err.Error())
		r.setEngineErr(err)
		return
	}
	secrets, err := readSecrets(r.path(DeviceDir, deviceKeyFile))
	if err != nil {
		r.setEngineErr(err)
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	r.mu.Lock()
	if r.stopDevice != nil {
		r.stopDevice()
	}
	r.stopDevice = cancel
	networkDir := ""
	if r.network != nil {
		networkDir = r.path(NetworkDir)
	}
	r.mu.Unlock()
	r.spawn(func() { r.superviseDevice(ctx, store, secrets, networkDir) })
}

// SetConnected implements panel.App.
func (r *Runtime) SetConnected(on bool) error {
	return r.setConnected(on, nil)
}

// setConnected turns the tunnel on or off; until, when set with off, is
// when the service turns it back on (F-121).
func (r *Runtime) setConnected(on bool, until *time.Time) error {
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	err := r.updateSettings(func(st *settings) (bool, error) {
		st.Disconnected = !on
		st.DisconnectedUntil = nil
		if !on && until != nil {
			t := until.UTC()
			st.DisconnectedUntil = &t
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	if on {
		r.logger.Info("tunnel turned on")
		r.startDevice()
		return nil
	}
	r.mu.Lock()
	if r.stopDevice != nil {
		r.stopDevice()
		r.stopDevice = nil
	}
	r.engineErr = ""
	r.mu.Unlock()
	// A tunnel turned off on purpose gives the normal internet back, also
	// when the chosen exit node was not active (ADR-0018, ADR-0023).
	if err := r.removeKillSwitch(); err != nil {
		return err
	}
	if until != nil {
		r.logger.Info("tunnel turned off for a while", "until", until.UTC().Format(time.RFC3339))
	} else {
		r.logger.Info("tunnel turned off")
	}
	return nil
}

func (r *Runtime) superviseDevice(ctx context.Context, store *member.Store, secrets *trust.DeviceSecrets, networkDir string) {
	// A lost interface (F-146) is recreated quickly; other failures wait
	// longer. Both delays grow with repeated failures and start over once
	// the tunnel ran for a while.
	lost := node.Backoff{Base: tunnelLostRetry, Max: tunnelLostRetryMax, Jitter: 0.2}
	failed := node.Backoff{Base: restartDelay, Max: restartDelayMax, Jitter: 0.2}
	for ctx.Err() == nil {
		started := r.cfg.Now()
		err := r.runDevice(ctx, store, secrets, networkDir)
		if ctx.Err() != nil {
			return
		}
		if r.cfg.Now().Sub(started) >= stableRun {
			lost.Reset()
			failed.Reset()
		}
		if secrets2, promoted := r.promoteRotatedKey(store); promoted {
			// The owner approved this device's key rotation (ADR-0020):
			// the next start uses the new keys.
			secrets = secrets2
			r.logger.Info("device keys rotated")
			continue
		}
		r.setEngineErr(err)
		if errors.Is(err, node.ErrNotMember) {
			r.logger.Warn("this device is no longer in the network")
			// No exit node can be used any more: restore the routes and
			// drop the kill switch instead of leaving the computer offline.
			if r.exitRouter != nil {
				if err := r.exitRouter.Disable(); err != nil {
					r.logger.Warn("exit node cleanup", "error", err.Error())
				}
			}
			return
		}
		delay := failed.Next()
		if errors.Is(err, node.ErrTunnelLost) {
			// The engine closed the old interface; the next start creates
			// a new one.
			delay = lost.Next()
			r.logger.Warn("tunnel interface lost; recreating it", "error", errString(err), "after", delay.String())
		} else {
			r.logger.Warn("tunnel stopped; restarting", "error", errString(err), "after", delay.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (r *Runtime) runDevice(ctx context.Context, store *member.Store, secrets *trust.DeviceSecrets, networkDir string) error {
	doc := store.Document()
	self, err := selfDevice(doc, secrets)
	if err != nil {
		return err
	}
	st, err := r.currentSettings()
	if err != nil {
		// Unreadable settings: start with the defaults, as before.
		r.logger.Warn("settings unreadable; using defaults", "error", err.Error())
		st = settings{}
	}
	mtu := tunnelMTUFor(st)
	if st.MTU != 0 && mtu != st.MTU {
		r.logger.Warn("saved tunnel MTU is not usable; using the default", "mtu", st.MTU)
	}
	if doc.Coordinator == nil {
		return errors.New("network document has no coordinator")
	}
	if err := r.cfg.Hooks.AllowTraffic(doc.IPv4Prefix); err != nil {
		r.logger.Warn("firewall rules", "error", err.Error())
	}
	if r.cfg.Hooks.ReapplyRemoteAccess {
		go r.reapplyRemoteAccess()
	}
	// Fail closed (ADR-0023): with an exit node chosen, the kill switch is
	// in place before the tunnel comes up. The tunnel permit follows once
	// the exit node is enabled on the new interface.
	if err := r.syncKillSwitch(""); err != nil {
		r.logger.Warn("kill switch before the tunnel", "error", err.Error())
	}
	dev, err := r.cfg.Hooks.OpenTunnel(withTUNOptions(ctx, tunOptionsFor(st)), self, doc, mtu)
	if err != nil {
		return err
	}
	if name, err := dev.Name(); err == nil {
		r.setTunnelInterface(name)
		defer r.setTunnelInterface("")
		// Let the tunnel itself through right away, even if the chosen
		// exit node turns out to be unusable: peers stay reachable while
		// internet traffic stays blocked.
		if err := r.syncKillSwitch(name); err != nil {
			r.logger.Warn("kill switch for the tunnel", "error", err.Error())
		}
	}
	if name, err := dev.Name(); err == nil && r.cfg.Hooks.ConfigureDNS != nil {
		dns := osnet.DNSConfig{Interface: name, Server: doc.DNSResolverIPv4(), Domain: doc.DNSDomain}
		// The DNS work of this run stops before the cleanup below runs, so
		// a late network DNS change cannot outlive the tunnel.
		dnsCtx, stopDNS := context.WithCancel(ctx)
		dnsDone := make(chan struct{})
		if r.cfg.Hooks.RemoveDNS != nil {
			if err := r.journal.Begin(DNSEntry(dns)); err != nil {
				r.logger.Warn("change journal", "error", err.Error())
			}
			defer func() {
				cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if err := r.cfg.Hooks.RemoveDNS(cctx, dns); err != nil {
					r.logger.Warn("MagicDNS cleanup", "error", err.Error())
					return
				}
				if err := r.journal.Done(JournalDNS); err != nil {
					r.logger.Warn("change journal", "error", err.Error())
				}
			}()
		}
		defer r.setDNSErr(nil)
		defer r.setNetworkDNS(false, nil)
		defer func() {
			stopDNS()
			<-dnsDone
		}()
		go func() {
			defer close(dnsDone)
			err := r.cfg.Hooks.ConfigureDNS(dnsCtx, dns)
			if err != nil && dnsCtx.Err() == nil {
				r.logger.Warn("MagicDNS setup", "error", err.Error())
			}
			if dnsCtx.Err() != nil {
				return
			}
			r.setDNSErr(err)
			if err != nil || r.cfg.Hooks.ConfigureNetworkDNS == nil {
				return
			}
			r.networkDNSWatch(store, dns).Run(dnsCtx)
		}()
	}
	exitName, shields := st.ExitNode, st.Shields
	// A restart (an update above all) hands the last endpoints over before
	// the engine starts (handover.go, #203).
	TakeHandover(store.Dir(), doc, r.cfg.Now(), r.logger.With("part", "handover"))
	engine, err := node.New(r.withTunnelOptions(st, node.Config{
		Store:        store,
		Secrets:      secrets,
		TUN:          dev,
		NetworkDir:   networkDir,
		PollInterval: r.cfg.PollInterval,
		Logger:       r.logger.With("role", "device"),
		Now:          r.cfg.Now,
		ExitNode:     exitName,
		ExitRouter:   r.exitRouter,
		Shields:      shields,
		MTU:          mtu,
		ForceRelay:   st.ForceRelay && mtu <= node.DefaultMTU,
		Resolve:      r.resolveCoordinator,
		OnExitRole: func(on bool) {
			if on {
				r.logger.Warn("this computer has the exit node role, but a Windows exit node is not supported yet")
			}
		},
	}))
	if err != nil {
		_ = dev.Close()
		return err
	}
	r.mu.Lock()
	r.engine, r.engineErr, r.engineSince = engine, "", r.cfg.Now()
	r.mu.Unlock()
	runCtx, stopRun := context.WithCancelCause(ctx)
	defer stopRun(nil)
	r.startWave3(runCtx, engine)
	r.startAutoUpdate(runCtx, engine)         // ADR-0225 (autoupdate.go)
	r.startWire(runCtx, store, secrets, self) // wire_g6.go: E2E files, tamper watch
	if name, err := dev.Name(); err == nil {
		// Written when the service stops, before the engine closes (#203).
		wait := StartHandover(runCtx, store.Dir(), name, engine, r.stopping, nil, r.cfg.Now, r.logger.With("part", "handover"))
		defer func() {
			stopRun(nil)
			wait()
		}()
	}
	// #717 (dnsenforce.go): DNS zorlama kuralları tünel bitmeden kalkar.
	defer r.startDNSEnforce(runCtx, dev, doc)()
	if name, err := dev.Name(); err == nil {
		watchInterface(runCtx, name, ifWatchEvery, stopRun)
	}
	err = engine.Run(runCtx)
	if cause := context.Cause(runCtx); ctx.Err() == nil && errors.Is(cause, node.ErrTunnelLost) {
		err = cause
	}
	r.mu.Lock()
	if r.engine == engine {
		r.engine = nil
	}
	r.mu.Unlock()
	if err == nil && ctx.Err() == nil {
		err = errors.New("tunnel stopped")
	}
	return err
}

// startCoordinator runs the coordinator if its state lives here. After the
// owner moves the coordinator elsewhere (for example to a VPS) it keeps
// running in handoff mode for handoffPeriod, fed with the newest document,
// so devices that still talk to it learn the new coordinator; then it
// retires itself.
func (r *Runtime) startCoordinator() {
	store, err := member.Open(r.path(CoordinatorDir))
	if err != nil {
		return
	}
	secrets, err := readSecrets(r.path(CoordinatorDir, coordKeyFile))
	if err != nil {
		r.setCoordErr(err)
		return
	}
	_, ownKey, err := secrets.PublicKeys()
	if err != nil {
		r.setCoordErr(err)
		return
	}
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil || st.CoordinatorPort == 0 {
		r.setCoordErr(errors.New("coordinator port is not configured"))
		return
	}
	relayRate, relayBurst := st.CoordinatorRelayRate, st.CoordinatorRelayBurst
	if err := validRelayLimits(relayRate, relayBurst); err != nil {
		r.logger.Warn("saved relay limits are not usable; using the defaults", "error", err.Error())
		relayRate, relayBurst = 0, 0
	}
	tcpListen, tcpMax, tcpPerIP := r.coordinatorTCPConfig(st)
	r.feedCoordinator(store)
	if r.retireIfDone(store, ownKey) {
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	r.mu.Lock()
	if r.stopCoord != nil {
		r.stopCoord()
	}
	r.stopCoord = cancel
	if c := store.Document().Coordinator; c != nil {
		r.coordEP = c.Endpoint
	}
	r.mu.Unlock()
	r.spawn(func() { r.feedLoop(ctx, store, ownKey) })
	r.spawn(func() {
		for ctx.Err() == nil {
			ccfg := coordinator.Config{
				Store: store, Secrets: secrets, ListenPort: st.CoordinatorPort,
				Logger: r.logger.With("role", "coordinator"), Handoff: true,
				RelayRate: relayRate, RelayBurst: relayBurst,
				TCPListen: tcpListen, TCPMaxConns: tcpMax, TCPMaxConnsPerIP: tcpPerIP,
				ReleaseMirror: r.path(CoordinatorDir, coordinator.ReleaseMirrorDir), // ADR-0225
				Rejections:    r.coordinatorRejection,                               // #187, coordinator_audit.go
			}
			srv, err := r.newCoordinatorWithObfs(ctx, ccfg) // ADR-0186, wire_coord_obfs.go
			if err == nil {
				r.mu.Lock()
				r.coordRun, r.coordErr, r.coord = true, "", srv
				r.mu.Unlock()
				err = srv.Run(ctx)
			}
			r.mu.Lock()
			r.coordRun, r.coord = false, nil
			r.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			r.setCoordErr(err)
			r.logger.Warn("coordinator stopped; restarting", "error", errString(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(restartDelay):
			}
		}
	})
}

// feedLoop keeps the local coordinator's document current and retires it
// once the handoff period has passed.
func (r *Runtime) feedLoop(ctx context.Context, store *member.Store, ownKey trust.Key) {
	every := feedInterval
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < every {
		every = r.cfg.PollInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r.feedCoordinator(store)
		if r.retireIfDone(store, ownKey) {
			r.mu.Lock()
			if r.stopCoord != nil {
				r.stopCoord()
				r.stopCoord = nil
			}
			r.coordEP, r.coordErr = "", ""
			r.mu.Unlock()
			return
		}
	}
}

// feedCoordinator hands the newest document this computer knows to its
// coordinator store. Store.Accept verifies the root signature and refuses
// older versions, so this can only move it forward.
func (r *Runtime) feedCoordinator(store *member.Store) {
	var data []byte
	if b, err := securefile.ReadLimited(r.path(NetworkDir, "network.json"), trust.MaxEnvelopeSize); err == nil {
		data = b
	} else if dev, err := member.Open(r.path(DeviceDir)); err == nil {
		data, _ = dev.Envelope()
	}
	if len(data) == 0 {
		return
	}
	if _, err := store.Accept(data, r.cfg.Now()); err != nil && !errors.Is(err, trust.ErrRollback) {
		r.logger.Warn("coordinator document update", "error", err.Error())
	}
}

// retireIfDone records when the coordinator was replaced and, after
// handoffPeriod, moves its state aside. It reports whether it retired.
func (r *Runtime) retireIfDone(store *member.Store, ownKey trust.Key) bool {
	doc := store.Document()
	pinned := doc.Coordinator != nil && doc.Coordinator.WireGuardKey == ownKey
	r.mu.Lock()
	defer r.mu.Unlock()
	r.coordHandoff = !pinned
	if pinned {
		return false
	}
	r.settingsMu.Lock()
	defer r.settingsMu.Unlock()
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil {
		return false
	}
	now := r.cfg.Now()
	if st.HandoffSince == nil {
		st.HandoffSince = &now
		if err := saveSettings(r.cfg.DataDir, st); err != nil {
			r.logger.Warn("save handoff time", "error", err.Error())
		}
		r.logger.Info("coordinator moved elsewhere; serving devices during the handoff")
		return false
	}
	if now.Sub(*st.HandoffSince) < handoffPeriod {
		return false
	}
	retired := r.path(CoordinatorDir + ".retired-" + now.UTC().Format("20060102-150405"))
	if err := os.Rename(r.path(CoordinatorDir), retired); err != nil {
		r.logger.Warn("retire coordinator", "error", err.Error())
		return false
	}
	st.CoordinatorPort, st.HandoffSince = 0, nil
	_ = saveSettings(r.cfg.DataDir, st)
	r.coordHandoff = false
	r.logger.Info("old coordinator retired after the handoff period")
	return true
}

func (r *Runtime) setEngineErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engineErr = describe(err)
}

func (r *Runtime) setDNSErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dnsErr = errString(err)
}

func (r *Runtime) setNetworkDNS(active bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.netDNSActive, r.netDNSErr = active, describeDNSErr(err)
}

func (r *Runtime) setCoordErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.coordErr = describe(err)
}

// Pending implements panel.App.
func (r *Runtime) Pending(ctx context.Context) ([]trust.SignedInviteEnrollment, error) {
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e == nil {
		return nil, errors.New("tunnel is not running")
	}
	return e.Pending(ctx)
}

// LiveStats implements panel.App.
func (r *Runtime) LiveStats() panel.LiveStats {
	r.mu.Lock()
	e, c := r.engine, r.coord
	r.mu.Unlock()
	var out panel.LiveStats
	if e != nil {
		if st, err := e.PeerStats(); err == nil {
			out.Direct = toTraffic(st)
		}
	}
	if c != nil {
		if st, err := c.PeerStats(); err == nil {
			out.ViaCoordinator = toTraffic(st)
		}
	}
	return out
}

func toTraffic(st map[trust.Key]wgconf.PeerStatus) map[trust.Key]panel.PeerTraffic {
	out := make(map[trust.Key]panel.PeerTraffic, len(st))
	for k, p := range st {
		t := panel.PeerTraffic{RxBytes: p.RxBytes, TxBytes: p.TxBytes, Relayed: p.Relayed}
		if p.Endpoint.IsValid() {
			t.Endpoint = p.Endpoint.String()
		}
		if p.LastHandshakeUnix > 0 {
			t.LastHandshake = time.Unix(p.LastHandshakeUnix, 0)
		}
		out[k] = t
	}
	return out
}

// Status implements panel.App.
func (r *Runtime) Status() panel.AppStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	host, _ := r.cfg.Hostname()
	st := panel.AppStatus{Mode: panel.ModeSetup, Hostname: trust.SanitizeHostname(host), SuggestedEndpoint: suggestEndpoint()}
	if r.join != nil {
		st.Mode = panel.ModeJoining
		st.Joining = &panel.JoiningStatus{Name: r.join.name, ShortCode: r.join.shortCode, Waiting: r.join.shortCode != "", Error: r.join.err}
	} else if r.lastJoinErr != "" {
		st.Error = r.lastJoinErr
	}
	var doc *trust.Document
	if store, err := member.Open(r.path(DeviceDir)); err == nil {
		st.Mode = panel.ModeMember
		st.Device = r.deviceStatusLocked(store)
		doc = store.Document()
		st.NetworkName = doc.DisplayName
	}
	if r.network != nil {
		st.Mode = panel.ModeAdmin
		// The owner's own document may be newer than the member copy.
		if own, err := r.network.Document(); err == nil {
			st.NetworkName = own.DisplayName
		}
	}
	if r.coordEP != "" || r.coordErr != "" {
		st.Coordinator = &panel.CoordinatorStatus{Endpoint: r.coordEP, Running: r.coordRun, Error: r.coordErr, Handoff: r.coordHandoff}
		if saved, err := loadSettings(r.cfg.DataDir); err == nil {
			st.Coordinator.RelayRate, st.Coordinator.RelayBurst = saved.CoordinatorRelayRate, saved.CoordinatorRelayBurst
			st.Coordinator.TCPListen = saved.CoordinatorTCPListen
			st.Coordinator.TCPMaxConns, st.Coordinator.TCPMaxConnsPerIP = saved.CoordinatorTCPMaxConns, saved.CoordinatorTCPMaxConnsPerIP
		}
		if r.coord != nil {
			if a := r.coord.TCPAddr(); a != nil {
				st.Coordinator.TCPAddr = a.String()
			}
		}
	}
	st.Health = r.healthLocked(&st, doc)
	st.PanelReadOnly = PanelReadOnly(r.cfg.DataDir)
	return st
}

func (r *Runtime) deviceStatusLocked(store *member.Store) *panel.DeviceStatus {
	doc := store.Document()
	ds := &panel.DeviceStatus{DocumentVersion: doc.Version, Error: r.engineErr, Peers: []panel.PeerInfo{}}
	secrets, err := readSecrets(r.path(DeviceDir, deviceKeyFile))
	if err != nil {
		return ds
	}
	self, err := selfDevice(doc, secrets)
	if err != nil {
		ds.Error = describe(err)
		ds.Removed = errors.Is(err, node.ErrNotMember)
		return ds
	}
	ds.Name, ds.IPv4, ds.IPv6 = self.Name, self.IPv4.String(), self.IPv6.String()
	ds.FQDN = self.Name + "." + doc.DNSDomain
	ds.ExitNodes = []panel.PeerInfo{}
	var stats map[trust.Key]wgconf.PeerStatus
	if r.engine != nil {
		stats, _ = r.engine.PeerStats()
	}
	now := r.cfg.Now()
	info := func(d trust.Device) panel.PeerInfo {
		p := panel.PeerInfo{Name: d.Name, IPv4: d.IPv4.String(), FQDN: d.Name + "." + doc.DNSDomain}
		if s, ok := stats[d.WireGuardKey]; ok && s.LastHandshakeUnix > 0 {
			p.Online = now.Sub(time.Unix(s.LastHandshakeUnix, 0)) < onlineWindow
			p.Relayed = s.Relayed
		}
		if r.engine != nil {
			p.PostQuantum, _ = r.engine.PostQuantumState(d.WireGuardKey)
		}
		return p
	}
	for _, p := range doc.PeersOf(self.Name) {
		ds.Peers = append(ds.Peers, info(p))
	}
	inv := r.Inventory()
	for _, d := range doc.Devices {
		if d.Name != self.Name && d.HasRole(trust.RoleExitNode) {
			p := info(d)
			p.Country = peerCountry(d, stats, inv)
			if rep, ok := inv.Devices[d.Name]; ok {
				p.Upstream = panel.UpstreamOf(rep.Info)
			}
			ds.ExitNodes = append(ds.ExitNodes, p)
		}
	}
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Unreadable settings: show the defaults, as the tunnel does.
		st = settings{}
	}
	ds.Connected = !st.Disconnected
	if st.Disconnected && st.DisconnectedUntil != nil {
		t := *st.DisconnectedUntil
		ds.DisconnectedUntil = &t
	}
	if r.engine != nil {
		ds.ExitNode = r.engine.ExitNode()
	}
	ds.ExitNodeWanted = st.ExitNode
	ds.KillSwitch, ds.ExitAllowLAN = st.killSwitchOn(), st.ExitAllowLAN
	ds.Shields = st.Shields
	for _, p := range ds.ExitNodes {
		if p.Name == st.LastExitNode {
			ds.LastExitNode = st.LastExitNode
		}
	}
	ds.AcceptNetworkDNS = !st.IgnoreNetworkDNS
	ds.NetworkDNSActive, ds.NetworkDNSError = r.netDNSActive, r.netDNSErr
	ds.MTU, ds.ForceRelay = st.MTU, st.ForceRelay
	ds.Transport = transportStatus(st)
	if r.engine != nil {
		ds.CoordinatorOverTCP = r.engine.CoordinatorOverTCP()
	}
	ds.Pinned = append([]string{}, st.Pinned...)
	sortPinned(ds.Peers, st.Pinned)
	if exp := self.ExpiresAt; !exp.IsZero() {
		t := exp
		ds.MembershipExpiresAt = &t
	}
	ks := r.killSwitchSnapshot()
	ds.KillSwitchSupported = r.killSwitchAvailable()
	ds.KillSwitchActive, ds.KillSwitchError = ks.installed, ks.err
	if r.engine != nil {
		s := r.engine.Status()
		ds.Running = true
		if !s.LastSync.IsZero() {
			t := s.LastSync
			ds.LastSync = &t
		}
		ds.LastSyncError = s.LastSyncError
	}
	ds.Wave3 = r.wave3StatusLocked()
	return ds
}

func readSecrets(path string) (*trust.DeviceSecrets, error) {
	data, err := securefile.ReadPrivate(path, trust.MaxDeviceKeySize)
	if err != nil {
		return nil, err
	}
	defer wipe(data)
	return unmarshalDeviceKey(data) // TPM-sealed or plain, wire_tpm.go (ADR-0208)
}

// loadOrCreateSecrets returns the key in path, creating it once.
func loadOrCreateSecrets(path string, random io.Reader, now time.Time) (*trust.DeviceSecrets, error) {
	s, err := readSecrets(path)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	s, err = trust.GenerateDeviceSecrets(random, now)
	if err != nil {
		return nil, err
	}
	data, err := trust.MarshalDeviceSecrets(s)
	if err != nil {
		return nil, err
	}
	defer wipe(data)
	if err := securefile.WriteNew(path, data); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return s, nil
}

func selfDevice(doc *trust.Document, secrets *trust.DeviceSecrets) (trust.Device, error) {
	_, wg, err := secrets.PublicKeys()
	if err != nil {
		return trust.Device{}, err
	}
	for _, d := range doc.Devices {
		if d.WireGuardKey == wg {
			return d, nil
		}
	}
	return trust.Device{}, node.ErrNotMember
}

func describe(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, node.ErrNotMember):
		return "Bu bilgisayar ağdan çıkarılmış veya henüz eklenmemiş."
	case errors.Is(err, node.ErrInviteGone):
		return "Davet artık geçerli değil (süresi dolmuş veya iptal edilmiş). Yöneticiden yeni bir davet kodu isteyin."
	case errors.Is(err, node.ErrInviteTaken):
		return "Bu davet başka bir cihaz için onaylandı. Yöneticiden yeni bir davet kodu isteyin."
	case errors.Is(err, node.ErrInviteRejected):
		return "Koordinatör katılım isteğini reddetti. Yöneticiden yeni bir davet kodu isteyin."
	}
	return admin.Describe(err)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
