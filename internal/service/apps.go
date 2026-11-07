package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/speedtest"
	"github.com/openscale/openscale/internal/sshd"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

// Remote access and diagnostics services (ADR-0030, ADR-0031).
//
// Apps runs the embedded SSH server, the file inbox, the Wake-on-LAN relay
// and the speed test server on this device's tunnel IPv4 address. A server
// listens only while an enabled allow rule of the signed document names
// this device for its service; every connection is decided again from the
// rules through the trust policy functions, by the tunnel source address.
// Nothing is sent to or stored at the coordinator.

// Layout under the data (or state) directory.
const (
	AppsDir       = "apps"
	InboxDir      = "inbox"
	hostKeyFile   = "ssh_host_ed25519_key"
	autoAcceptFn  = "autoaccept.json"
	receivedFn    = "received.json"
	wakeMACsFn    = "wake-macs.json"
	outboxDir     = "outbox"
	maxStateFile  = 1 << 20
	maxReceived   = 500
	maxAutoAccept = 256
)

const (
	appsInterval      = 3 * time.Second
	appsRetryDelay    = 10 * time.Second
	offerTimeout      = 2 * time.Minute
	maxPendingOffers  = 16
	maxTransfers      = 50
	maxActiveSends    = 2
	maxPanelUpload    = int64(2) << 30
	speedtestMaxPanel = 10
	speedtestMaxDur   = 10 * time.Second
)

// AppEngine is the part of the tunnel engine the services need.
type AppEngine interface {
	Document() *trust.Document
	Self() (trust.Device, error)
}

// AppsConfig configures Apps.
type AppsConfig struct {
	// Dir is the data directory (service) or state directory (openscale up).
	Dir string
	// Engine returns the running tunnel engine, or nil while it is down.
	Engine func() AppEngine
	// TunnelInterface names the tunnel interface, skipped when sending
	// Wake-on-LAN packets; may be nil.
	TunnelInterface func() string
	// Reports returns the latest system reports of other devices (admin
	// devices only); may be nil.
	Reports func() map[string]sysinfo.Info
	// Interactive makes file offers wait for the owner's decision in the
	// panel. Without it only devices on the auto-accept list can send.
	Interactive bool
	Logger      *slog.Logger
	Interval    time.Duration
	Now         func() time.Time
	// RemoteDesktop runs the remote desktop server (ADR-0110); nil means
	// this device cannot show its screen and an rdesk rule stays unserved.
	RemoteDesktop RemoteDesktopHost
}

type serviceRunner struct {
	addr    netip.AddrPort
	bound   netip.AddrPort
	cancel  context.CancelFunc
	done    chan struct{}
	err     string
	retryAt time.Time
	running bool
}

type pendingOffer struct {
	view   panel.PendingOffer
	decide chan bool
}

type transferJob struct {
	status panel.TransferStatus
}

// Apps runs the services.
type Apps struct {
	cfg AppsConfig
	log *slog.Logger

	mu          sync.Mutex
	runCtx      context.Context
	runners     map[trust.RuleService]*serviceRunner
	sshSrv      *sshd.Server
	fingerprint string
	lastVersion uint64
	pending     map[string]*pendingOffer
	transfers   []*transferJob
	sending     int
	stateMu     sync.Mutex // serializes state file writes

	// Test seams: listenHost replaces the tunnel address servers bind to,
	// mapPeer maps a connection's source to a tunnel address and wakeSend
	// replaces the LAN broadcast.
	listenHost netip.Addr
	anyPort    bool
	mapPeer    func(netip.Addr) netip.Addr
	wakeSend   func(context.Context, *trust.Document, net.HardwareAddr) (int, error)

	// extState holds the remote desktop and sync state (apps_ext.go).
	extState appsExt
	// p18State holds the tunnel services: publishing, internal CA issuer
	// and identity provider (apps_p18.go, ADR-0138, ADR-0139).
	p18State p18State
	// supportHostState is the remote support toolbox (support_host.go,
	// ADR-0232); created on first use under mu.
	supportHostState *supportHost
}

// NewApps returns the services; call Run to start them.
func NewApps(cfg AppsConfig) *Apps {
	if cfg.Interval <= 0 {
		cfg.Interval = appsInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	a := &Apps{
		cfg:     cfg,
		log:     cfg.Logger,
		runCtx:  context.Background(),
		runners: map[trust.RuleService]*serviceRunner{},
		pending: map[string]*pendingOffer{},
	}
	a.fingerprint = HostKeyFingerprint(cfg.Dir)
	return a
}

// Run keeps the services in line with the signed document until ctx ends.
func (a *Apps) Run(ctx context.Context) {
	a.mu.Lock()
	a.runCtx = ctx
	a.mu.Unlock()
	a.cleanOutbox()
	go a.runExt(ctx)
	go a.runP18(ctx)
	sysinfo.SetExtra(a.fillInfo)
	defer sysinfo.SetExtra(nil)
	ticker := time.NewTicker(a.cfg.Interval)
	defer ticker.Stop()
	for {
		a.sync(ctx)
		select {
		case <-ctx.Done():
			a.stopAll()
			return
		case <-ticker.C:
		}
	}
}

func (a *Apps) appsPath(parts ...string) string {
	return filepath.Join(append([]string{a.cfg.Dir, AppsDir}, parts...)...)
}

func (a *Apps) inboxPath() string { return filepath.Join(a.cfg.Dir, InboxDir) }

// current returns the document and this device while the tunnel runs.
func (a *Apps) current() (*trust.Document, trust.Device, bool) {
	if a.cfg.Engine == nil {
		return nil, trust.Device{}, false
	}
	e := a.cfg.Engine()
	if e == nil {
		return nil, trust.Device{}, false
	}
	doc := e.Document()
	if doc == nil {
		return nil, trust.Device{}, false
	}
	self, err := e.Self()
	if err != nil || !self.IPv4.IsValid() {
		return nil, trust.Device{}, false
	}
	return doc, self, true
}

// peer maps a tunnel source address to a device of the current document.
func (a *Apps) peer(from netip.Addr) (*trust.Document, trust.Device, trust.Device, bool) {
	doc, self, ok := a.current()
	if !ok {
		return nil, trust.Device{}, trust.Device{}, false
	}
	if a.mapPeer != nil {
		from = a.mapPeer(from)
	}
	dev, ok := doc.DeviceByAddr(from)
	if !ok || dev.Name == self.Name {
		return nil, trust.Device{}, trust.Device{}, false
	}
	return doc, self, dev, true
}

func (a *Apps) sync(ctx context.Context) {
	doc, self, ok := a.current()
	for _, svc := range trust.Services() {
		want := ok && doc.HostsService(self.Name, svc)
		var addr netip.AddrPort
		if ok {
			host := self.IPv4
			if a.listenHost.IsValid() {
				host = a.listenHost
			}
			port := svc.Port()
			if a.anyPort {
				port = 0
			}
			addr = netip.AddrPortFrom(host, port)
		}
		a.reconcile(ctx, svc, want, addr)
	}
	a.mu.Lock()
	changed := ok && doc.Version != a.lastVersion
	if ok {
		a.lastVersion = doc.Version
	} else {
		a.lastVersion = 0
	}
	srv := a.sshSrv
	a.mu.Unlock()
	if changed && srv != nil {
		// Rules changed: sessions whose permission was withdrawn end now.
		if n := srv.Revalidate(); n > 0 {
			a.log.Info("SSH sessions closed after a rule change", "count", n)
		}
	}
	if changed {
		a.revalidateExt()
	}
	if ok {
		a.recordReports()
	}
}

func (a *Apps) reconcile(ctx context.Context, svc trust.RuleService, want bool, addr netip.AddrPort) {
	a.mu.Lock()
	r := a.runners[svc]
	if r == nil {
		r = &serviceRunner{}
		a.runners[svc] = r
	}
	if r.running {
		select {
		case <-r.done:
			// The server stopped on its own; try again later.
			r.running, r.cancel = false, nil
			r.retryAt = a.cfg.Now().Add(appsRetryDelay)
			if svc == trust.ServiceSSH {
				a.sshSrv = nil
			}
		default:
		}
	}
	if r.running && (!want || r.addr != addr) {
		cancel, done := r.cancel, r.done
		r.running, r.cancel = false, nil
		if svc == trust.ServiceSSH {
			a.sshSrv = nil
		}
		a.mu.Unlock()
		cancel()
		<-done
		a.log.Info("service stopped", "service", string(svc))
		a.mu.Lock()
	}
	if !want {
		r.err, r.retryAt = "", time.Time{}
		a.mu.Unlock()
		return
	}
	if r.running || a.cfg.Now().Before(r.retryAt) {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	cancel, done, bound, err := a.start(ctx, svc, addr)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		r.err = err.Error()
		r.retryAt = a.cfg.Now().Add(appsRetryDelay)
		a.log.Warn("service could not start", "service", string(svc), "error", err.Error())
		return
	}
	r.addr, r.bound, r.cancel, r.done, r.running, r.err = addr, bound, cancel, done, true, ""
	a.log.Info("service listening on the tunnel", "service", string(svc), "port", bound.Port())
}

func (a *Apps) start(ctx context.Context, svc trust.RuleService, addr netip.AddrPort) (context.CancelFunc, chan struct{}, netip.AddrPort, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp4", addr.String())
	if err != nil {
		return nil, nil, netip.AddrPort{}, fmt.Errorf("tünel adresi dinlenemedi: %w", err)
	}
	bound := addr
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		bound = netip.AddrPortFrom(ta.AddrPort().Addr().Unmap(), ta.AddrPort().Port())
	}
	sctx, cancel := context.WithCancel(ctx)
	var serve func() error
	switch svc {
	case trust.ServiceSSH:
		if err := os.MkdirAll(a.appsPath(), 0o700); err != nil {
			_ = ln.Close()
			cancel()
			return nil, nil, netip.AddrPort{}, err
		}
		srv, err := sshd.New(sshd.Config{
			ListenAddr:       addr,
			HostKeyPath:      a.appsPath(hostKeyFile),
			Authorize:        a.authorizeSSH,
			AuthorizeForward: a.authorizeForward,
			Logger:           a.log.With("service", "ssh"),
		})
		if err != nil {
			_ = ln.Close()
			cancel()
			return nil, nil, netip.AddrPort{}, err
		}
		a.mu.Lock()
		a.sshSrv = srv
		a.fingerprint = ssh.FingerprintSHA256(srv.HostKey())
		a.mu.Unlock()
		serve = func() error { return srv.Serve(sctx, ln) }
	case trust.ServiceFiles:
		srv, err := filesend.NewServer(filesend.Config{
			ListenAddr: addr,
			InboxDir:   a.inboxPath(),
			Accept:     a.acceptFile,
			OnReceived: a.received,
			Logger:     a.log.With("service", "files"),
		})
		if err != nil {
			_ = ln.Close()
			cancel()
			return nil, nil, netip.AddrPort{}, err
		}
		serve = func() error { return srv.Serve(sctx, ln) }
	case trust.ServiceSpeedtest:
		srv, err := speedtest.NewServer(speedtest.Config{
			ListenAddr:  addr,
			Allow:       a.allowSpeedtest,
			MaxDuration: speedtestMaxDur,
			Logger:      a.log.With("service", "speedtest"),
		})
		if err != nil {
			_ = ln.Close()
			cancel()
			return nil, nil, netip.AddrPort{}, err
		}
		serve = func() error { return srv.Serve(sctx, ln) }
	case trust.ServiceRemoteDesktop, trust.ServiceSync:
		s, err := a.startExt(sctx, svc, ln, addr)
		if err != nil {
			_ = ln.Close()
			cancel()
			return nil, nil, netip.AddrPort{}, err
		}
		serve = s
	case trust.ServiceWake:
		ws := newWakeServer(a)
		serve = func() error { return ws.serve(sctx, ln) }
	case trust.ServiceSupport: // ADR-0232, support_host.go
		s, err := a.startSupport(sctx, ln)
		if err != nil {
			_ = ln.Close()
			cancel()
			return nil, nil, netip.AddrPort{}, err
		}
		serve = s
	default:
		_ = ln.Close()
		cancel()
		return nil, nil, netip.AddrPort{}, fmt.Errorf("bilinmeyen servis %q", svc)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serve(); err != nil && sctx.Err() == nil {
			a.log.Warn("service stopped with an error", "service", string(svc), "error", err.Error())
			a.mu.Lock()
			if r := a.runners[svc]; r != nil {
				r.err = err.Error()
			}
			a.mu.Unlock()
		}
	}()
	return cancel, done, bound, nil
}

func (a *Apps) stopAll() {
	a.mu.Lock()
	var waits []chan struct{}
	for _, r := range a.runners {
		if r.running {
			r.cancel()
			waits = append(waits, r.done)
			r.running = false
		}
	}
	a.sshSrv = nil
	for id, p := range a.pending {
		select {
		case p.decide <- false:
		default:
		}
		delete(a.pending, id)
	}
	a.mu.Unlock()
	for _, d := range waits {
		<-d
	}
}

// --- authorization callbacks ---

func (a *Apps) authorizeSSH(remote netip.Addr, user string) (bool, string) {
	doc, self, dev, ok := a.peer(remote)
	if !ok {
		return false, "kaynak adres ağdaki bir cihaz değil"
	}
	ruleUser, ok := sshRuleUser(user)
	if !ok {
		return false, "bu sistemde yalnızca hizmet hesabıyla (system) oturum açılabilir"
	}
	if !doc.AllowsSSH(dev.Name, self.Name, ruleUser) {
		return false, "kural izin vermiyor"
	}
	// An account with uid 0 under another name is still root.
	if ruleUser != trust.SSHRootUser && accountIsSuperuser(user) && !doc.AllowsSSH(dev.Name, self.Name, trust.SSHRootUser) {
		return false, "yönetici (uid 0) hesabı için allow_root gerekir"
	}
	return true, ""
}

func (a *Apps) authorizeForward(remote netip.Addr, user string, dst netip.AddrPort) (bool, string) {
	doc, self, dev, ok := a.peer(remote)
	if !ok {
		return false, "kaynak adres ağdaki bir cihaz değil"
	}
	ruleUser, ok := sshRuleUser(user)
	if !ok || !doc.AllowsSSHForward(dev.Name, self.Name, ruleUser) {
		return false, "kural port yönlendirmeye izin vermiyor"
	}
	// A forward must not reach other OpenScale devices: it would carry the
	// client's traffic with this device's identity past their rules.
	d := dst.Addr()
	if (doc.IPv4Prefix.Contains(d) || doc.IPv6Prefix.Contains(d)) && d != self.IPv4 && d != self.IPv6 {
		return false, "yönlendirme hedefi başka bir OpenScale cihazı olamaz"
	}
	return true, ""
}

func (a *Apps) allowSpeedtest(from netip.Addr) bool {
	doc, self, dev, ok := a.peer(from)
	return ok && doc.AllowsSpeedtest(dev.Name, self.Name)
}

// --- system report fields ---

func (a *Apps) fillInfo(in *sysinfo.Info) {
	a.mu.Lock()
	fp := a.fingerprint
	a.mu.Unlock()
	in.SSHHostKey = fp
	in.WakeMAC = a.localWakeMAC()
}

// HostKeyFingerprint returns the SHA256 fingerprint of the SSH host key
// stored under dir, or "" when there is none yet.
func HostKeyFingerprint(dir string) string {
	data, err := securefile.ReadPrivate(filepath.Join(dir, AppsDir, hostKeyFile), 16<<10)
	if err != nil {
		return ""
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(signer.PublicKey())
}

// recordReports stores the Wake-on-LAN MAC addresses other devices
// reported (admin devices only), so a sleeping device can still be woken.
func (a *Apps) recordReports() {
	if a.cfg.Reports == nil {
		return
	}
	reports := a.cfg.Reports()
	if len(reports) == 0 {
		return
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	macs, _ := LoadWakeMACs(a.cfg.Dir)
	changed := false
	for name, in := range reports {
		if in.WakeMAC != "" && macs[name] != in.WakeMAC && macs[manualKey(name)] == "" {
			macs[name] = in.WakeMAC
			changed = true
		}
	}
	if changed {
		if err := saveJSON(a.appsPath(wakeMACsFn), macs); err != nil {
			a.log.Warn("save wake addresses", "error", err.Error())
		}
	}
}

// manualKey marks a MAC set by the owner; reports never overwrite it.
func manualKey(name string) string { return name + "#manual" }

// --- state files ---

func newID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func errNoTunnel() error { return errors.New("tünel kapalı; önce bağlanın") }

func containsName(list []string, name string) bool { return slices.Contains(list, name) }

func normalizeDevice(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
