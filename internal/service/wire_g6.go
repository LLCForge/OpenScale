package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/p2psend"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

// Wiring of the G6 parts that live while the tunnel runs:
//   - end-to-end file transfer (ADR-0204): the panel's E2E endpoints use a
//     p2psend.Service built from the device key and the signed document;
//     when this device hosts the "files" service, the receiving server
//     listens on its tunnel address (p2psend.DefaultPort);
//   - tamper watch (ADR-0207): the running program is hashed periodically
//     and differences are kept in a signed, chained log;
//   - TPM status (ADR-0208): whether device.key is sealed.

const (
	e2eDirName        = "e2e"
	e2eSettingsFile   = "e2e.json"
	tamperDirName     = "tamper"
	tamperEvery       = 10 * time.Minute
	maxTamperInMemory = 256
	maxE2ESettings    = 1 << 10
	maxTamperLog      = 4 << 20
)

// wireState is the Runtime's share of the wiring.
type wireState struct {
	mu     sync.Mutex
	e2e    *p2psend.Service
	listen netip.AddrPort
	events []posture.TamperEvent
	// Tests only: listen address, watched files and check interval.
	listenOverride netip.AddrPort
	tamperPaths    []string
	tamperEvery    time.Duration
}

var (
	_ panel.E2EFileControl = (*Runtime)(nil)
	_ panel.TamperControl  = (*Runtime)(nil)
	_ panel.TPMControl     = (*Runtime)(nil)
)

var errE2EOff = errors.New("uçtan uca aktarım için tünel açık olmalı")

type e2eSettings struct {
	Relay bool `json:"relay"`
}

func (r *Runtime) loadE2ESettings() e2eSettings {
	var s e2eSettings
	data, err := securefile.ReadPrivate(r.path(e2eDirName, e2eSettingsFile), maxE2ESettings)
	if err == nil {
		if json.Unmarshal(data, &s) != nil {
			s = e2eSettings{}
		}
	}
	return s
}

func (r *Runtime) saveE2ESettings(s e2eSettings) error {
	if err := os.MkdirAll(r.path(e2eDirName), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return securefile.Replace(r.path(e2eDirName, e2eSettingsFile), data)
}

// docDirectory answers from the verified signed document only.
type docDirectory struct {
	store *member.Store
	now   func() time.Time // nil uses time.Now
}

func peerOf(d trust.Device) p2psend.Peer {
	return p2psend.Peer{Name: d.Name, Key: p2psend.Key(d.WireGuardKey), Addr: d.IPv4}
}

// current reports whether dev's membership is still valid.
//
// SECURITY FIX: CWE-672 the engine drops an expired device from the tunnel,
// but the document keeps naming it and its rules. On a relayed stream the
// receiver only sees the last relay, so the directory must not resolve it.
func (d docDirectory) current(dev trust.Device) bool {
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	return now().Before(dev.ExpiresAt)
}

func (d docDirectory) ByKey(k p2psend.Key) (p2psend.Peer, bool) {
	for _, dev := range d.store.Document().Devices {
		if p2psend.Key(dev.WireGuardKey) == k && d.current(dev) {
			return peerOf(dev), true
		}
	}
	return p2psend.Peer{}, false
}

func (d docDirectory) ByAddr(a netip.Addr) (p2psend.Peer, bool) {
	a = a.Unmap()
	for _, dev := range d.store.Document().Devices {
		if dev.IPv4 == a && d.current(dev) {
			return peerOf(dev), true
		}
	}
	return p2psend.Peer{}, false
}

func (d docDirectory) byName(name string) (p2psend.Peer, bool) {
	dev, ok := d.store.Document().DeviceByName(name)
	if !ok || !d.current(dev) {
		return p2psend.Peer{}, false
	}
	return peerOf(dev), true
}

// startWire starts the tunnel-bound parts; they stop with ctx.
func (r *Runtime) startWire(ctx context.Context, store *member.Store, secrets *trust.DeviceSecrets, self trust.Device) {
	if err := r.startE2E(ctx, store, secrets, self); err != nil {
		r.logger.Warn("end-to-end file transfer not started", "error", err.Error())
	}
	if err := r.startTamper(ctx, secrets, self); err != nil {
		r.logger.Warn("tamper watch not started", "error", err.Error())
	}
}

func (r *Runtime) startE2E(ctx context.Context, store *member.Store, secrets *trust.DeviceSecrets, self trust.Device) error {
	if len(secrets.WireGuardPrivate) != p2psend.KeySize {
		return errors.New("cihaz anahtarı biçimi beklenmedik")
	}
	var priv [p2psend.KeySize]byte
	copy(priv[:], secrets.WireGuardPrivate)
	id, err := p2psend.NewIdentity(priv)
	clear(priv[:])
	if err != nil {
		return err
	}
	dir := docDirectory{store: store, now: r.cfg.Now}
	settings := r.loadE2ESettings()
	approvals := p2psend.NewApprovals(0)
	registry := p2psend.NewRegistry()
	qdir := r.path(e2eDirName, "karantina")
	svc := &p2psend.Service{
		Identity: id, Approvals: approvals, Registry: registry,
		Q:       p2psend.Quarantine{Dir: qdir, Inbox: r.path(e2eDirName, "gelen")},
		Resolve: dir.byName, Port: p2psend.DefaultPort, Context: ctx,
		OnRelayChange: func(on bool) error {
			// Takes effect the next time the tunnel starts.
			return r.saveE2ESettings(e2eSettings{Relay: on})
		},
	}
	if settings.Relay {
		_ = svc.SetE2ERelay(true)
	}
	var addr netip.AddrPort
	if store.Document().HostsService(self.Name, trust.ServiceFiles) && self.IPv4.IsValid() {
		srv, err := p2psend.NewServer(p2psend.Config{
			Identity: id, Directory: dir, QuarantineDir: qdir, Ask: approvals.Ask, AllowFile: func(from string) bool { return store.Document().AllowsFileSend(from, self.Name) },
			Relay: settings.Relay, RelayPort: p2psend.DefaultPort, Registry: registry,
			Logger: r.logger.With("service", "e2e-files"), Now: r.cfg.Now,
		})
		if err != nil {
			return err
		}
		addr = netip.AddrPortFrom(self.IPv4, p2psend.DefaultPort)
		if r.wire.listenOverride.IsValid() {
			addr = r.wire.listenOverride
		}
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp4", addr.String())
		if err != nil {
			// Sending still works; receiving waits for the next start.
			r.logger.Warn("end-to-end receiver not listening", "error", err.Error())
			addr = netip.AddrPort{}
		} else {
			if ta, ok := ln.Addr().(*net.TCPAddr); ok {
				addr = ta.AddrPort()
			}
			r.spawn(func() {
				if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
					r.logger.Warn("end-to-end receiver stopped", "error", err.Error())
				}
			})
		}
	}
	r.wire.mu.Lock()
	r.wire.e2e, r.wire.listen = svc, addr
	r.wire.mu.Unlock()
	go func() {
		<-ctx.Done()
		r.wire.mu.Lock()
		if r.wire.e2e == svc {
			r.wire.e2e, r.wire.listen = nil, netip.AddrPort{}
		}
		r.wire.mu.Unlock()
	}()
	return nil
}

func (r *Runtime) e2eService() (*p2psend.Service, error) {
	r.wire.mu.Lock()
	defer r.wire.mu.Unlock()
	if r.wire.e2e == nil {
		return nil, errE2EOff
	}
	return r.wire.e2e, nil
}

// E2ETransfers implements panel.E2EFileControl.
func (r *Runtime) E2ETransfers() []p2psend.TransferView {
	if s, err := r.e2eService(); err == nil {
		return s.E2ETransfers()
	}
	return []p2psend.TransferView{}
}

// E2EPending implements panel.E2EFileControl.
func (r *Runtime) E2EPending() []p2psend.Offer {
	if s, err := r.e2eService(); err == nil {
		return s.E2EPending()
	}
	return []p2psend.Offer{}
}

// E2EDecide implements panel.E2EFileControl.
func (r *Runtime) E2EDecide(id string, accept bool) error {
	s, err := r.e2eService()
	if err != nil {
		return err
	}
	return s.E2EDecide(id, accept)
}

// E2EStart implements panel.E2EFileControl.
func (r *Runtime) E2EStart(req p2psend.SendRequest) error {
	s, err := r.e2eService()
	if err != nil {
		return err
	}
	return s.E2EStart(req)
}

// E2EQuarantine implements panel.E2EFileControl.
func (r *Runtime) E2EQuarantine() p2psend.Quarantine {
	if s, err := r.e2eService(); err == nil {
		return s.E2EQuarantine()
	}
	return p2psend.Quarantine{Dir: r.path(e2eDirName, "karantina"), Inbox: r.path(e2eDirName, "gelen")}
}

// E2ERelay implements panel.E2EFileControl.
func (r *Runtime) E2ERelay() bool {
	if s, err := r.e2eService(); err == nil {
		return s.E2ERelay()
	}
	return r.loadE2ESettings().Relay
}

// SetE2ERelay implements panel.E2EFileControl.
func (r *Runtime) SetE2ERelay(on bool) error {
	if s, err := r.e2eService(); err == nil {
		return s.SetE2ERelay(on)
	}
	return r.saveE2ESettings(e2eSettings{Relay: on})
}

// --- tamper watch ---

func (r *Runtime) startTamper(ctx context.Context, secrets *trust.DeviceSecrets, self trust.Device) error {
	paths := r.wire.tamperPaths
	if len(paths) == 0 {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		paths = []string{exe}
	}
	key := secrets.SigningKey()
	dir := r.path(tamperDirName)
	w, err := posture.OpenTamperWatcher(posture.TamperConfig{
		Device: self.Name, Paths: paths, StateDir: dir, Key: key, Now: r.cfg.Now,
	})
	if err != nil {
		return err
	}
	// Earlier events from the signed log; a broken log is reported, not
	// trusted.
	if f, err := os.Open(filepath.Join(dir, "tamper.log")); err == nil {
		pub, _ := key.Public().(ed25519.PublicKey)
		evs, verr := posture.VerifyTamperLog(io.LimitReader(f, maxTamperLog), pub)
		_ = f.Close()
		if verr != nil {
			r.logger.Warn("tamper log does not verify", "error", verr.Error())
		}
		r.addTamper(evs)
	} else if !errors.Is(err, fs.ErrNotExist) {
		r.logger.Warn("tamper log unreadable", "error", err.Error())
	}
	every := tamperEvery
	if r.wire.tamperEvery > 0 {
		every = r.wire.tamperEvery
	}
	r.spawn(func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			evs, err := w.Check()
			if err != nil {
				r.logger.Warn("tamper check", "error", err.Error())
			} else if len(evs) > 0 {
				r.logger.Warn("program files changed", "count", len(evs))
				r.addTamper(evs)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
	return nil
}

func (r *Runtime) addTamper(evs []posture.TamperEvent) {
	if len(evs) == 0 {
		return
	}
	r.wire.mu.Lock()
	defer r.wire.mu.Unlock()
	r.wire.events = append(r.wire.events, evs...)
	if n := len(r.wire.events); n > maxTamperInMemory {
		r.wire.events = append([]posture.TamperEvent(nil), r.wire.events[n-maxTamperInMemory:]...)
	}
}

// TamperEvents implements panel.TamperControl.
func (r *Runtime) TamperEvents() []posture.TamperEvent {
	r.wire.mu.Lock()
	defer r.wire.mu.Unlock()
	return append([]posture.TamperEvent{}, r.wire.events...)
}

// DeviceKeySealed implements panel.TPMControl.
func (r *Runtime) DeviceKeySealed() (bool, string) {
	data, err := securefile.ReadPrivate(r.path(DeviceDir, deviceKeyFile), trust.MaxDeviceKeySize)
	if err != nil {
		return false, ""
	}
	defer wipe(data)
	return tpm.SealedKind(data)
}
