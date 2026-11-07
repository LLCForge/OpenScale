package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
)

// Services added in connection wave 2 (ADR-0110): the remote desktop and
// folder sync. They plug into the same reconcile loop as SSH and files:
// a server runs only while an allow rule names this device.

// appsExt holds the wave 2 state of Apps.
type appsExt struct {
	once  sync.Once
	rdesk *rdeskTracker
	sync  syncState
	// noKick keeps QueueFile from sending at once (tests).
	noKick bool
}

const extEvery = 30 * time.Second

func (a *Apps) ext() *appsExt {
	a.extState.once.Do(func() {
		a.extState.rdesk = newRDeskTracker(a.cfg.Now, a.log)
	})
	return &a.extState
}

// startExt returns the serve function of a wave 2 service.
func (a *Apps) startExt(ctx context.Context, svc trust.RuleService, ln net.Listener, addr netip.AddrPort) (func() error, error) {
	switch svc {
	case trust.ServiceRemoteDesktop:
		return a.startRDesk(ctx, ln, addr)
	case trust.ServiceSync:
		return a.startSync(ctx, ln, addr)
	}
	return nil, errors.New("bilinmeyen servis")
}

func (a *Apps) startRDesk(ctx context.Context, ln net.Listener, addr netip.AddrPort) (func() error, error) {
	host := a.cfg.RemoteDesktop
	if host == nil {
		// Fail closed: without a desktop to show the screen of (and the
		// indicator on) nothing listens.
		return nil, errors.New("bu cihazda uzak masaüstü sunucusu çalıştırılamıyor (masaüstü oturumu yok)")
	}
	settings, err := LoadRemoteDesktopSettings(a.cfg.Dir)
	if err != nil {
		return nil, errors.New("uzak masaüstü ayarları okunamadı: " + err.Error())
	}
	_, self, ok := a.current()
	if !ok {
		return nil, errNoTunnel()
	}
	tracker := a.ext().rdesk
	env := RemoteDesktopEnv{
		Addr:      addr,
		Device:    self.Name,
		Authorize: a.authorizeRDesk,
		OnEvent:   func(ev rdesk.SessionEvent) { tracker.event("p", ev) },
		Settings:  settings,
		Dir:       a.cfg.Dir,
		Logger:    a.log.With("service", "rdesk"),
	}
	return func() error {
		defer tracker.endSource("p", "sunucu durdu")
		return host.Serve(ctx, ln, env)
	}, nil
}

// revalidateExt ends sessions whose permission was withdrawn.
func (a *Apps) revalidateExt() {
	if h := a.cfg.RemoteDesktop; h != nil {
		h.Revalidate()
	}
}

// restartService stops a running server so the next round starts it with
// new settings.
func (a *Apps) restartService(svc trust.RuleService) {
	a.mu.Lock()
	r := a.runners[svc]
	if r == nil || !r.running {
		a.mu.Unlock()
		return
	}
	cancel, done := r.cancel, r.done
	r.running, r.cancel, r.retryAt = false, nil, time.Time{}
	a.mu.Unlock()
	cancel()
	<-done
	a.log.Info("service restarted for new settings", "service", string(svc))
}

// runExt runs the outbox and the sync and backup timers.
func (a *Apps) runExt(ctx context.Context) {
	t := time.NewTicker(extEvery)
	defer t.Stop()
	defer a.closeFolders()
	for {
		a.runOutbox(ctx)
		a.syncDue(a.cfg.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RDeskEvent records an event of a session that runs in the desktop
// helper (source names the helper run).
func (a *Apps) RDeskEvent(source string, ev rdesk.SessionEvent) { a.ext().rdesk.event(source, ev) }

// RDeskEndSource closes the sessions of a helper run that stopped.
func (a *Apps) RDeskEndSource(source, reason string) { a.ext().rdesk.endSource(source, reason) }

// RDeskAuthorize decides a helper's session request.
func (a *Apps) RDeskAuthorize(remote netip.Addr, mode rdesk.Mode) rdesk.Decision {
	return a.authorizeRDesk(remote, mode)
}

// RDeskStatus implements panel.RemoteDesktopControl.
func (a *Apps) RDeskStatus() panel.RDeskStatus {
	out := panel.RDeskStatus{Supported: a.cfg.RemoteDesktop != nil}
	if h := a.cfg.RemoteDesktop; h != nil {
		out.Runner = h.Kind()
	}
	if s, err := LoadRemoteDesktopSettings(a.cfg.Dir); err == nil {
		out.Settings = panel.RDeskSettings{Recording: s.Recording, RecordingDays: s.RecordingDays, LocalLock: s.LocalLock, Power: s.Power,
			FileRoots: append([]string{}, s.FileRoots...)}
	} else {
		out.Error = "ayarlar okunamadı: " + err.Error()
	}
	if out.Settings.RecordingDays == 0 {
		out.Settings.RecordingDays = defaultRecordingDays
	}
	if doc, self, ok := a.current(); ok {
		out.Hosted = doc.HostsService(self.Name, trust.ServiceRemoteDesktop)
	}
	a.mu.Lock()
	if r := a.runners[trust.ServiceRemoteDesktop]; r != nil {
		out.Running = r.running
		if r.err != "" {
			out.Error = r.err
		}
	}
	a.mu.Unlock()
	out.Sessions, out.Recent = a.ext().rdesk.snapshot()
	return out
}

// SetRDeskSettings implements panel.RemoteDesktopControl; a running server
// restarts with the new settings (sessions end).
func (a *Apps) SetRDeskSettings(c panel.RDeskSettingsChange) error {
	s, err := LoadRemoteDesktopSettings(a.cfg.Dir)
	if err != nil {
		return err
	}
	next := s
	if c.Recording != nil {
		next.Recording = *c.Recording
	}
	if c.RecordingDays != nil {
		if *c.RecordingDays < 1 || *c.RecordingDays > maxRecordingDays {
			return errors.New("kayıt saklama süresi 1 ile 3650 gün arasında olmalı")
		}
		next.RecordingDays = *c.RecordingDays
	}
	if c.LocalLock != nil {
		next.LocalLock = *c.LocalLock
	}
	if c.Power != nil {
		next.Power = *c.Power
	}
	if c.FileRoots != nil {
		next.FileRoots = slices.Clone(*c.FileRoots)
		if len(next.FileRoots) == 0 {
			next.FileRoots = nil
		}
	}
	if next.Equal(s) {
		return nil
	}
	if err := SaveRemoteDesktopSettings(a.cfg.Dir, next); err != nil {
		return err
	}
	a.log.Info("remote desktop settings changed", "recording", next.Recording, "local_lock", next.LocalLock, "power", next.Power)
	go a.restartService(trust.ServiceRemoteDesktop)
	return nil
}
