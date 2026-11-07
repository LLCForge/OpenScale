package service

import (
	"context"
	"errors"
	"io"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sysinfo"
)

// The desktop service implements panel.RemoteApps with Apps.
var _ panel.RemoteApps = (*Runtime)(nil)

func (r *Runtime) startApps(ctx context.Context) {
	interval := appsInterval
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < interval {
		interval = r.cfg.PollInterval
	}
	apps := NewApps(AppsConfig{
		Dir: r.cfg.DataDir,
		Engine: func() AppEngine {
			r.mu.Lock()
			e := r.engine
			r.mu.Unlock()
			if e == nil {
				return nil
			}
			return e
		},
		TunnelInterface: r.tunnelInterface,
		Reports:         r.inventoryReports,
		Interactive:     true,
		Logger:          r.logger.With("role", "apps"),
		Interval:        interval,
		Now:             r.cfg.Now,
		RemoteDesktop:   r.newRemoteDesktopHost(),
	})
	r.mu.Lock()
	r.apps = apps
	r.mu.Unlock()
	r.wireP07(ctx, apps)
	r.wireSupport(apps) // ADR-0232, support_runtime.go
	r.spawn(func() { apps.Run(ctx) })
	r.spawn(func() { r.wave2Loop(ctx) })
}

func (r *Runtime) inventoryReports() map[string]sysinfo.Info {
	inv := r.Inventory()
	out := make(map[string]sysinfo.Info, len(inv.Devices))
	for name, rep := range inv.Devices {
		if rep.Err == "" {
			out[name] = rep.Info
		}
	}
	return out
}

func (r *Runtime) appsOrErr() (*Apps, error) {
	r.mu.Lock()
	a := r.apps
	r.mu.Unlock()
	if a == nil {
		return nil, errors.New("servisler henüz başlamadı")
	}
	return a, nil
}

// AppsStatus implements panel.RemoteApps.
func (r *Runtime) AppsStatus() panel.AppsStatus {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.AppsStatus{}
	}
	return a.AppsStatus()
}

// RemoteDevice implements panel.RemoteApps.
func (r *Runtime) RemoteDevice(name string) (panel.RemoteDeviceView, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.RemoteDeviceView{}, err
	}
	return a.RemoteDevice(name)
}

// Inbox implements panel.RemoteApps.
func (r *Runtime) Inbox() panel.InboxView {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.InboxView{Files: []panel.InboxFile{}, Pending: []panel.PendingOffer{}, AutoAccept: []string{}}
	}
	return a.Inbox()
}

// DecideOffer implements panel.RemoteApps.
func (r *Runtime) DecideOffer(id string, accept bool) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	return a.DecideOffer(id, accept)
}

// SetAutoAccept implements panel.RemoteApps.
func (r *Runtime) SetAutoAccept(device string, on bool) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	return a.SetAutoAccept(device, on)
}

// DeleteInboxFile implements panel.RemoteApps.
func (r *Runtime) DeleteInboxFile(name string) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	return a.DeleteInboxFile(name)
}

// OpenInboxFile implements panel.RemoteApps.
func (r *Runtime) OpenInboxFile(name string) (io.ReadSeekCloser, panel.InboxFile, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return nil, panel.InboxFile{}, err
	}
	return a.OpenInboxFile(name)
}

// SendFile implements panel.RemoteApps.
func (r *Runtime) SendFile(device, name string, body io.Reader, size int64) (string, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return "", err
	}
	return a.SendFile(device, name, body, size)
}

// Transfers implements panel.RemoteApps.
func (r *Runtime) Transfers() []panel.TransferStatus {
	a, err := r.appsOrErr()
	if err != nil {
		return []panel.TransferStatus{}
	}
	return a.Transfers()
}

// Wake implements panel.RemoteApps.
func (r *Runtime) Wake(ctx context.Context, device string) (panel.WakeResult, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.WakeResult{}, err
	}
	return a.Wake(ctx, device)
}

// SetWakeMAC implements panel.RemoteApps.
func (r *Runtime) SetWakeMAC(device, mac string) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	return a.SetWakeMAC(device, mac)
}

// SpeedTest implements panel.RemoteApps.
func (r *Runtime) SpeedTest(ctx context.Context, device string, upload bool, seconds int) (panel.SpeedResult, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SpeedResult{}, err
	}
	return a.SpeedTest(ctx, device, upload, seconds)
}
