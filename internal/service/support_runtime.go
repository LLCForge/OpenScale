package service

import (
	"context"
	"errors"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/support"
)

// The desktop service implements panel.SupportApp with Apps (#852,
// support_host.go).
var _ panel.SupportApp = (*Runtime)(nil)

// wireSupport routes support requests and sessions to the security event
// stream with a desktop notification, so the person at the device sees
// them even with the panel closed.
func (r *Runtime) wireSupport(apps *Apps) {
	apps.SetSupportNotify(func(kind, peer, message string) {
		r.observer().Security(kind, audit.SeverityWarning, panel.CategorySecurity, peer, message, true)
	})
}

// SupportSnapshot implements panel.SupportApp.
func (r *Runtime) SupportSnapshot(ctx context.Context, device, kind string) (support.Snapshot, error) {
	a, err := r.appsOrErr()
	if err != nil {
		return support.Snapshot{}, err
	}
	return a.SupportSnapshot(ctx, device, kind)
}

// SupportKill implements panel.SupportApp.
func (r *Runtime) SupportKill(ctx context.Context, device string, pid int, name string) error {
	a, err := r.appsOrErr()
	if err != nil {
		return err
	}
	return a.SupportKill(ctx, device, pid, name)
}

// SupportLocal implements panel.SupportApp.
func (r *Runtime) SupportLocal() panel.SupportLocalView {
	a, err := r.appsOrErr()
	if err != nil {
		return panel.SupportLocalView{}
	}
	return a.SupportLocal()
}

// SupportDecide implements panel.SupportApp.
func (r *Runtime) SupportDecide(id string, accept bool) error {
	a, err := r.appsOrErr()
	if err != nil {
		return errors.New("servisler henüz başlamadı")
	}
	return a.SupportDecide(id, accept)
}

// SupportEndAll implements panel.SupportApp.
func (r *Runtime) SupportEndAll() int {
	a, err := r.appsOrErr()
	if err != nil {
		return 0
	}
	return a.SupportEndAll()
}
