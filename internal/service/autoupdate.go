package service

import (
	"context"
	"errors"
	"sync"

	"github.com/openscale/openscale/internal/autoupdate"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rollout"
	"github.com/openscale/openscale/internal/version"
)

// Automatic updates (ADR-0225): while the tunnel runs, the service checks
// the coordinator's mirror and hands a verified release to the detached
// installer ("openscale update auto install"). Only the installed Windows
// service turns it on (Hooks.AutoUpdate); tests never do.

type autoUpdateState struct {
	mu     sync.Mutex
	runner *autoupdate.Runner
}

func (r *Runtime) autoUpdater() *autoupdate.Runner {
	r.auto.mu.Lock()
	defer r.auto.mu.Unlock()
	if r.auto.runner == nil {
		p := autoupdate.DefaultPaths()
		var trigger func(context.Context) error
		if r.cfg.Hooks.AutoUpdate {
			trigger = autoupdate.Trigger("")
		}
		r.auto.runner = autoupdate.New(autoupdate.Config{
			Paths: p, Installed: version.Version, Trigger: trigger,
			Logger: r.logger.With("part", "autoupdate"),
		})
	}
	return r.auto.runner
}

// startAutoUpdate checks through engine until ctx ends.
func (r *Runtime) startAutoUpdate(ctx context.Context, engine *node.Engine) {
	if !r.cfg.Hooks.AutoUpdate {
		return
	}
	p := autoupdate.DefaultPaths()
	runner := autoupdate.New(autoupdate.Config{
		Paths: p, Fetcher: engine, Installed: version.Version, Trigger: autoupdate.Trigger(""),
		Logger:  r.logger.With("part", "autoupdate"),
		Rings:   func() autoupdate.RingInfo { return EngineRings(engine) }, // ADR-0235
		Healthy: r.rolloutHealthy,
	})
	r.auto.mu.Lock()
	r.auto.runner = runner
	r.auto.mu.Unlock()
	r.spawn(func() { runner.Run(ctx) })
}

// EngineRings reads this device's update ring and the ring sizes from the
// engine's signed document (ADR-0235).
func EngineRings(engine *node.Engine) autoupdate.RingInfo {
	self, err := engine.Self()
	if err != nil {
		return autoupdate.RingInfo{Ring: rollout.RingMain}
	}
	return autoupdate.RingInfoOf(engine.Document(), self.ID)
}

// rolloutHealthy is the service's health for the rollout report: the
// tunnel runs and MagicDNS is set up.
func (r *Runtime) rolloutHealthy() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engine != nil && r.engineErr == "" && r.dnsErr == ""
}

func toPanelAutoUpdate(st autoupdate.Status, supported bool) panel.AutoUpdateStatus {
	out := panel.AutoUpdateStatus{
		Supported: supported, Enabled: st.Enabled, State: st.State, Message: st.Message, Action: st.Action,
		Channel: st.Channel, Current: st.Current, Latest: st.Latest, LatestVerified: st.LatestVerified,
		LastCheck: st.LastCheck, NextCheck: st.NextCheck, ScheduledAt: st.ScheduledAt,
		Source: st.Source, SourceChecked: st.SourceChecked,
	}
	out.Ring = st.Ring
	if ro := st.Rollout; ro != nil {
		pr := &panel.AutoUpdateRollout{
			Announced: ro.Announced, Open: ro.Open, Halted: ro.Halted, HaltRing: ro.HaltRing,
			CanarySoak: ro.CanarySoak, EarlySoak: ro.EarlySoak, Since: ro.Since, EarlyAt: ro.EarlyAt, MainAt: ro.MainAt,
			FirstSeen: ro.FirstSeen, NotBefore: ro.NotBefore,
		}
		for _, c := range ro.Rings {
			pr.Rings = append(pr.Rings, panel.AutoUpdateRing(c))
		}
		out.Rollout = pr
	}
	if a := st.LastAttempt; a != nil {
		out.LastAttempt = &panel.AutoUpdateAttempt{Version: a.Version, At: a.At, OK: a.OK, RolledBack: a.RolledBack, Message: a.Message}
	}
	return out
}

// AutoUpdateStatus is GET /api/app/auto-update.
func (r *Runtime) AutoUpdateStatus() (panel.AutoUpdateStatus, error) {
	p := autoupdate.DefaultPaths()
	return toPanelAutoUpdate(r.autoUpdater().Status(), p.Supported), nil
}

// SetAutoUpdate is POST /api/app/auto-update.
func (r *Runtime) SetAutoUpdate(on bool) (panel.AutoUpdateStatus, error) {
	p := autoupdate.DefaultPaths()
	if !p.Supported {
		return panel.AutoUpdateStatus{}, errors.New(p.Reason)
	}
	st, err := r.autoUpdater().SetEnabled(on)
	if err != nil {
		return panel.AutoUpdateStatus{}, err
	}
	return toPanelAutoUpdate(st, true), nil
}
