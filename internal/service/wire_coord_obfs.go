package service

import (
	"context"

	"github.com/openscale/openscale/internal/coordinator"
)

// newCoordinatorWithObfs builds the local coordinator with the transport
// disguise saved in its state directory (ADR-0186, obfs-coordinator.json).
// A broken settings file stops the start: the error is shown in the panel
// and the restart loop retries, rather than silently running undisguised.
func (r *Runtime) newCoordinatorWithObfs(ctx context.Context, cfg coordinator.Config) (*coordinator.Server, error) {
	dir := r.path(CoordinatorDir)
	f, err := coordinator.LoadObfsFile(dir)
	if err != nil {
		return nil, err
	}
	rt, err := coordinator.ApplyObfs(&cfg, dir, f, r.cfg.Now())
	if err != nil {
		return nil, err
	}
	srv, err := coordinator.New(cfg)
	if err != nil {
		rt.Close()
		return nil, err
	}
	rt.Serve(ctx, srv, func(err error) {
		r.logger.Warn("coordinator TLS camouflage stopped", "error", err.Error())
	})
	return srv, nil
}
