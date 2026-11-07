package cli

import (
	"context"
	"log/slog"

	"github.com/openscale/openscale/internal/autoupdate"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/version"
)

// startUpAutoUpdate runs the automatic updater (ADR-0225) when "openscale
// up" is the installed Linux device unit (--state-dir
// /var/lib/openscale/device). It only downloads and checks; the privileged
// openscale-autoupdate.service installs. A manual "up" never updates.
func startUpAutoUpdate(ctx context.Context, dir string, engine *node.Engine, logger *slog.Logger) func() {
	if !autoupdate.IsDeviceServiceDir(dir) {
		return func() {}
	}
	p := autoupdate.DefaultPaths()
	r := autoupdate.New(autoupdate.Config{
		Paths: p, Fetcher: engine, Installed: version.Version,
		Trigger: autoupdate.Trigger(""), Logger: logger.With("part", "autoupdate"),
		Rings: func() autoupdate.RingInfo { return service.EngineRings(engine) }, // ADR-0235
	})
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	return func() {
		cancel()
		<-done
	}
}
