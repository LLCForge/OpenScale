package cli

import (
	"context"
	"log/slog"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/autoupdate"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/updater"
)

// Seamless restarts for "openscale up" (#203, ADR-0235): the handover file
// in the state folder carries the last endpoints to the next start; as the
// installed Linux device unit, an update also keeps the TUN interface with
// its addresses and routes (TUNSETPERSIST) for the new process.

// adoptUpTUN clears the persistent flag of an interface an update kept, so
// a normal stop of this run removes it again.
func adoptUpTUN(dev tun.Device, logger *slog.Logger) {
	if err := osnet.SetTUNPersist(dev, false); err == nil {
		logger.Debug("tunnel interface opened (persistent flag cleared)")
	}
}

// startUpHandover keeps the handover snapshot while ctx lasts and writes it
// when ctx ends; the returned stop waits for that.
func startUpHandover(ctx context.Context, env *Env, dir, name string, dev tun.Device, engine *node.Engine, logger *slog.Logger) func() {
	run, cancel := context.WithCancel(ctx)
	keepTUN := func() {
		if !autoupdate.IsDeviceServiceDir(dir) || !updater.RestartForUpdate(autoupdate.DefaultPaths().UpdaterState, env.Now()) {
			return
		}
		if err := osnet.SetTUNPersist(dev, true); err != nil {
			logger.Warn("tunnel interface not kept for the update", "error", err.Error())
			return
		}
		logger.Info("tunnel interface kept for the update", "interface", name)
	}
	wait := service.StartHandover(run, dir, name, engine, func() bool { return ctx.Err() != nil }, keepTUN, env.Now, logger.With("part", "handover"))
	return func() {
		cancel()
		wait()
	}
}
