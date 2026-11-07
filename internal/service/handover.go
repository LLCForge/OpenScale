package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/handover"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

// Seamless restarts (#203, ADR-0235). The stopping tunnel writes a
// handover file into the member state folder (keys, document and endpoint
// cache live there; administrators/root only); the next start takes it
// before the engine starts and seeds the endpoint cache, so every peer is
// configured with its last working endpoint before the coordinator answers.

// TakeHandover uses a handover file of dir once, before the engine starts.
// It returns how many peers it handed over.
func TakeHandover(dir string, doc *trust.Document, now time.Time, logger *slog.Logger) int {
	st, err := handover.Take(dir, doc.NetworkID, now)
	switch {
	case errors.Is(err, handover.ErrNone):
		return 0
	case err != nil:
		logger.Warn("handover ignored", "error", err.Error())
		return 0
	}
	n, err := handover.Seed(filepath.Join(dir, handover.EndpointCacheFile), st, now)
	if err != nil {
		logger.Warn("handover not applied", "error", err.Error())
		return 0
	}
	logger.Info("handover used", "peers", n, "coordinator", st.Coordinator != nil, "from", st.From, "age", now.Sub(st.Created).Round(time.Millisecond).String())
	return n
}

// StartHandover keeps a snapshot of engine's peers while run lasts and
// writes the handover when stopping reports that the process stops (not
// just this tunnel). onStop runs first (Linux keeps the TUN for an
// update). The returned wait blocks until the handover is written.
func StartHandover(run context.Context, dir, iface string, engine *node.Engine, stopping func() bool, onStop func(), now func() time.Time, logger *slog.Logger) (wait func()) {
	k := &handover.Keeper{
		Dir: dir,
		Capture: func() (handover.State, bool) {
			stats, err := engine.PeerStats()
			doc := engine.Document()
			if err != nil || doc == nil {
				return handover.State{}, false
			}
			var coordKey trust.Key
			if doc.Coordinator != nil {
				coordKey = doc.Coordinator.WireGuardKey
			}
			return handover.Capture(doc.NetworkID, iface, version.Version, coordKey, stats, now()), true
		},
		OnStop: onStop,
		Logf:   func(format string, args ...any) { logger.Info("handover", "event", fmt.Sprintf(format, args...)) },
	}
	var wg sync.WaitGroup
	wg.Go(func() { k.Run(run, stopping) })
	return wg.Wait
}
