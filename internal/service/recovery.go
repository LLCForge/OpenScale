package service

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// recoverChanges undoes the DNS and route changes a crashed run left
// behind (ADR-0051).
func (r *Runtime) recoverChanges(ctx context.Context) {
	done, err := r.journal.Recover(ctx, r.cfg.Hooks.Recover, r.logger)
	if err != nil {
		r.logger.Warn("crash recovery incomplete; retried at the next start", "error", err.Error())
	}
	if len(done) > 0 {
		r.logger.Info("crash recovery finished", "undone", fmt.Sprint(done))
	}
}

// Interface watch (F-146, #306). The engine notices a lost interface when
// reading or writing fails; an adapter removed from outside while no
// packet flows is noticed here instead, so the tunnel is recreated within
// seconds rather than at the next packet.
const (
	ifWatchEvery  = 3 * time.Second
	ifWatchMisses = 2
)

// interfaceExists is net.InterfaceByName; tests replace it.
var interfaceExists = func(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// watchInterface cancels run with node.ErrTunnelLost once the interface
// is missing twice in a row. An interface the system never listed (a test
// device) is not watched.
func watchInterface(ctx context.Context, name string, every time.Duration, cancel context.CancelCauseFunc) {
	if name == "" || !interfaceExists(name) {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		misses := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if interfaceExists(name) {
				misses = 0
				continue
			}
			if misses++; misses >= ifWatchMisses {
				cancel(fmt.Errorf("%w: %s arayüzü sistemden kaldırıldı", node.ErrTunnelLost, name))
				return
			}
		}
	}()
}
