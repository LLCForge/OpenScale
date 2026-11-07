package service

import (
	"context"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

const (
	inventoryEvery   = 30 * time.Second
	inventoryTimeout = 4 * time.Second
	inventoryWorkers = 8
)

// inventoryLoop collects system reports while the tunnel runs. Only admin
// devices get answers, so other computers just keep their own report.
func (r *Runtime) inventoryLoop(ctx context.Context) {
	every := inventoryEvery
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < every {
		every = r.cfg.PollInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		r.collectInventory(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runtime) collectInventory(ctx context.Context) {
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e == nil {
		return
	}
	self, err := e.Self()
	if err != nil {
		return
	}
	now := r.cfg.Now()
	selfReport := &panel.Report{Info: e.SelfInfo(), At: now}
	inv := panel.Inventory{Self: selfReport, Devices: map[string]panel.Report{}}
	if !self.HasRole(trust.RoleAdmin) {
		r.setInventory(inv)
		return
	}
	doc := r.deviceDocument()
	if doc == nil {
		return
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, inventoryWorkers)
	)
	ask := func(name string, query func(context.Context) (panel.Report, error)) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		qctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
		rep, err := query(qctx)
		cancel()
		if err != nil {
			rep = panel.Report{Err: "yanıt yok", At: r.cfg.Now()}
			if old, ok := r.previousReport(name); ok {
				// Keep the last good report so the panel can show it as
				// stale instead of empty.
				old.Err = rep.Err
				rep = old
			}
		}
		mu.Lock()
		if name == "" {
			inv.Coordinator = &rep
		} else {
			inv.Devices[name] = rep
		}
		mu.Unlock()
	}
	for _, d := range doc.Devices {
		if d.Name == self.Name || !now.Before(d.ExpiresAt) {
			continue
		}
		addr := d.IPv4
		wg.Add(1)
		go ask(d.Name, func(c context.Context) (panel.Report, error) {
			in, err := e.QueryInfo(c, addr)
			return panel.Report{Info: in, At: r.cfg.Now()}, err
		})
	}
	wg.Add(1)
	go ask("", func(c context.Context) (panel.Report, error) {
		in, err := e.CoordinatorInfo(c)
		return panel.Report{Info: in, At: r.cfg.Now()}, err
	})
	wg.Wait()
	if doc.Coordinator != nil {
		if stats, err := e.PeerStats(); err == nil {
			if p, ok := stats[doc.Coordinator.WireGuardKey]; ok && p.Endpoint.IsValid() {
				inv.CoordinatorAddr = p.Endpoint.Addr().Unmap().String()
			}
		}
	}
	r.setInventory(inv)
}

func (r *Runtime) deviceDocument() *trust.Document {
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e == nil {
		return nil
	}
	return e.Document()
}

func (r *Runtime) previousReport(name string) (panel.Report, bool) {
	r.invMu.Lock()
	defer r.invMu.Unlock()
	if name == "" {
		if r.inventory.Coordinator != nil && r.inventory.Coordinator.Info.OS != "" {
			return *r.inventory.Coordinator, true
		}
		return panel.Report{}, false
	}
	rep, ok := r.inventory.Devices[name]
	return rep, ok && rep.Info.OS != ""
}

func inventoryEmpty() panel.Inventory {
	return panel.Inventory{Devices: map[string]panel.Report{}}
}

func (r *Runtime) setInventory(inv panel.Inventory) {
	r.invMu.Lock()
	r.inventory = inv
	r.invMu.Unlock()
}

// Inventory implements panel.App.
func (r *Runtime) Inventory() panel.Inventory {
	r.invMu.Lock()
	defer r.invMu.Unlock()
	out := r.inventory
	out.Devices = make(map[string]panel.Report, len(r.inventory.Devices))
	for k, v := range r.inventory.Devices {
		out.Devices[k] = v
	}
	return out
}
