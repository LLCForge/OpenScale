package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/socks5"
)

// Optional transports and traffic shaping (ADR-0042, ADR-0043, ADR-0044):
// router port mapping, Tor for the coordinator connection, padding, cover
// traffic and interactive priority. Every one of them is off by default.

// extrasStopWait bounds how long the engine waits, when stopping, for the
// extras to finish (deleting the router's port mapping).
const extrasStopWait = 5 * time.Second

// extrasState is the engine state of the optional features.
type extrasState struct {
	portMap portMapState
	torAuth *socks5.Auth
	netWake chan struct{}
	wg      sync.WaitGroup

	padded     atomic.Uint64
	padBytes   atomic.Uint64
	coverPkts  atomic.Uint64
	coverBytes atomic.Uint64
}

// normalizeExtras checks the optional settings and applies what they
// imply: Tor forces relaying and turns port mapping off.
func normalizeExtras(cfg *Config) error {
	switch cfg.Padding {
	case PaddingOff, PaddingBuckets, PaddingMTU:
	default:
		return fmt.Errorf("bilinmeyen dolgu kipi %d", cfg.Padding)
	}
	if cfg.CoverTraffic != 0 && (cfg.CoverTraffic < MinCoverTraffic || cfg.CoverTraffic > MaxCoverTraffic) {
		return fmt.Errorf("sahte trafik hızı %d ile %d B/sn arasında olmalı", MinCoverTraffic, MaxCoverTraffic)
	}
	if cfg.PortMap.Enabled && cfg.PortMap.DisablePCP && cfg.PortMap.DisableNATPMP && cfg.PortMap.DisableUPnP {
		return errors.New("port eşleme açık ama bütün protokoller kapalı")
	}
	if cfg.TorSOCKS != "" {
		ap, err := netip.ParseAddrPort(cfg.TorSOCKS)
		if err != nil || ap.Port() == 0 || !ap.Addr().Unmap().IsLoopback() {
			return fmt.Errorf("Tor SOCKS adresi %q geçersiz; yalnızca bu makinedeki (loopback) bir adres:port kabul edilir", cfg.TorSOCKS)
		}
		if cfg.DisableTCPFallback {
			return errors.New("Tor kipi TCP taşımasını kullanır; TCP yedeği kapalıyken açılamaz")
		}
		// No UDP may reveal this device's address (ADR-0044).
		cfg.ForceRelay = true
		cfg.PortMap.Enabled = false
	}
	return nil
}

// setupExtras prepares the extras once the engine exists (New).
func (e *Engine) setupExtras() error {
	e.extras.netWake = make(chan struct{}, 1)
	if e.cfg.TorSOCKS != "" {
		if e.tcp == nil {
			return errors.New("Tor kipi TCP taşıması olmadan çalışamaz")
		}
		var u, p [12]byte
		if _, err := rand.Read(u[:]); err != nil {
			return err
		}
		if _, err := rand.Read(p[:]); err != nil {
			return err
		}
		e.extras.torAuth = &socks5.Auth{Username: "openscale-" + hex.EncodeToString(u[:]), Password: hex.EncodeToString(p[:])}
		e.tcp.forced = true
		e.tcp.wanted = true
		e.tcp.active.Store(true)
		e.tcp.dial = e.dialCoordinatorTor
	}
	return nil
}

// startExtras starts the background parts (port mapping, cover traffic)
// and returns a function that stops them and waits for them, bounded.
func (e *Engine) startExtras(ctx context.Context) func() {
	xctx, cancel := context.WithCancel(ctx)
	if e.cfg.PortMap.Enabled && !e.cfg.ForceRelay {
		e.extras.wg.Add(1)
		go func() {
			defer e.extras.wg.Done()
			e.runPortMap(xctx)
		}()
	}
	if e.cfg.CoverTraffic > 0 {
		e.extras.wg.Add(1)
		go func() {
			defer e.extras.wg.Done()
			e.runCover(xctx)
		}()
	}
	return func() {
		cancel()
		done := make(chan struct{})
		go func() {
			e.extras.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(extrasStopWait):
			e.logger.Warn("optional transports did not stop in time")
		}
	}
}

// extrasNetChanged tells the extras the network changed.
func (e *Engine) extrasNetChanged() {
	if e.extras.netWake == nil {
		return
	}
	select {
	case e.extras.netWake <- struct{}{}:
	default:
	}
}
