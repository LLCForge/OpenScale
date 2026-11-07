package p2psend

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Service bundles what the desktop app needs for the panel: approvals,
// transfer list, quarantine and starting sends by device name. The node
// creates one next to the Server and passes the same Approvals and
// Registry to it.
type Service struct {
	Identity  Identity
	Approvals *Approvals
	Registry  *Registry
	Q         Quarantine
	// Resolve finds a member device by its name in the signed document.
	Resolve func(name string) (Peer, bool)
	// Port is the p2psend port of member devices.
	Port uint16
	// Context bounds background sends; nil uses context.Background.
	Context context.Context

	relay atomic.Bool
	// OnRelayChange, if set, persists the relay choice and reconfigures
	// the server.
	OnRelayChange func(on bool) error
}

// SendRequest starts a transfer from the panel.
type SendRequest struct {
	Device       string   `json:"device"`
	Path         string   `json:"path"`
	Route        string   `json:"route,omitempty"`
	Hops         []string `json:"hops,omitempty"`
	KeepMetadata bool     `json:"keep_metadata,omitempty"`
}

// Validate checks a request before anything is resolved.
func (r SendRequest) Validate() error {
	switch {
	case r.Device == "" || len(r.Device) > 64:
		return errors.New("alıcı cihaz gerekli")
	case r.Path == "" || len(r.Path) > 4096:
		return errors.New("dosya yolu gerekli")
	case len(r.Hops) > MaxHops:
		return fmt.Errorf("en çok %d ara cihaz seçilebilir", MaxHops)
	}
	switch r.Route {
	case "", RouteAuto, RouteDirect, RouteOnion:
	default:
		return fmt.Errorf("bilinmeyen yol türü %q", r.Route)
	}
	return nil
}

// E2ETransfers lists recent transfers.
func (s *Service) E2ETransfers() []TransferView { return s.Registry.List() }

// E2EPending lists offers waiting for a decision.
func (s *Service) E2EPending() []Offer { return s.Approvals.Pending() }

// E2EDecide answers an offer.
func (s *Service) E2EDecide(id string, accept bool) error { return s.Approvals.Decide(id, accept) }

// E2EQuarantine returns the quarantine.
func (s *Service) E2EQuarantine() Quarantine { return s.Q }

// E2ERelay reports whether this device relays onion streams.
func (s *Service) E2ERelay() bool { return s.relay.Load() }

// SetE2ERelay turns relaying on or off.
func (s *Service) SetE2ERelay(on bool) error {
	if s.OnRelayChange != nil {
		if err := s.OnRelayChange(on); err != nil {
			return err
		}
	}
	s.relay.Store(on)
	return nil
}

// resolveTarget turns names into a target and hops.
func (s *Service) resolveTarget(req SendRequest) (Target, []Hop, error) {
	if s.Resolve == nil || s.Port == 0 {
		return Target{}, nil, errors.New("uçtan uca aktarım bu cihazda yapılandırılmamış")
	}
	p, ok := s.Resolve(req.Device)
	if !ok {
		return Target{}, nil, fmt.Errorf("%q imzalı belgede yok", req.Device)
	}
	t := Target{Name: p.Name, Key: p.Key, Addr: netip.AddrPortFrom(p.Addr, s.Port)}
	var hops []Hop
	for _, h := range req.Hops {
		hp, ok := s.Resolve(h)
		if !ok {
			return Target{}, nil, fmt.Errorf("ara cihaz %q imzalı belgede yok", h)
		}
		hops = append(hops, Hop{Key: hp.Key, Addr: netip.AddrPortFrom(hp.Addr, s.Port)})
	}
	return t, hops, nil
}

// E2EStart validates req and sends in the background; progress and the
// result appear in Transfers.
func (s *Service) E2EStart(req SendRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	// The path comes from the local panel. It must name a regular file
	// directly (no link that could point somewhere the user did not see).
	if !filepath.IsAbs(req.Path) {
		return errors.New("dosya yolu tam yol olmalı")
	}
	if st, err := os.Lstat(req.Path); err != nil || !st.Mode().IsRegular() {
		return errors.New("dosya bulunamadı veya normal bir dosya değil")
	}
	target, hops, err := s.resolveTarget(req)
	if err != nil {
		return err
	}
	if req.Route == RouteOnion && len(hops) < MinHops {
		return fmt.Errorf("%w: en az %d güvenilen ara cihaz seçin", ErrRoute, MinHops)
	}
	ctx := s.Context
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 24*time.Hour)
		defer cancel()
		_, _ = Send(ctx, s.Identity, target, req.Path, &SendOptions{Route: req.Route, Hops: hops,
			KeepMetadata: req.KeepMetadata, Registry: s.Registry})
	}()
	return nil
}
