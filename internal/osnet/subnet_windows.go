//go:build windows

package osnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// SubnetRouter applies RouteConfig on Windows: routes into the tunnel and
// exit node exceptions. Windows is never a subnet router (ADR-0133).
type SubnetRouter struct {
	run          func(ctx context.Context, name string, args ...string) error
	defaultRoute func(tunnel string) (uint32, netip.Addr, error)

	mu     sync.Mutex
	iface  string
	client []netip.Prefix
	except []netip.Prefix
	// exceptVia is the interface and gateway the exceptions were added on.
	exceptIdx uint32
}

// NewSubnetRouter returns the system's subnet router.
func NewSubnetRouter() *SubnetRouter {
	return &SubnetRouter{run: run, defaultRoute: windowsDefaultRoute}
}

// RouterSupported reports whether this system can be a subnet router.
func RouterSupported() bool { return false }

// RouterStatus is a short status line for diagnostics.
func (r *SubnetRouter) RouterStatus() string { return "desteklenmiyor" }

func netshFamily(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

// Apply changes the routes to match cfg.
func (r *SubnetRouter) Apply(cfg RouteConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var errs []error
	have := r.client
	if r.iface != cfg.Interface {
		have = nil
	}
	add, del := prefixDiff(have, cfg.Client)
	for _, p := range del {
		if err := r.run(ctx, "netsh", "interface", netshFamily(p), "delete", "route", "prefix="+p.String(), "interface="+r.iface); err != nil {
			errs = append(errs, err)
		}
	}
	installed := slices.DeleteFunc(slices.Clone(have), func(p netip.Prefix) bool { return slices.Contains(del, p) })
	for _, p := range add {
		if err := r.run(ctx, "netsh", "interface", netshFamily(p), "add", "route", "prefix="+p.String(), "interface="+cfg.Interface, "store=active", "metric=1"); err != nil {
			errs = append(errs, err)
			continue
		}
		installed = append(installed, p)
	}
	r.iface, r.client = cfg.Interface, installed
	if err := r.applyExcept(ctx, cfg); err != nil {
		errs = append(errs, err)
	}
	if len(cfg.Own) > 0 {
		errs = append(errs, ErrRouterUnsupported)
	}
	return errors.Join(errs...)
}

// applyExcept routes exit node exceptions (#79) through the default
// gateway of the physical network. Only IPv4 is supported; the kill
// switch, when on, still blocks them (ADR-0133).
func (r *SubnetRouter) applyExcept(ctx context.Context, cfg RouteConfig) error {
	var want []netip.Prefix
	if cfg.ExitActive {
		for _, p := range cfg.ExitExcept {
			if p.Addr().Is4() {
				want = append(want, p)
			}
		}
	}
	var errs []error
	if len(want) == 0 && len(r.except) == 0 {
		return nil
	}
	idx, gw := uint32(0), netip.Addr{}
	if len(want) > 0 {
		var err error
		idx, gw, err = r.defaultRoute(cfg.Interface)
		if err != nil {
			return err
		}
	}
	// A changed physical network moves every exception.
	have := r.except
	if idx != r.exceptIdx {
		for _, p := range r.except {
			_ = r.run(ctx, "netsh", "interface", "ipv4", "delete", "route", "prefix="+p.String(), "interface="+strconv.FormatUint(uint64(r.exceptIdx), 10))
		}
		have = nil
	}
	add, del := prefixDiff(have, want)
	for _, p := range del {
		if err := r.run(ctx, "netsh", "interface", "ipv4", "delete", "route", "prefix="+p.String(), "interface="+strconv.FormatUint(uint64(r.exceptIdx), 10)); err != nil {
			errs = append(errs, err)
		}
	}
	kept := slices.DeleteFunc(slices.Clone(have), func(p netip.Prefix) bool { return slices.Contains(del, p) })
	for _, p := range add {
		if err := r.run(ctx, "netsh", "interface", "ipv4", "add", "route", "prefix="+p.String(), "interface="+strconv.FormatUint(uint64(idx), 10),
			"nexthop="+gw.String(), "store=active", "metric=1"); err != nil {
			errs = append(errs, err)
			continue
		}
		kept = append(kept, p)
	}
	r.except, r.exceptIdx = kept, idx
	return errors.Join(errs...)
}

// Close removes everything Apply installed.
func (r *SubnetRouter) Close() error {
	return r.Apply(RouteConfig{Interface: r.iface})
}

// windowsDefaultRoute returns the interface and gateway of the best IPv4
// default route that is not the tunnel.
func windowsDefaultRoute(tunnel string) (uint32, netip.Addr, error) {
	idx := defaultInterface(windows.AF_INET, interfaceIndex(tunnel))
	if idx == 0 {
		return 0, netip.Addr{}, errors.New("internet bağlantısı olan bir ağ kartı bulunamadı")
	}
	gws, err := DefaultGateways4()
	if err != nil {
		return 0, netip.Addr{}, err
	}
	if len(gws) == 0 {
		return 0, netip.Addr{}, fmt.Errorf("%w", ErrNoGateway)
	}
	return idx, gws[0], nil
}
