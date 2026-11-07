package service

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Name lookups of the coordinator (ADR-0023). While the kill switch is in
// place the Windows DNS client (svchost) is blocked like every other
// program, so a coordinator given by name could not be resolved and the
// device would stay cut off. Three sources are tried in turn:
//
//  1. the system resolver, unless the kill switch is installed;
//  2. Go's own resolver: its queries leave from openscale.exe, which the
//     kill switch lets through;
//  3. the addresses of the last successful lookup, kept in the settings.
const (
	systemLookupTimeout = 1500 * time.Millisecond
	// lookupReserve is left of the caller's deadline for the cache step.
	lookupReserve = 200 * time.Millisecond
	// minLookupTime is the least a resolver step is given to be worth it.
	minLookupTime = 300 * time.Millisecond
)

// lookupFunc resolves a host name to addresses.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

var (
	systemLookup = lookupNetIP4or6(net.DefaultResolver)
	goLookup     = lookupNetIP4or6(&net.Resolver{PreferGo: true})
)

// errNoAddress is returned when no source knows the host.
var errNoAddress = errors.New("koordinatör adı çözülemedi ve kayıtlı adres yok")

// resolveCoordinator is the tunnel's Resolve hook.
func (r *Runtime) resolveCoordinator(ctx context.Context, host string) ([]netip.Addr, error) {
	var errs []error
	try := func(name string, lookup lookupFunc, limit time.Duration) []netip.Addr {
		if dl, ok := ctx.Deadline(); ok {
			// Leave time for the next steps within the caller's deadline.
			left := time.Until(dl) - lookupReserve
			if left < minLookupTime {
				errs = append(errs, errors.New(name+": süre kalmadı"))
				return nil
			}
			if limit == 0 || left < limit {
				limit = left
			}
		}
		var (
			lctx   context.Context
			cancel context.CancelFunc
		)
		if limit > 0 {
			lctx, cancel = context.WithTimeout(ctx, limit)
		} else {
			lctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()
		addrs, err := lookup(lctx, host)
		addrs = usableAddrs(addrs)
		if err == nil && len(addrs) == 0 {
			err = errors.New("adres yok")
		}
		if err != nil {
			errs = append(errs, errors.New(name+": "+err.Error()))
			return nil
		}
		return addrs
	}
	if !r.killSwitchSnapshot().installed {
		if addrs := try("sistem çözücüsü", systemLookup, systemLookupTimeout); addrs != nil {
			r.rememberCoordinator(host, addrs)
			return addrs, nil
		}
	}
	if addrs := try("OpenScale çözücüsü", goLookup, 0); addrs != nil {
		r.rememberCoordinator(host, addrs)
		return addrs, nil
	}
	if addrs := r.cachedCoordinator(host); len(addrs) > 0 {
		r.logger.Warn("coordinator name not resolved; using the last known addresses", "host", host, "error", errors.Join(errs...).Error())
		return addrs, nil
	}
	return nil, errors.Join(append([]error{errNoAddress}, errs...)...)
}

// lookupNetIP4or6 adapts LookupNetIP with the "ip" network.
func lookupNetIP4or6(res *net.Resolver) lookupFunc {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return res.LookupNetIP(ctx, "ip", host)
	}
}

// usableAddrs drops addresses a coordinator can never have (unspecified,
// loopback, multicast) and keeps at most maxCachedAddrs, IPv4 first like
// the tunnel prefers.
func usableAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		a = a.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
	}
	slices.SortStableFunc(out, func(a, b netip.Addr) int {
		switch {
		case a.Is4() && !b.Is4():
			return -1
		case !a.Is4() && b.Is4():
			return 1
		}
		return 0
	})
	if len(out) > maxCachedAddrs {
		out = out[:maxCachedAddrs]
	}
	return out
}

// rememberCoordinator saves addrs when they differ from the saved ones, so
// a steady name costs no disk write.
func (r *Runtime) rememberCoordinator(host string, addrs []netip.Addr) {
	strs := make([]string, len(addrs))
	for i, a := range addrs {
		strs[i] = a.String()
	}
	err := r.updateSettings(func(st *settings) (bool, error) {
		if c := st.CoordinatorAddrs; c != nil && c.Host == host && slices.Equal(c.Addrs, strs) {
			return false, nil
		}
		st.CoordinatorAddrs = &addrCache{Host: host, Addrs: strs, At: r.cfg.Now().UTC()}
		return true, nil
	})
	if err != nil {
		r.logger.Warn("save coordinator addresses", "error", err.Error())
	}
}

// cachedCoordinator returns the saved addresses of host; a cache for
// another name (the owner moved the coordinator) is ignored.
func (r *Runtime) cachedCoordinator(host string) []netip.Addr {
	st, err := r.currentSettings()
	if err != nil || st.CoordinatorAddrs == nil || st.CoordinatorAddrs.Host != host {
		return nil
	}
	var out []netip.Addr
	for _, s := range st.CoordinatorAddrs.Addrs {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return usableAddrs(out)
}

// updateSettings loads the settings (a missing file gives the defaults),
// lets fn change them and saves them when fn reports a change.
func (r *Runtime) updateSettings(fn func(*settings) (bool, error)) error {
	r.settingsMu.Lock()
	defer r.settingsMu.Unlock()
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	changed, err := fn(&st)
	if err != nil || !changed {
		return err
	}
	return saveSettings(r.cfg.DataDir, st)
}
