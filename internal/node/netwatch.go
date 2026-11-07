package node

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Network change and wake detection (F-004).
const (
	// netWatchInterval is how often the host's addresses are compared.
	netWatchInterval = 2 * time.Second
	// wakeSlack: a wall clock gap this much longer than the interval means
	// the computer slept (the ticker does not run while it is suspended).
	wakeSlack = 5 * time.Second
)

// netEvent is a set of reasons to reconnect quickly.
type netEvent uint32

const (
	// netChanged: the local addresses changed (new Wi-Fi, cable plugged).
	netChanged netEvent = 1 << iota
	// netWoke: the clock jumped, usually a wake from sleep.
	netWoke
)

func (ev netEvent) String() string {
	var parts []string
	if ev&netChanged != 0 {
		parts = append(parts, "address change")
	}
	if ev&netWoke != 0 {
		parts = append(parts, "wake")
	}
	return strings.Join(parts, "+")
}

// netWatcher compares a fingerprint of the host's network configuration and
// the wall clock between polls. It is platform independent: polling is
// cheap and needs no OS notification API.
type netWatcher struct {
	probe    func() (string, error)
	interval time.Duration

	primed   bool
	last     string
	lastWall time.Time
}

func newNetWatcher(probe func() (string, error), interval time.Duration) *netWatcher {
	return &netWatcher{probe: probe, interval: interval}
}

// check polls once. The first call only records the starting state.
func (w *netWatcher) check(now time.Time) netEvent {
	var ev netEvent
	wall := now.Round(0) // drop the monotonic reading: it stops during sleep
	if w.primed {
		gap := wall.Sub(w.lastWall)
		if gap > w.interval+wakeSlack || gap < -wakeSlack {
			ev |= netWoke
		}
	}
	w.lastWall = wall
	fp, err := w.probe()
	if err != nil {
		// Keep the last good fingerprint: an error is not a change.
		return ev
	}
	if w.primed && fp != w.last {
		ev |= netChanged
	}
	w.last, w.primed = fp, true
	return ev
}

// interfaceFingerprint returns a probe that lists the addresses of every
// interface that is up, except loopback, the tunnel itself and overlay
// addresses (the coordinator's own interface on the same host). IPv6
// addresses count by their /64, so privacy addresses that rotate within
// the same network are not mistaken for a network change. Link-local
// addresses are ignored for the same reason.
func interfaceFingerprint(tunnel string, overlay func() []netip.Prefix) func() (string, error) {
	return func() (string, error) {
		ifs, err := net.Interfaces()
		if err != nil {
			return "", err
		}
		skip := overlay()
		var parts []string
		for _, ifi := range ifs {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Name == tunnel {
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				addr, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				addr = addr.Unmap()
				if addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() || inAny(skip, addr) {
					continue
				}
				s := addr.String()
				if addr.Is6() {
					s = netip.PrefixFrom(addr, 64).Masked().String()
				}
				parts = append(parts, ifi.Name+"|"+s)
			}
		}
		slices.Sort(parts)
		parts = slices.Compact(parts)
		return strings.Join(parts, ","), nil
	}
}

func inAny(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.IsValid() && p.Contains(a) {
			return true
		}
	}
	return false
}

// watchNetwork polls until ctx ends and reports events to the run loop.
func (e *Engine) watchNetwork(ctx context.Context, w *netWatcher, every time.Duration) {
	w.check(time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if ev := w.check(now); ev != 0 {
				e.signalNetwork(ev)
			}
		}
	}
}

// signalNetwork records ev and wakes the run loop without blocking;
// events that arrive while one is pending are merged into it.
func (e *Engine) signalNetwork(ev netEvent) {
	for {
		old := e.netPending.Load()
		if e.netPending.CompareAndSwap(old, old|uint32(ev)) {
			break
		}
	}
	select {
	case e.netWake <- struct{}{}:
	default:
	}
}

// takeNetwork returns and clears the pending events.
func (e *Engine) takeNetwork() netEvent { return netEvent(e.netPending.Swap(0)) }
