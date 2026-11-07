package edgenet

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Gateway watch (#466). The detector remembers, in memory only, the
// link-layer address of the default gateway seen on each network (keyed
// by the network's name and the gateway address, so moving from home to
// a café with the same 192.168.1.1 is not a change). A different address
// for the same key is reported once per change: ARP spoofing replaces the
// gateway's address with the attacker's. A router replaced on purpose, or
// a failover pair, gives the same signal; the owner decides, and the
// automatic reaction is off by default.

// maxWatched bounds the remembered gateways; the oldest half is dropped.
const maxWatched = 256

// Alert kinds.
const (
	AlertGatewayMAC = "gateway_mac_changed"
)

// Alert is one suspicious observation.
type Alert struct {
	At      time.Time
	Kind    string
	Gateway netip.Addr
	Old     string
	New     string
	Network string
}

// Message explains the alert in Turkish for the event list.
func (a Alert) Message() string {
	where := a.Network
	if where == "" {
		where = "bu ağ"
	}
	return fmt.Sprintf("%s üzerinde ağ geçidi %s için donanım adresi %s iken %s oldu; ARP sahteciliği olabilir. Bu ağa güvenmeyin: kill switch'li çıkış düğümü kullanın (openscale edge mode travel)", where, a.Gateway, a.Old, a.New)
}

type watched struct {
	mac  string
	seen time.Time
}

// Detector compares gateway observations. It is safe for concurrent use.
type Detector struct {
	mu   sync.Mutex
	seen map[string]watched
}

// NewDetector returns an empty detector.
func NewDetector() *Detector { return &Detector{seen: map[string]watched{}} }

// Observe records the gateway's address on a network and returns an
// alert when it differs from what was seen there before.
func (d *Detector) Observe(network string, gw netip.Addr, mac string, now time.Time) (Alert, bool) {
	if !gw.IsValid() || mac == "" {
		return Alert{}, false
	}
	key := network + "\x00" + gw.Unmap().String()
	d.mu.Lock()
	defer d.mu.Unlock()
	prev, ok := d.seen[key]
	if !ok && len(d.seen) >= maxWatched {
		d.dropOldest()
	}
	d.seen[key] = watched{mac: mac, seen: now}
	if !ok || prev.mac == mac {
		return Alert{}, false
	}
	return Alert{At: now, Kind: AlertGatewayMAC, Gateway: gw.Unmap(), Old: prev.mac, New: mac, Network: network}, true
}

// dropOldest removes the older half of the entries. d.mu is held.
func (d *Detector) dropOldest() {
	var cut time.Time
	times := make([]time.Time, 0, len(d.seen))
	for _, w := range d.seen {
		times = append(times, w.seen)
	}
	// The median is good enough to drop about half.
	for i := 1; i < len(times); i++ {
		for j := i; j > 0 && times[j].Before(times[j-1]); j-- {
			times[j], times[j-1] = times[j-1], times[j]
		}
	}
	cut = times[len(times)/2]
	for k, w := range d.seen {
		if !w.seen.After(cut) {
			delete(d.seen, k)
		}
	}
}
