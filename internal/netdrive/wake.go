package netdrive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wol"
)

// Wake-on-LAN button (#749). A phone or the panel asks a relay device on
// the sleeper's LAN, through the tunnel, to broadcast the magic packet.
// The relay set comes from the signed document's wake rules
// (Document.WakeRelays); this device sends locally when it is a relay
// itself. Relays that are online are tried first, and one target can be
// woken at most once per WakeCooldown so a double tap sends one request.

// WakeCooldown separates two wake requests for the same target.
const WakeCooldown = 10 * time.Second

// Errors of the wake button.
var (
	ErrWakeNoRule    = errors.New("bu cihazı uyandırmaya izin veren bir wake kuralı (aracı cihazıyla) yok")
	ErrWakeNoMAC     = errors.New("cihazın MAC adresi bilinmiyor")
	ErrWakeCooldown  = errors.New("bu cihaz için az önce uyandırma isteği gönderildi")
	ErrWakeNoDevice  = errors.New("böyle bir cihaz yok")
	ErrWakeNoSenders = errors.New("uyandırma için gönderici yapılandırılmamış")
)

// WakeSender asks the relay at addr (its tunnel address and
// trust.WakePort) to wake target; the service's SendWakeRequest.
type WakeSender func(ctx context.Context, addr netip.AddrPort, target, mac string) (int, error)

// LocalWake sends the magic packet on this device's own LAN.
type LocalWake func(ctx context.Context, mac net.HardwareAddr) (int, error)

// WakeResult tells which relay sent the packet.
type WakeResult struct {
	Target string   `json:"target"`
	Relay  string   `json:"relay"`
	MAC    string   `json:"mac"`
	Tried  []string `json:"tried"`
}

// Waker is the button's state.
type Waker struct {
	Send  WakeSender
	Local LocalWake
	// Online reports whether a relay is reachable now; nil treats every
	// relay alike.
	Online func(device string) bool
	Now    func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

func (w *Waker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// OrderRelays puts self first (no tunnel hop), then online relays, then
// the rest, each group in document order. The target never relays for
// itself.
func OrderRelays(relays []string, self, target string, online func(string) bool) []string {
	var first, up, rest []string
	for _, r := range relays {
		switch {
		case r == target:
		case r == self:
			first = append(first, r)
		case online != nil && online(r):
			up = append(up, r)
		default:
			rest = append(rest, r)
		}
	}
	return slices.Concat(first, up, rest)
}

// Wake wakes target with mac from device self.
func (w *Waker) Wake(ctx context.Context, doc *trust.Document, self, target, mac string) (WakeResult, error) {
	if doc == nil {
		return WakeResult{}, ErrWakeNoDevice
	}
	if _, ok := doc.DeviceByName(target); !ok || target == self {
		return WakeResult{}, ErrWakeNoDevice
	}
	if mac == "" {
		return WakeResult{}, ErrWakeNoMAC
	}
	hw, err := wol.ParseMAC(mac)
	if err != nil {
		return WakeResult{}, err
	}
	relays := OrderRelays(doc.WakeRelays(self, target), self, target, w.Online)
	if len(relays) == 0 {
		return WakeResult{}, ErrWakeNoRule
	}
	if w.Send == nil && w.Local == nil {
		return WakeResult{}, ErrWakeNoSenders
	}
	now := w.now()
	w.mu.Lock()
	if w.last == nil {
		w.last = map[string]time.Time{}
	}
	if t, ok := w.last[target]; ok && now.Sub(t) < WakeCooldown && now.Sub(t) >= 0 {
		w.mu.Unlock()
		return WakeResult{}, ErrWakeCooldown
	}
	w.last[target] = now
	w.mu.Unlock()

	res := WakeResult{Target: target, MAC: hw.String()}
	var errs []error
	for _, relay := range relays {
		if relay == self {
			if w.Local == nil {
				continue
			}
			res.Tried = append(res.Tried, relay)
			if _, err := w.Local(ctx, hw); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", relay, err))
				continue
			}
			res.Relay = relay
			return res, nil
		}
		if w.Send == nil {
			continue
		}
		d, ok := doc.DeviceByName(relay)
		if !ok || !d.IPv4.IsValid() || !doc.IPv4Prefix.Contains(d.IPv4) {
			continue
		}
		res.Tried = append(res.Tried, relay)
		if _, err := w.Send(ctx, netip.AddrPortFrom(d.IPv4, trust.WakePort), target, hw.String()); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", relay, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		res.Relay = relay
		return res, nil
	}
	if len(errs) == 0 {
		return res, errors.New("kullanılabilir aracı cihaz yok")
	}
	return res, errors.Join(errs...)
}
