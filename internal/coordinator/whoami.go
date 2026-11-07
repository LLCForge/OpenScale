package coordinator

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
)

// whoAmIBind answers who-am-I requests (control.WhoAmIRequest, #77) on the
// coordinator's WireGuard UDP port and hides them from WireGuard. A reply
// has the request's size and carries only the address the request came
// from, so it reveals nothing the sender did not already have and cannot
// amplify traffic. Replies are rate-limited.
type whoAmIBind struct {
	conn.Bind
	now func() time.Time

	mu     sync.Mutex
	tokens float64
	at     time.Time
}

const (
	whoAmIRate  = 20
	whoAmIBurst = 40
)

func newWhoAmIBind(base conn.Bind) *whoAmIBind {
	return &whoAmIBind{Bind: base, now: time.Now, tokens: whoAmIBurst}
}

func (b *whoAmIBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = b.filter(fn)
	}
	return fns, actual, nil
}

func (b *whoAmIBind) filter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for i := 0; i < n; i++ {
			data := packets[i][:sizes[i]]
			if control.IsWhoAmI(data, control.WhoAmIRequest) {
				if eps[i] != nil && b.take() {
					if from, ok := endpointAddr(eps[i]); ok {
						_ = b.Bind.Send([][]byte{control.WhoAmIAnswer(data, from)}, eps[i])
					}
				}
				continue
			}
			if kept != i {
				sizes[kept] = copy(packets[kept], packets[i][:sizes[i]])
				eps[kept] = eps[i]
			}
			kept++
		}
		return kept, err
	}
}

// endpointAddr returns the UDP source of an endpoint.
func endpointAddr(ep conn.Endpoint) (netip.AddrPort, bool) {
	s := ep.DstToString()
	if strings.HasPrefix(s, tcpEndpointPfx) {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func (b *whoAmIBind) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if !b.at.IsZero() {
		b.tokens = min(whoAmIBurst, b.tokens+now.Sub(b.at).Seconds()*whoAmIRate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
