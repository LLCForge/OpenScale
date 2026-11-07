package coordinator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/trust"
)

// Single packet authorization (#614, ADR-0181). With SPA on, the
// coordinator's UDP port drops every datagram (WireGuard, who-am-I echo,
// anything) from a source address that has not first sent a valid knock,
// and the TCP transport closes connections whose first bytes are not a
// valid knock. An internet scan sees a closed, silent port.
//
// The knock key is derived from values only members hold: the
// coordinator's WireGuard public key and the network id (both in the
// signed document and the invite bundle, never published). It is a
// scanning shield, not authentication: WireGuard still authenticates every
// peer. A member who leaves still knows the key; that only lets it reach
// a port that answers it nothing.
//
// Knock datagram (61 bytes): "OSK1" | version 1 | unix seconds (8, big
// endian) | random nonce (16) | HMAC-SHA256(key, first 29 bytes).
// WireGuard message types are 1-4 in the first byte, so a knock can never
// be taken for a WireGuard packet.

const (
	spaMagic = obfs.SPAMagic
	// SPAKnockSize is the knock's length.
	SPAKnockSize = obfs.SPAKnockSize
	// SPASkew is how far a knock's time may differ from the coordinator's.
	SPASkew = 90 * time.Second
	// SPAOpen is how long a source address stays allowed after its last
	// knock or datagram.
	SPAOpen = 15 * time.Minute
	// SPAKnockEvery is how often a device should knock again.
	SPAKnockEvery = 5 * time.Minute
	spaMaxSources = 8192
	spaMaxNonces  = 16384
)

// SPAKey derives the knock key of a coordinator (shared with devices,
// obfs.SPAKey).
func SPAKey(coordinatorWG trust.Key, networkID string) [32]byte {
	return obfs.SPAKey(coordinatorWG, networkID)
}

// SPAKnock builds a knock datagram (devices send it to the coordinator's
// UDP port before the handshake and every SPAKnockEvery; over TCP it is the
// first bytes of the connection, before the preamble).
func SPAKnock(key [32]byte, now time.Time, random io.Reader) ([]byte, error) {
	return obfs.SPAKnock(key, now, random)
}

// IsSPAKnock reports whether data looks like a knock (shape only).
func IsSPAKnock(data []byte) bool { return obfs.IsSPAKnock(data) }

// spaGate keeps the allowed sources and the replay cache.
type spaGate struct {
	key [32]byte
	now func() time.Time

	mu      sync.Mutex
	allowed map[netip.Addr]time.Time // until
	nonces  map[[16]byte]time.Time   // expiry
	dropped uint64
	knocks  uint64
}

func newSPAGate(key [32]byte, now func() time.Time) *spaGate {
	return &spaGate{key: key, now: now, allowed: map[netip.Addr]time.Time{}, nonces: map[[16]byte]time.Time{}}
}

// knock verifies a knock from src and opens the gate for it.
func (g *spaGate) knock(src netip.Addr, data []byte) bool {
	if !IsSPAKnock(data) {
		return false
	}
	now := g.now()
	ts := time.Unix(int64(binary.BigEndian.Uint64(data[5:13])), 0) //nolint:gosec // checked below
	if ts.Before(now.Add(-SPASkew)) || ts.After(now.Add(SPASkew)) {
		return false
	}
	m := hmac.New(sha256.New, g.key[:])
	m.Write(data[:29])
	if !hmac.Equal(m.Sum(nil), data[29:]) {
		return false
	}
	var nonce [16]byte
	copy(nonce[:], data[13:29])
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, seen := g.nonces[nonce]; seen {
		return false // replay
	}
	if len(g.nonces) >= spaMaxNonces {
		g.pruneLocked(now)
		if len(g.nonces) >= spaMaxNonces {
			return false
		}
	}
	g.nonces[nonce] = now.Add(2 * SPASkew)
	if _, ok := g.allowed[src]; !ok && len(g.allowed) >= spaMaxSources {
		g.pruneLocked(now)
		if len(g.allowed) >= spaMaxSources {
			return false
		}
	}
	g.allowed[src] = now.Add(SPAOpen)
	g.knocks++
	return true
}

// allow reports whether src may pass and refreshes it.
func (g *spaGate) allow(src netip.Addr) bool {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.allowed[src]
	if !ok || !now.Before(until) {
		if ok {
			delete(g.allowed, src)
		}
		g.dropped++
		return false
	}
	g.allowed[src] = now.Add(SPAOpen)
	return true
}

func (g *spaGate) pruneLocked(now time.Time) {
	for a, until := range g.allowed {
		if !now.Before(until) {
			delete(g.allowed, a)
		}
	}
	for n, exp := range g.nonces {
		if !now.Before(exp) {
			delete(g.nonces, n)
		}
	}
}

func (g *spaGate) prune() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(g.now())
}

// forgetOlder drops allowed sources idle for longer than d (no-metadata
// retention, #630).
func (g *spaGate) forgetOlder(d time.Duration) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for a, until := range g.allowed {
		if until.Sub(now) < SPAOpen-d {
			delete(g.allowed, a)
		}
	}
}

// SPAStats are the gate's counters.
type SPAStats struct {
	Enabled bool   `json:"enabled"`
	Open    int    `json:"open"`
	Knocks  uint64 `json:"knocks"`
	Dropped uint64 `json:"dropped"`
}

func (g *spaGate) stats() SPAStats {
	if g == nil {
		return SPAStats{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return SPAStats{Enabled: true, Open: len(g.allowed), Knocks: g.knocks, Dropped: g.dropped}
}

// spaBind filters the UDP receive path.
type spaBind struct {
	conn.Bind
	gate *spaGate
}

func (b *spaBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = b.filter(fn)
	}
	return fns, actual, nil
}

func (b *spaBind) filter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for i := 0; i < n; i++ {
			from, ok := endpointAddr(eps[i])
			if !ok {
				// TCP frames were admitted at connection time (tcp.go).
				if kept != i {
					sizes[kept] = copy(packets[kept], packets[i][:sizes[i]])
					eps[kept] = eps[i]
				}
				kept++
				continue
			}
			data := packets[i][:sizes[i]]
			if IsSPAKnock(data) {
				b.gate.knock(from.Addr(), data)
				continue // never passed on, never answered
			}
			if !b.gate.allow(from.Addr()) {
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

// tcpKnock verifies the knock read at the start of a TCP connection
// (tcpBind.readKnock).
func (g *spaGate) tcpKnock(c net.Conn, data []byte) bool {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	return g.knock(ap.Addr().Unmap(), data)
}

// ErrSPAWithoutDocument is returned when SPA is on but the coordinator is
// not in the document (the key needs its pinned WireGuard key).
var ErrSPAWithoutDocument = errors.New("SPA needs the network document")
