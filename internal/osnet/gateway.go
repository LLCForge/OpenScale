package osnet

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strings"
)

// ErrNoGateway is returned when no IPv4 default gateway is known.
var ErrNoGateway = errors.New("varsayılan ağ geçidi bulunamadı")

// DefaultGateways4 returns the next hops of the IPv4 default routes of the
// physical interfaces, best first, without changing anything. Used for
// captive portal detection (F-018), which talks to the local gateway only.
func DefaultGateways4() ([]netip.Addr, error) {
	gws, err := defaultGateways4()
	if err != nil {
		return nil, err
	}
	if len(gws) == 0 {
		return nil, ErrNoGateway
	}
	return gws, nil
}

// parseProcRoute reads /proc/net/route: default routes (destination and
// mask 0) with the gateway flag, lowest metric first. Addresses are
// little-endian hex.
func parseProcRoute(r io.Reader) []netip.Addr {
	type route struct {
		gw     netip.Addr
		metric uint64
	}
	var routes []route
	s := bufio.NewScanner(r)
	first := true
	for s.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(s.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := hex.DecodeString(padHex(f[3]))
		if err != nil || len(flags) != 2 || binary.BigEndian.Uint16(flags)&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		gw := netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		var metric uint64
		for _, c := range f[6] {
			if c < '0' || c > '9' {
				metric = ^uint64(0)
				break
			}
			metric = metric*10 + uint64(c-'0')
		}
		if gw.IsUnspecified() {
			continue
		}
		routes = append(routes, route{gw, metric})
	}
	// Stable insertion sort by metric; the table is tiny.
	for i := 1; i < len(routes); i++ {
		for j := i; j > 0 && routes[j].metric < routes[j-1].metric; j-- {
			routes[j], routes[j-1] = routes[j-1], routes[j]
		}
	}
	var out []netip.Addr
	for _, r := range routes {
		dup := false
		for _, o := range out {
			dup = dup || o == r.gw
		}
		if !dup {
			out = append(out, r.gw)
		}
	}
	return out
}

func padHex(s string) string {
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}
