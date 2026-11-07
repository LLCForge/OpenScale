//go:build darwin

package netwatch

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// maxDarwinNeighbors bounds one routing table read.
const maxDarwinNeighbors = 4096

// readNeighbors reads the link-layer (ARP) entries of the routing table
// through sysctl NET_RT_FLAGS with RTF_LLINFO, as "arp -an" does, without
// running a command or sending a packet.
func readNeighbors() []Neighbor {
	rib, err := route.FetchRIB(syscall.AF_INET, syscall.NET_RT_FLAGS, syscall.RTF_LLINFO)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_FLAGS, rib)
	if err != nil {
		return nil
	}
	var out []Neighbor
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		ll, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || len(ll.Addr) != 6 {
			continue
		}
		out = append(out, Neighbor{Addr: netip.AddrFrom4(dst.IP), MAC: net.HardwareAddr(append([]byte(nil), ll.Addr...))})
		if len(out) >= maxDarwinNeighbors {
			break
		}
	}
	return out
}
