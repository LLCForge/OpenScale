//go:build windows

package osnet

import (
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

func defaultGateways4() ([]netip.Addr, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, ErrNoGateway
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	type route struct {
		gw     netip.Addr
		metric uint32
	}
	var routes []route
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.NextHop.Family != windows.AF_INET {
			continue
		}
		// SOCKADDR_IN: the address follows family and port, at the start
		// of Data.
		raw := (*[4]byte)(unsafe.Pointer(&row.NextHop.Data[0]))
		gw := netip.AddrFrom4(*raw)
		if gw.IsUnspecified() {
			continue // on-link default (VPN adapters, the exit node split routes are /1)
		}
		routes = append(routes, route{gw, row.Metric})
	}
	slices.SortStableFunc(routes, func(a, b route) int {
		switch {
		case a.metric < b.metric:
			return -1
		case a.metric > b.metric:
			return 1
		}
		return 0
	})
	var out []netip.Addr
	for _, r := range routes {
		if !slices.Contains(out, r.gw) {
			out = append(out, r.gw)
		}
	}
	return out, nil
}
