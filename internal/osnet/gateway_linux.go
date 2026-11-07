//go:build linux

package osnet

import (
	"net/netip"
	"os"
)

func defaultGateways4() ([]netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcRoute(f), nil
}
