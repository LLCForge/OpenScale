//go:build linux

package edgenet

import (
	"io"
	"os"
)

const maxProcARP = 1 << 20

func neighbors() []Neighbor {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcARP))
	if err != nil {
		return nil
	}
	return ParseProcARP(data)
}

// meteredHint: Linux has no system-wide metered flag without NetworkManager's
// D-Bus API, which would need a new dependency (ADR-0002); unknown.
func meteredHint() (bool, bool) { return false, false }
