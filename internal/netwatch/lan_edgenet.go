//go:build linux || windows

package netwatch

import (
	"net"

	"github.com/openscale/openscale/internal/edgenet"
)

// readNeighbors uses edgenet's read-only neighbour table readers (Linux
// /proc/net/arp, Windows GetIpNetTable).
func readNeighbors() []Neighbor {
	var out []Neighbor
	for _, n := range edgenet.Neighbors() {
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue
		}
		out = append(out, Neighbor{Addr: n.Addr, MAC: mac})
	}
	return out
}
