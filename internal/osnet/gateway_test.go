package osnet

import (
	"strings"
	"testing"
)

func TestParseProcRoute(t *testing.T) {
	table := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0104A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
tun0	00000000	00000000	0001	0	0	0	00000000	0	0	0
eth1	00000000	0101A8C0	0003	0	0	700	00000000	0	0	0
bad	00000000	zz	0003	0	0	1	00000000	0	0	0
`
	got := parseProcRoute(strings.NewReader(table))
	if len(got) != 2 || got[0].String() != "192.168.1.1" || got[1].String() != "192.168.4.1" {
		t.Fatalf("gateways = %v", got)
	}
}

// The live lookup must not fail on a machine with a normal network; it
// only reads the routing table.
func TestDefaultGateways4Reads(t *testing.T) {
	gws, err := DefaultGateways4()
	if err != nil && err != ErrNoGateway {
		t.Fatalf("DefaultGateways4: %v", err)
	}
	for _, g := range gws {
		if !g.Is4() || g.IsUnspecified() {
			t.Fatalf("bad gateway %v", g)
		}
	}
}
