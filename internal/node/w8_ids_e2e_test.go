package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/netwatch"
	"github.com/openscale/openscale/internal/trust"
)

// w8SYN builds an IPv4 TCP SYN (header only, valid IP checksum).
func w8SYN(src, dst netip.Addr, sport, dport uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	pkt[32] = 5 << 4
	pkt[33] = 0x02
	return pkt
}

// TestFlowTapPortScanOverLoopbackTunnel runs two devices and a
// coordinator over real UDP sockets on 127.0.0.1. The laptop scans the
// desktop's TCP ports through the tunnel; the desktop's packet filter
// tap samples the SYNs and the netwatch detector reports a port scan
// (#729, ADR-0221).
func TestFlowTapPortScanOverLoopbackTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordSecrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := coordSecrets.PublicKeys()
	coordPort := freeUDPPort(t)
	commit(t, n, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(coordPort), coordWG)
	})
	laptopKey := enroll(t, n, "laptop")
	masaustuKey := enroll(t, n, "masaustu")
	commit(t, n, func(doc *trust.Document) error {
		if err := doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP}); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolTCP, Ports: []string{"1-200"}})
	})
	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	laptopStore := join(t, n, filepath.Join(base, "laptop"))
	masaustuStore := join(t, n, filepath.Join(base, "masaustu"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	select {
	case <-coord.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not start")
	}
	laptopTUN, masaustuTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, networkDir string) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), NetworkDir: networkDir,
			PollInterval: 300 * time.Millisecond, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = e.Run(ctx) }()
		return e
	}
	laptop := start(laptopStore, laptopKey, laptopTUN, netDir)
	masaustu := start(masaustuStore, masaustuKey, masaustuTUN, "")
	ls, _ := laptop.Self()
	ms, _ := masaustu.Self()
	if !expectPacket(t, laptopTUN, masaustuTUN, ls.IPv4, ms.IPv4, 20*time.Second) {
		t.Fatal("tunnel did not come up")
	}

	tap := filter.NewFlowTap(0)
	masaustu.PacketFilter().SetFlowTap(tap)
	det := netwatch.NewDetector(netwatch.IDSConfig{})
	var alerts []netwatch.Alert
	deadline := time.Now().Add(15 * time.Second)
	for p := uint16(1); len(alerts) == 0 && time.Now().Before(deadline); p = p%200 + 1 {
		laptopTUN.Outbound <- w8SYN(ls.IPv4, ms.IPv4, 30000+p, p)
	drain:
		for {
			select {
			case <-masaustuTUN.Inbound:
			default:
				break drain
			}
		}
		tap.Drain(0, func(r filter.TapRecord) {
			if r.Src != ls.IPv4 || r.Dst != ms.IPv4 || r.Proto != 6 || !r.Inbound {
				return
			}
			alerts = append(alerts, det.Observe(netwatch.Flow{At: time.Now(), Src: r.Src, Dst: r.Dst, Proto: r.Proto, Port: r.Port, Dropped: r.Dropped})...)
		})
		time.Sleep(5 * time.Millisecond)
	}
	if len(alerts) == 0 || alerts[0].Kind != netwatch.KindPortScan || alerts[0].Src != ls.IPv4 {
		t.Fatalf("alerts = %+v (lost %d)", alerts, tap.Lost())
	}
}
