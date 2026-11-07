package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/portmap"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
)

func TestNormalizeExtras(t *testing.T) {
	cfg := Config{TorSOCKS: "127.0.0.1:9050", PortMap: PortMapConfig{Enabled: true}}
	if err := normalizeExtras(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.ForceRelay || cfg.PortMap.Enabled {
		t.Fatalf("Tor did not force relaying / disable port mapping: %+v", cfg)
	}
	bad := []Config{
		{TorSOCKS: "192.168.1.5:9050"},
		{TorSOCKS: "tor:9050"},
		{TorSOCKS: "127.0.0.1:0"},
		{TorSOCKS: "127.0.0.1:9050", DisableTCPFallback: true},
		{Padding: PaddingMode(7)},
		{CoverTraffic: 10},
		{CoverTraffic: MaxCoverTraffic + 1},
		{PortMap: PortMapConfig{Enabled: true, DisablePCP: true, DisableNATPMP: true, DisableUPnP: true}},
	}
	for i, c := range bad {
		if err := normalizeExtras(&c); err == nil {
			t.Errorf("case %d accepted: %+v", i, c)
		}
	}
	ok := Config{Padding: PaddingBuckets, CoverTraffic: 1024, PortMap: PortMapConfig{Enabled: true, DisableUPnP: true}}
	if err := normalizeExtras(&ok); err != nil || ok.ForceRelay {
		t.Fatalf("valid settings: %v %+v", err, ok)
	}
}

func TestPaddedSize(t *testing.T) {
	cases := []struct {
		mode   PaddingMode
		n, mtu int
		want   int
	}{
		{PaddingOff, 60, 1280, 60},
		{PaddingBuckets, 60, 1280, 128},
		{PaddingBuckets, 128, 1280, 128},
		{PaddingBuckets, 129, 1280, 256},
		{PaddingBuckets, 1000, 1280, 1024},
		{PaddingBuckets, 1100, 1280, 1280},
		{PaddingBuckets, 1280, 1280, 1280},
		{PaddingBuckets, 1400, 1280, 1400}, // never shrinks, never above MTU
		{PaddingMTU, 60, 1280, 1280},
		{PaddingMTU, 60, 1420, 1420},
	}
	for _, c := range cases {
		if got := paddedSize(c.mode, c.n, c.mtu); got != c.want {
			t.Errorf("paddedSize(%v, %d, %d) = %d, want %d", c.mode, c.n, c.mtu, got, c.want)
		}
	}
}

func TestShapingCosts(t *testing.T) {
	off, err := PaddingCost(PaddingOff, DefaultMTU)
	if err != nil || off != 0 {
		t.Fatalf("off: %v %v", off, err)
	}
	buckets, _ := PaddingCost(PaddingBuckets, DefaultMTU)
	mtu, _ := PaddingCost(PaddingMTU, DefaultMTU)
	if !(buckets > 0 && mtu > buckets) {
		t.Fatalf("buckets %.1f%% mtu %.1f%%", buckets, mtu)
	}
	t.Logf("padding cost at MTU %d: buckets %.1f%%, MTU %.1f%%", DefaultMTU, buckets, mtu)
	if _, err := PaddingCost(PaddingBuckets, 10); err == nil {
		t.Fatal("bad MTU accepted")
	}
	c, err := CoverTrafficCost(1024, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	if c.AveragePacket != (128+256+512+1024+1280)/5 || c.PacketsPerHour != 1024*3600/int64(c.AveragePacket) {
		t.Fatalf("estimate %+v", c)
	}
	if c.WireBytesPerHour <= 1024*3600 || c.WireBytesPer30Days != c.WireBytesPerDay*30 || c.WireBytesPerDay != c.WireBytesPerHour*24 {
		t.Fatalf("estimate %+v", c)
	}
	t.Logf("cover traffic 1 KB/s: %+v", c)
	if _, err := CoverTrafficCost(1, DefaultMTU); err == nil {
		t.Fatal("rate below the minimum accepted")
	}
}

// tcp4 builds a minimal IPv4 TCP segment.
func tcp4(src, dst netip.Addr, sport, dport uint16) []byte {
	b := make([]byte, 40)
	b[0], b[9] = 0x45, packet.ProtoTCP
	binary.BigEndian.PutUint16(b[2:4], 40)
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	b[32] = 5 << 4
	return b
}

func TestClassifyPacket(t *testing.T) {
	a, b := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	dns, _ := packet.BuildUDP4(a, b, 53000, 53, []byte("q"))
	other, _ := packet.BuildUDP4(a, b, 53000, 8080, []byte("x"))
	cases := []struct {
		name string
		pkt  []byte
		want int
	}{
		{"ping", tuntest.Ping(b, a), prioHigh},
		{"ssh", tcp4(a, b, 50000, 22), prioHigh},
		{"ssh reply", tcp4(b, a, trust.SSHPort, 50000), prioHigh},
		{"remote desktop", tcp4(a, b, 50000, trust.RemoteDesktopPort), prioHigh},
		{"dns", dns, prioHigh},
		{"file send", tcp4(a, b, 50000, trust.FilesPort), prioLow},
		{"speed test reply", tcp4(b, a, trust.SpeedtestPort, 50000), prioLow},
		{"web", tcp4(a, b, 50000, 443), prioNormal},
		{"udp", other, prioNormal},
		{"garbage", []byte{1, 2, 3}, prioNormal},
	}
	for _, c := range cases {
		if got := classifyPacket(c.pkt); got != c.want {
			t.Errorf("%s: class %d, want %d", c.name, got, c.want)
		}
	}
}

// newTestWrap returns a TUN wrapper whose filter lets everything out.
func newTestWrap(t *testing.T, o wrapOptions) (*wrapTUN, *tuntest.ChannelTUN) {
	t.Helper()
	ch := tuntest.NewChannelTUN()
	f := filter.New(time.Now)
	o.filter, o.logger = f, testLogger(t, "[wrap]")
	o.intercept = func([]byte) bool { return false }
	w := newWrapTUN(ch.TUN(), o)
	t.Cleanup(func() { _ = w.Close() })
	return w, ch
}

func TestWrapPriorityQueues(t *testing.T) {
	w, _ := newTestWrap(t, wrapOptions{classify: classifyPacket})
	a, b := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	low, normal, high := tcp4(a, b, 50000, trust.FilesPort), tcp4(a, b, 50000, 443), tcp4(a, b, 50000, 22)
	// Queue directly, as the read loop would after the filter.
	w.queueFor(low) <- low
	w.queueFor(normal) <- normal
	w.queueFor(high) <- high
	w.Inject([]byte{0x45, 0xff})
	bufs := [][]byte{make([]byte, 2000)}
	sizes := []int{0}
	var order []int
	for range 4 {
		if _, err := w.Read(bufs, sizes, 0); err != nil {
			t.Fatal(err)
		}
		order = append(order, sizes[0])
		if sizes[0] == 40 {
			order[len(order)-1] = classifyPacket(bufs[0][:40])
		}
	}
	// Control packet (2 bytes) first, then high, normal, low.
	if order[0] != 2 || order[1] != prioHigh || order[2] != prioNormal || order[3] != prioLow {
		t.Fatalf("order %v", order)
	}
}

func TestWrapPadsWithZeros(t *testing.T) {
	e := &Engine{cfg: Config{Padding: PaddingBuckets, MTU: DefaultMTU}}
	w, _ := newTestWrap(t, wrapOptions{pad: e.padder()})
	pkt := tuntest.Ping(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"))
	w.Inject(pkt)
	buf := bytes.Repeat([]byte{0xaa}, 4000) // stale data from an earlier packet
	sizes := []int{0}
	if _, err := w.Read([][]byte{buf}, sizes, 16); err != nil {
		t.Fatal(err)
	}
	if sizes[0] != 128 {
		t.Fatalf("padded to %d, want 128", sizes[0])
	}
	got := buf[16 : 16+sizes[0]]
	if !bytes.Equal(got[:len(pkt)], pkt) || !bytes.Equal(got[len(pkt):], make([]byte, 128-len(pkt))) {
		t.Fatal("padding is not zeros after the packet")
	}
	if st := e.TrafficShaping(); st.PaddedPackets != 1 || st.PaddingBytes != uint64(128-len(pkt)) {
		t.Fatalf("stats %+v", st)
	}
}

func TestPredictedPorts(t *testing.T) {
	got := predictedPorts(netip.MustParseAddrPort("203.0.113.5:40000"), 4)
	if len(got) != 4 || got[0].Port() != 40001 || got[3].Port() != 40004 {
		t.Fatalf("%v", got)
	}
	if got := predictedPorts(netip.MustParseAddrPort("203.0.113.5:65534"), 4); len(got) != 1 {
		t.Fatalf("near the top: %v", got)
	}
	for _, s := range []string{"192.168.1.5:40000", "100.64.1.1:40000", "[2001:db8::1]:40000", "203.0.113.5:0"} {
		if got := predictedPorts(netip.MustParseAddrPort(s), 4); got != nil {
			t.Errorf("%s: %v", s, got)
		}
	}
	pp := &peerProbe{observed: netip.MustParseAddrPort("203.0.113.5:40000"), cands: []netip.AddrPort{netip.MustParseAddrPort("192.168.1.5:51820")}}
	if n := len(pp.probeTargets()); n != 2 {
		t.Fatalf("without prediction: %d targets", n)
	}
	pp.predict = true
	if n := len(pp.probeTargets()); n != 2+portPredictionSpan {
		t.Fatalf("with prediction: %d targets", n)
	}
}

func TestMappedAddressIsACandidate(t *testing.T) {
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	e, err := New(Config{Store: tn.join(t, "laptop"), Secrets: tn.aKey, TUN: tuntest.NewChannelTUN().TUN(), PortMap: PortMapConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	saved := listInterfaceAddrs
	listInterfaceAddrs = func() ([]interfaceAddr, error) {
		return []interfaceAddr{{iface: "eth0", addr: netip.MustParseAddr("192.168.1.10")}}, nil
	}
	defer func() { listInterfaceAddrs = saved }()

	if got := e.gatherCandidates(51820); len(got) != 1 {
		t.Fatalf("before mapping: %v", got)
	}
	ext := netip.MustParseAddrPort("203.0.113.7:40820")
	e.onPortMap(portmap.Mapping{Protocol: portmap.ProtoPCP, External: ext, Lifetime: time.Hour, Obtained: time.Now()}, true)
	got := e.gatherCandidates(51820)
	if len(got) != 2 || got[0] != ext {
		t.Fatalf("with mapping: %v", got)
	}
	st := e.PortMapStatus()
	if !st.Enabled || !st.Active || st.Protocol != "PCP" || st.External != ext {
		t.Fatalf("status %+v", st)
	}
	// Hidden local candidates still report the mapped public address.
	e.cfg.HideLocalCandidates = true
	if got := e.gatherCandidates(51820); len(got) != 1 || got[0] != ext {
		t.Fatalf("hidden local candidates: %v", got)
	}
	e.onPortMap(portmap.Mapping{}, false)
	if got := e.gatherCandidates(51820); len(got) != 0 {
		t.Fatalf("after losing the mapping: %v", got)
	}
}

// countBind counts every UDP datagram it is asked to send.
type countBind struct {
	conn.Bind
	sent atomic.Int64
}

func (b *countBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.sent.Add(int64(len(bufs)))
	return b.Bind.Send(bufs, ep)
}

// fakeTor is a SOCKS5 proxy on 127.0.0.1 that connects every CONNECT to
// one address and records the requested host.
func fakeTor(t *testing.T, to string) (addr string, hosts chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	hosts = make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var h [2]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				m := make([]byte, h[1])
				if _, err := io.ReadFull(c, m); err != nil || !bytes.Contains(m, []byte{2}) {
					return // the engine must offer username/password
				}
				_, _ = c.Write([]byte{5, 2})
				var v [2]byte
				_, _ = io.ReadFull(c, v[:])
				u := make([]byte, v[1])
				_, _ = io.ReadFull(c, u)
				var pl [1]byte
				_, _ = io.ReadFull(c, pl[:])
				_, _ = io.ReadFull(c, make([]byte, pl[0]))
				_, _ = c.Write([]byte{1, 0})
				var req [5]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || req[3] != 3 {
					return // only names are expected
				}
				name := make([]byte, req[4])
				_, _ = io.ReadFull(c, name)
				_, _ = io.ReadFull(c, make([]byte, 2))
				hosts <- string(name)
				up, err := net.Dial("tcp", to)
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), hosts
}

// In Tor mode a device reaches the coordinator and, through the relay, its
// peer without sending a single UDP datagram (ADR-0044).
func TestTorModeSendsNoUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: tn.join(t, "koordinator"), Secrets: tn.coordSecrets, ListenPort: tn.coordPort,
		TCPListen: "127.0.0.1:0", Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()
	socks, hosts := fakeTor(t, coord.TCPAddr().String())

	aBind := &countBind{Bind: testnet.NewLoopbackBind()}
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, err := New(Config{Store: tn.join(t, "laptop"), Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t), Bind: aBind,
		TorSOCKS: socks, TCPFallback: "koordinatorabcdefgh.onion:443", PortMap: PortMapConfig{Enabled: true},
		PollInterval: 300 * time.Millisecond, RelayAfter: time.Second, Logger: testLogger(t, "[laptop]")})
	if err != nil {
		t.Fatal(err)
	}
	if !a.TorActive() || !a.cfg.ForceRelay || a.PortMapStatus().Enabled {
		t.Fatal("Tor mode did not force relaying or left port mapping on")
	}
	go func() { _ = a.Run(ctx) }()
	b, _ := startEngine(ctx, t, Config{Store: tn.join(t, "masaustu"), Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t), RelayAfter: time.Second})

	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 60*time.Second) {
		t.Fatalf("no traffic in Tor mode (status %+v)", a.Status())
	}
	if !a.CoordinatorOverTCP() {
		t.Fatal("traffic flowed but not over the TCP transport")
	}
	select {
	case h := <-hosts:
		if h != "koordinatorabcdefgh.onion" {
			t.Fatalf("Tor asked for %q", h)
		}
	default:
		t.Fatal("no CONNECT seen by the fake Tor")
	}
	if n := aBind.sent.Load(); n != 0 {
		t.Fatalf("%d UDP datagrams sent in Tor mode", n)
	}
	waitFor(t, 10*time.Second, "sync over Tor", func() bool { return a.Status().LastSyncError == "" })
	if n := aBind.sent.Load(); n != 0 {
		t.Fatalf("%d UDP datagrams sent in Tor mode", n)
	}
}

// Padding, cover traffic and priority queues on one side: traffic still
// flows, the peer (with none of them) gets packets at their real length,
// and the cover packets are counted (ADR-0043).
func TestShapingEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real sockets")
	}
	tn := newTestNet(t, func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: tn.join(t, "koordinator"), Secrets: tn.coordSecrets, ListenPort: tn.coordPort,
		Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	a, _ := startEngine(ctx, t, Config{Store: tn.join(t, "laptop"), Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t),
		RelayAfter: time.Second, Padding: PaddingMTU, CoverTraffic: MaxCoverTraffic, InteractivePriority: true})
	b, _ := startEngine(ctx, t, Config{Store: tn.join(t, "masaustu"), Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t), RelayAfter: time.Second})
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	ping := tuntest.Ping(bSelf.IPv4, aSelf.IPv4)
	deadline := time.After(60 * time.Second)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for got := false; !got; {
		select {
		case aTUN.Outbound <- ping:
		case pkt := <-bTUN.Inbound:
			info, err := packet.Parse(pkt)
			if err != nil || info.Src != aSelf.IPv4 || !info.IsICMP() {
				continue
			}
			if len(pkt) != len(ping) {
				t.Fatalf("peer got %d bytes, want the unpadded %d", len(pkt), len(ping))
			}
			got = true
		case <-deadline:
			t.Fatal("no traffic with padding on")
		case <-tick.C:
		}
	}
	waitFor(t, 10*time.Second, "cover packets", func() bool { return a.TrafficShaping().CoverPackets > 0 })
	st := a.TrafficShaping()
	if st.PaddedPackets == 0 || st.PaddingBytes == 0 || !st.InteractivePriority || st.Padding != PaddingMTU {
		t.Fatalf("stats %+v", st)
	}
	// The coordinator keeps answering while cover traffic flows.
	waitFor(t, 10*time.Second, "sync", func() bool { return a.Status().LastSyncError == "" })
}
