package node

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// The exit DNS handlers are not the only ones that run before the packet
// filter and answer through the inject queue. These tests cover the rest:
// a chained entry's relayed DNS, status queries and gossip. A refused peer
// gets nothing from any of them; the filter's contract is the same.

var chainTestFinal = netip.MustParseAddr("100.64.0.250")

// chainEntry makes the fixture's exit node the entry of a usable chain with
// the fixture's peer as a member.
func (f exitDNSG3Fixture) chainEntry() {
	r := &f.e.chain
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selfIP, r.finalIP, r.usable = f.e.self.IPv4, chainTestFinal, true
	r.overlay = f.e.cfg.Store.Document().IPv4Prefix
	r.members = map[netip.Addr]bool{f.peer.IPv4: true}
	r.entry.Store(true)
}

// eachRefusal runs check for the owner's quarantine and for lost mode, and
// lifts each of them afterwards.
func (f exitDNSG3Fixture) eachRefusal(t *testing.T, check func(t *testing.T, what string)) {
	t.Helper()
	if err := f.e.filter.Quarantine(f.peer.Name, "test", 0); err != nil {
		t.Fatal(err)
	}
	check(t, "quarantine")
	f.e.filter.Release(f.peer.Name)
	f.e.filter.SetIsolated(true)
	check(t, "lost mode")
	f.e.filter.SetIsolated(false)
}

// TestChainDNSHonoursQuarantineAndLostMode: a chained entry consumes its
// members' DNS in chainIntercept, before serveExitDNS and outside the filter,
// and relays it to the final exit. A refused member's query must not leave
// and an answer already on its way must not reach it.
func TestChainDNSHonoursQuarantineAndLostMode(t *testing.T) {
	f := newExitDNSG3Fixture(t)
	f.chainEntry()
	e := f.e

	if !e.chainIntercept(f.udpQuery(t, 1)) {
		t.Fatal("query not consumed")
	}
	out := f.injected(time.Second)
	if out == nil {
		t.Fatal("baseline: query not relayed")
	}
	sent, err := packet.Parse(out)
	if err != nil || sent.Dst != chainTestFinal || sent.DstPort != dnsPort {
		t.Fatalf("baseline relay %+v %v", sent, err)
	}
	answer, err := packet.BuildUDP4(chainTestFinal, e.self.IPv4, dnsPort, sent.SrcPort, answerFor(sent.Payload, 1, 30))
	if err != nil {
		t.Fatal(err)
	}
	if !e.chainIntercept(answer) {
		t.Fatal("answer not consumed")
	}
	back := f.injected(time.Second)
	if back == nil {
		t.Fatal("baseline: answer not relayed")
	}
	if in, err := packet.Parse(back); err != nil || in.Dst != f.peer.IPv4 {
		t.Fatalf("baseline answer %+v %v", in, err)
	}

	// The flow of the query above stays open for the answer below.
	f.eachRefusal(t, func(t *testing.T, what string) {
		t.Helper()
		if !e.chainIntercept(f.udpQuery(t, 2)) {
			t.Fatalf("%s: query fell through instead of being dropped", what)
		}
		if p := f.injected(100 * time.Millisecond); p != nil {
			t.Fatalf("%s: a refused peer's query was relayed to the final exit", what)
		}
		if !e.chainIntercept(answer) {
			t.Fatalf("%s: answer not consumed", what)
		}
		if p := f.injected(100 * time.Millisecond); p != nil {
			t.Fatalf("%s: an answer was relayed to a refused peer", what)
		}
		status, err := packet.BuildUDP4(f.peer.IPv4, e.self.IPv4, chainStatusPort, chainStatusPort, chainStatusMagic)
		if err != nil {
			t.Fatal(err)
		}
		if !e.chainIntercept(status) {
			t.Fatalf("%s: status query not consumed", what)
		}
		if p := f.injected(100 * time.Millisecond); p != nil {
			t.Fatalf("%s: chain state answered to a refused peer", what)
		}
	})

	// A refused query leaves no flow behind (chainMaxFlows is shared).
	e.chain.mu.Lock()
	flows := len(e.chain.flows)
	e.chain.mu.Unlock()
	if flows != 1 {
		t.Fatalf("flows after refused queries: %d, want the baseline one", flows)
	}

	// Lifted: served again.
	if !e.chainIntercept(f.udpQuery(t, 3)) || f.injected(time.Second) == nil {
		t.Fatal("after release: query not relayed")
	}
}

// TestChainProbeStopsInLostMode: while lost, only the coordinator tunnel
// stays; the entry does not keep probing the final exit.
func TestChainProbeStopsInLostMode(t *testing.T) {
	f := newExitDNSG3Fixture(t)
	f.chainEntry()
	f.e.chainTick()
	if f.injected(time.Second) == nil {
		t.Fatal("baseline: no probe")
	}
	f.e.filter.SetIsolated(true)
	f.e.chainTick()
	if p := f.injected(100 * time.Millisecond); p != nil {
		t.Fatal("probe sent to the final exit in lost mode")
	}
}

// TestInfoHonoursQuarantineAndLostMode: a quarantined admin device, and any
// admin device while this one is lost, gets no system report or inventory.
func TestInfoHonoursQuarantineAndLostMode(t *testing.T) {
	f := newExitDNSG3Fixture(t)
	e := f.e
	e.admins = map[netip.Addr]bool{f.peer.IPv4: true}
	query := func(t *testing.T, typ string) []byte {
		t.Helper()
		data, err := control.Encode(control.Message{T: typ, ID: 7})
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := packet.BuildUDP4(f.peer.IPv4, e.self.IPv4, 41000, control.InfoPort, data)
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}
	if !e.serveInfo(query(t, control.TypeInfo)) || f.injected(5*time.Second) == nil {
		t.Fatal("baseline: no report")
	}
	if !e.serveInfo(query(t, control.TypeInfoDetail)) || f.injected(5*time.Second) == nil {
		t.Fatal("baseline: no inventory answer")
	}
	f.eachRefusal(t, func(t *testing.T, what string) {
		t.Helper()
		time.Sleep(infoInterval + 50*time.Millisecond) // the rate limit must not hide the answer
		e.serveInfo(query(t, control.TypeInfo))
		if p := f.injected(100 * time.Millisecond); p != nil {
			t.Fatalf("%s: system report sent to a refused admin", what)
		}
		e.serveInfo(query(t, control.TypeInfoDetail))
		if p := f.injected(100 * time.Millisecond); p != nil {
			t.Fatalf("%s: inventory sent to a refused admin", what)
		}
	})
	time.Sleep(infoInterval + 50*time.Millisecond)
	if !e.serveInfo(query(t, control.TypeInfo)) || f.injected(5*time.Second) == nil {
		t.Fatal("after release: no report")
	}
}

// TestGossipHonoursQuarantineAndLostMode: a refused peer is neither answered
// nor asked, and its hello queues no pull from it.
func TestGossipHonoursQuarantineAndLostMode(t *testing.T) {
	f := newExitDNSG3Fixture(t)
	e := f.e
	e.p15.gossip.init()
	hello := func(t *testing.T, version uint64) []byte {
		t.Helper()
		data, err := control.Encode(control.Message{T: control.TypeGossipHello, ID: 9, Version: version, Size: 10})
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := packet.BuildUDP4(f.peer.IPv4, e.self.IPv4, control.GossipPort, control.GossipPort, data)
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}
	if _, ok := e.gossipPeer(f.peer.IPv4); !ok {
		t.Fatal("the fixture's peer is not a tunnel peer")
	}
	if !e.serveGossip(hello(t, 0)) || f.injected(time.Second) == nil {
		t.Fatal("baseline: no answer")
	}
	now := time.Now()
	st := wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{f.peer.WireGuardKey: {LastHandshakeUnix: now.Unix()}}}
	if !e.gossipCandidate(f.peer, st, now) {
		t.Fatal("baseline: connected peer is no candidate")
	}
	newer := e.cfg.Store.Document().Version + 1
	f.eachRefusal(t, func(t *testing.T, what string) {
		t.Helper()
		if !e.serveGossip(hello(t, newer)) {
			t.Fatalf("%s: hello fell through", what)
		}
		if p := f.injected(100 * time.Millisecond); p != nil {
			t.Fatalf("%s: gossip answered to a refused peer", what)
		}
		select {
		case <-e.p15.gossip.pulls:
			t.Fatalf("%s: pull queued from a refused peer", what)
		default:
		}
		if e.gossipCandidate(f.peer, st, now) {
			t.Fatalf("%s: a round would ask a refused peer", what)
		}
	})
}

// gatedResolver answers plain DNS on 127.0.0.1, UDP and TCP, only after the
// test opens the gate; arrived says a query is waiting.
func gatedResolver(t *testing.T) (server netip.AddrPort, arrived <-chan struct{}, open func()) {
	t.Helper()
	var udp *net.UDPConn
	var tcp net.Listener
	// The free UDP port may be taken or reserved for TCP; try another one.
	for try := 0; tcp == nil; try++ {
		var err error
		udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		server = netip.MustParseAddrPort(udp.LocalAddr().String())
		if tcp, err = net.Listen("tcp4", server.String()); err != nil {
			_ = udp.Close()
			tcp = nil
			if try == 50 {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	came := make(chan struct{}, 8)
	gate := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			came <- struct{}{}
			<-gate
			_, _ = udp.WriteToUDPAddrPort(answerFor(append([]byte(nil), buf[:n]...), 1, 30), from)
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				came <- struct{}{}
				<-gate
				a := answerFor(q, 1, 30)
				binary.BigEndian.PutUint16(size[:], uint16(len(a))) //nolint:gosec // a test answer
				_, _ = c.Write(append(size[:], a...))
			}()
		}
	}()
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(gate) }) })
	return server, came, func() { once.Do(func() { close(gate) }) }
}

// TestExitDNSAnswerInFlightIsRefused: a peer quarantined while its query is
// with the upstream resolver gets no answer, on UDP and on TCP.
func TestExitDNSAnswerInFlightIsRefused(t *testing.T) {
	waitQuery := func(t *testing.T, arrived <-chan struct{}) {
		t.Helper()
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("query did not reach the upstream resolver")
		}
	}
	useGate := func(f exitDNSG3Fixture, server netip.AddrPort) {
		loop := netip.MustParseAddr("127.0.0.1")
		f.e.cfg.ExitDNSVia = func() (netip.AddrPort, netip.Addr, bool) { return server, loop, true }
	}
	t.Run("udp", func(t *testing.T) {
		f := newExitDNSG3Fixture(t)
		server, arrived, open := gatedResolver(t)
		useGate(f, server)
		if !f.e.serveExitDNS(f.udpQuery(t, 1)) {
			t.Fatal("query not consumed")
		}
		waitQuery(t, arrived)
		if err := f.e.filter.Quarantine(f.peer.Name, "test", 0); err != nil {
			t.Fatal(err)
		}
		open()
		if p := f.injected(500 * time.Millisecond); p != nil {
			t.Fatal("answer injected to a peer quarantined in flight")
		}
	})
	t.Run("tcp", func(t *testing.T) {
		f := newExitDNSG3Fixture(t)
		server, arrived, open := gatedResolver(t)
		useGate(f, server)
		client, self := netip.AddrPortFrom(f.peer.IPv4, 40200), netip.AddrPortFrom(f.e.self.IPv4, dnsPort)
		if !f.e.serveExitDNSTCP(buildTCP4(client, self, 1000, 0, tcpFlagSyn, 1360, nil)) {
			t.Fatal("SYN not consumed")
		}
		synAck, ok := parseTCP4(f.injected(time.Second))
		if !ok || synAck.flags&tcpFlagSyn == 0 {
			t.Fatalf("no SYN-ACK: %+v", synAck)
		}
		q := dnsQuery(t, 1, "uye.example.", dnsmessage.TypeA, 0)
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(q))) //nolint:gosec // a short query
		framed = append(framed, q...)
		f.e.serveExitDNSTCP(buildTCP4(client, self, 1001, synAck.seq+1, tcpFlagAck|tcpFlagPsh, 0, framed))
		waitQuery(t, arrived)
		for f.injected(50*time.Millisecond) != nil { // the ACK of the query
		}
		if err := f.e.filter.Quarantine(f.peer.Name, "test", 0); err != nil {
			t.Fatal(err)
		}
		open()
		if p := f.injected(500 * time.Millisecond); p != nil {
			t.Fatal("answer injected to a peer quarantined in flight")
		}
	})
}
