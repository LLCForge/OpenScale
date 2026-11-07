package node

import (
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// exitDNSG3Fixture is an exit node engine ("vps") with a member allowed to
// use it ("telefon") and a loopback upstream resolver that counts queries.
type exitDNSG3Fixture struct {
	e       *Engine
	peer    trust.Device
	queries *atomic.Int32
}

func newExitDNSG3Fixture(t *testing.T) exitDNSG3Fixture {
	t.Helper()
	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, cwg, _ := cs.PublicKeys()
	commit(t, n, func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", cwg) })
	enroll(t, n, "vps")
	enroll(t, n, "telefon")
	commit(t, n, func(doc *trust.Document) error { return doc.SetExitNode("vps", true) })
	store := join(t, n, filepath.Join(base, "vps"))
	doc := store.Document()
	self, ok := doc.DeviceByName("vps")
	if !ok {
		t.Fatal("vps missing")
	}
	peer, ok := doc.DeviceByName("telefon")
	if !ok || !doc.MayUseExitNode("telefon") {
		t.Fatal("telefon cannot use the exit node")
	}

	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	var queries atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			k, from, err := up.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			if resp := answerFor(append([]byte(nil), buf[:k]...), 1, 30); resp != nil {
				_, _ = up.WriteToUDPAddrPort(resp, from)
			}
		}
	}()
	server := netip.MustParseAddrPort(up.LocalAddr().String())
	loop := netip.MustParseAddr("127.0.0.1")

	e := &Engine{
		cfg: Config{
			Store:      store,
			Now:        time.Now,
			ExitDNSVia: func() (netip.AddrPort, netip.Addr, bool) { return server, loop, true },
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		filter:   filter.New(time.Now),
		wrap:     &wrapTUN{inject: make(chan []byte, 16)},
		dnsSem:   make(chan struct{}, exitDNSConcurrency),
		self:     self,
		exitRole: true,
	}
	return exitDNSG3Fixture{e: e, peer: peer, queries: &queries}
}

// udpQuery is peer's UDP DNS query to the exit node's overlay address.
func (f exitDNSG3Fixture) udpQuery(t *testing.T, id uint16) []byte {
	t.Helper()
	pkt, err := packet.BuildUDP4(f.peer.IPv4, f.e.self.IPv4, 40000+id, dnsPort, dnsQuery(t, id, "uye.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

// injected waits up to d for a packet on the inject queue.
func (f exitDNSG3Fixture) injected(d time.Duration) []byte {
	select {
	case p := <-f.e.wrap.inject:
		return p
	case <-time.After(d):
		return nil
	}
}

// TestExitDNSHonoursQuarantineAndLostMode: the exit DNS handlers run before
// the packet filter, so they must apply the device's own quarantine and
// lost mode decision: a quarantined (or, in lost mode, any) peer's UDP or
// TCP query never reaches the upstream resolver and gets no answer.
func TestExitDNSHonoursQuarantineAndLostMode(t *testing.T) {
	f := newExitDNSG3Fixture(t)
	e := f.e

	// Baseline: the member's query is forwarded and answered.
	if !e.serveExitDNS(f.udpQuery(t, 1)) {
		t.Fatal("query not consumed")
	}
	reply := f.injected(5 * time.Second)
	if reply == nil {
		t.Fatal("baseline: no answer")
	}
	if in, err := packet.Parse(reply); err != nil || in.Dst != f.peer.IPv4 || in.SrcPort != dnsPort {
		t.Fatalf("baseline answer %+v %v", in, err)
	}
	if f.queries.Load() != 1 {
		t.Fatalf("baseline upstream queries %d", f.queries.Load())
	}
	syn := buildTCP4(netip.AddrPortFrom(f.peer.IPv4, 40100), netip.AddrPortFrom(e.self.IPv4, dnsPort), 1000, 0, tcpFlagSyn, 1360, nil)
	if !e.serveExitDNSTCP(syn) {
		t.Fatal("SYN not consumed")
	}
	if f.injected(time.Second) == nil {
		t.Fatal("baseline: no SYN-ACK")
	}
	e.netDNS.exitTCP = tcpDNS{}

	refused := func(t *testing.T, what string) {
		t.Helper()
		before := f.queries.Load()
		if !e.serveExitDNS(f.udpQuery(t, 2)) {
			t.Fatalf("%s: UDP query fell through instead of being dropped", what)
		}
		if p := f.injected(300 * time.Millisecond); p != nil {
			t.Fatalf("%s: UDP answer injected to a refused peer", what)
		}
		if !e.serveExitDNSTCP(syn) {
			t.Fatalf("%s: SYN fell through instead of being dropped", what)
		}
		if p := f.injected(300 * time.Millisecond); p != nil {
			t.Fatalf("%s: TCP handshake answered to a refused peer", what)
		}
		if got := f.queries.Load(); got != before {
			t.Fatalf("%s: upstream saw %d queries from a refused peer", what, got-before)
		}
	}

	// Owner's quarantine.
	if err := e.filter.Quarantine("telefon", "test", 0); err != nil {
		t.Fatal(err)
	}
	refused(t, "quarantine")
	e.filter.Release("telefon")

	// An expired quarantine no longer refuses.
	if err := e.filter.Quarantine("telefon", "test", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if e.exitDNSRefused("telefon") {
		t.Fatal("expired quarantine still refuses")
	}
	e.filter.Release("telefon")

	// Lost mode: every peer.
	e.filter.SetIsolated(true)
	refused(t, "lost mode")
	e.filter.SetIsolated(false)

	// Lifted: served again.
	if !e.serveExitDNS(f.udpQuery(t, 3)) || f.injected(5*time.Second) == nil {
		t.Fatal("after release: no answer")
	}
}
