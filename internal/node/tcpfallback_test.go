package node

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/testnet"
)

// udpBlockBind drops every UDP datagram it is asked to send while blocked,
// like a network that lets no UDP out.
type udpBlockBind struct {
	conn.Bind
	blocked atomic.Bool
}

func (b *udpBlockBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.blocked.Load() {
		return nil
	}
	return b.Bind.Send(bufs, ep)
}

// A device whose network blocks UDP reaches the coordinator over the TCP
// transport and its peer through the relay over that same stream; when UDP
// works again it leaves TCP (ADR-0032).
func TestTCPFallbackWhenUDPBlocked(t *testing.T) {
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
	tcpAddr := coord.TCPAddr()
	if tcpAddr == nil {
		t.Fatal("no TCP listener")
	}

	aStore, bStore := tn.join(t, "laptop"), tn.join(t, "masaustu")
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	aBind := &udpBlockBind{Bind: testnet.NewLoopbackBind()}
	aBind.blocked.Store(true)
	a, err := New(Config{Store: aStore, Secrets: tn.aKey, TUN: aTUN.TUN(), ListenPort: freeUDPPort(t), Bind: aBind,
		TCPFallback: tcpAddr.String(), PollInterval: 300 * time.Millisecond, RelayAfter: time.Second, Logger: testLogger(t, "[laptop]")})
	if err != nil {
		t.Fatal(err)
	}
	a.tcp.echoFirst = 500 * time.Millisecond
	go func() { _ = a.Run(ctx) }()
	b, _ := startEngine(ctx, t, Config{Store: bStore, Secrets: tn.bKey, TUN: bTUN.TUN(), ListenPort: freeUDPPort(t), RelayAfter: time.Second})

	aSelf, _ := a.Self()
	bSelf, _ := b.Self()
	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 60*time.Second) {
		t.Fatalf("no traffic with UDP blocked (status %+v, tcp %v)", a.Status(), a.CoordinatorOverTCP())
	}
	if !a.CoordinatorOverTCP() {
		t.Fatal("traffic flowed but not over the TCP transport")
	}
	if st := a.Status(); st.LastSyncError != "" {
		// Syncing works over TCP too.
		waitFor(t, 10*time.Second, "sync over TCP", func() bool { return a.Status().LastSyncError == "" })
	}
	drainTUN(ctx, bTUN)

	// UDP works again: the echo moves the device back.
	aBind.blocked.Store(false)
	waitFor(t, 20*time.Second, "back on UDP", func() bool { return !a.CoordinatorOverTCP() && !a.tcp.Active() })
	waitFor(t, 20*time.Second, "sync over UDP", func() bool { return a.Status().LastSyncError == "" })
}

// An address that is not an OpenScale TCP transport is refused at the
// preamble, without sending any WireGuard data to it.
func TestTCPFallbackRefusesForeignService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	tf := newTCPFallback(testnet.NewLoopbackBind(), testLogger(t, "tcp"), time.Now)
	ap, _ := netipAddrPort(ln.Addr().String())
	if _, err := tf.dialStream(context.Background(), ap); err == nil {
		t.Fatal("foreign service accepted")
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, []byte(control.TCPMagic)) {
			t.Fatalf("sent %q before the preamble check, want only the preamble", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no preamble sent")
	}
}

func netipAddrPort(s string) (netip.AddrPort, error) { return netip.ParseAddrPort(s) }
