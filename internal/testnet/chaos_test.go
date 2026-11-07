package testnet

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// pair opens a chaos bind and a plain loopback socket that talk to it.
func pair(t *testing.T) (*ChaosBind, conn.ReceiveFunc, uint16, *net.UDPConn) {
	t.Helper()
	b := NewChaosBind(NewLoopbackBind(), 1)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return b, fns[0], port, peer
}

func endpointOf(t *testing.T, b conn.Bind, c *net.UDPConn) conn.Endpoint {
	t.Helper()
	ep, err := b.ParseEndpoint(c.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func received(c *net.UDPConn, within time.Duration) int {
	n := 0
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(within))
	for {
		if _, _, err := c.ReadFromUDP(buf); err != nil {
			return n
		}
		n++
	}
}

func TestChaosSendLossPartitionAndDelay(t *testing.T) {
	b, _, _, peer := pair(t)
	ep := endpointOf(t, b, peer)
	send := func(n int) {
		for i := 0; i < n; i++ {
			if err := b.Send([][]byte{[]byte("x")}, ep); err != nil {
				t.Fatal(err)
			}
		}
	}
	send(5)
	if got := received(peer, 300*time.Millisecond); got != 5 {
		t.Fatalf("clean: %d of 5", got)
	}
	b.SetPartition(true)
	send(5)
	if got := received(peer, 200*time.Millisecond); got != 0 {
		t.Fatalf("partition let %d through", got)
	}
	b.SetPartition(false)
	b.BlockPort(uint16(peer.LocalAddr().(*net.UDPAddr).Port), true)
	send(3)
	if got := received(peer, 200*time.Millisecond); got != 0 {
		t.Fatalf("blocked port let %d through", got)
	}
	b.BlockPort(uint16(peer.LocalAddr().(*net.UDPAddr).Port), false)
	b.SetLoss(0.5)
	send(200)
	got := received(peer, 500*time.Millisecond)
	if got < 60 || got > 140 {
		t.Fatalf("50%% loss passed %d of 200", got)
	}
	b.SetLoss(0)
	b.SetDelay(150 * time.Millisecond)
	start := time.Now()
	send(1)
	if got := received(peer, time.Second); got != 1 || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("delayed send: %d after %v", got, time.Since(start))
	}
	if dropped, passed := b.Stats(); dropped == 0 || passed == 0 {
		t.Fatalf("stats %d/%d", dropped, passed)
	}
}

func TestChaosReceiveFilter(t *testing.T) {
	b, recv, port, peer := pair(t)
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, port))
	b.SetPartition(true)
	type result struct {
		n    int
		err  error
		data string
	}
	done := make(chan result, 1)
	go func() {
		packets, sizes, eps := [][]byte{make([]byte, 64)}, []int{0}, []conn.Endpoint{nil}
		n, err := recv(packets, sizes, eps)
		done <- result{n, err, string(packets[0][:sizes[0]])}
	}()
	if _, err := peer.WriteToUDP([]byte("kayıp"), dst); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if dropped, _ := b.Stats(); dropped == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("partitioned packet was not read and dropped")
		}
	}
	b.SetPartition(false)
	if _, err := peer.WriteToUDP([]byte("geçer"), dst); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.n != 1 || r.data != "geçer" {
			t.Fatalf("recv %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet after the partition healed")
	}
}
