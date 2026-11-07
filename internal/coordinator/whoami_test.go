package coordinator

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
)

func TestWhoAmIAnswered(t *testing.T) {
	base := newMemBind()
	wb := newWhoAmIBind(base)
	fns, _, err := wb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer close(base.done)
	from := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("203.0.113.9:41641")}
	var nonce [control.WhoAmINonce]byte
	copy(nonce[:], bytes.Repeat([]byte{9}, control.WhoAmINonce))
	req := control.NewWhoAmIRequest(nonce)
	base.in <- memPkt{data: req, from: from}
	wg := make([]byte, 148)
	wg[0] = 1
	base.in <- memPkt{data: wg, from: from}
	packets, sizes, eps := [][]byte{make([]byte, 2048)}, []int{0}, []conn.Endpoint{nil}
	for {
		n, err := fns[0](packets, sizes, eps)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
	}
	if sizes[0] != 148 {
		t.Fatalf("WireGuard saw %d bytes; the request was not filtered", sizes[0])
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.sent) != 1 || len(base.sent[0]) != len(req) {
		t.Fatalf("reply %q: must be exactly the request's size", base.sent)
	}
	got, ok := control.ParseWhoAmIReply(base.sent[0], nonce)
	if !ok || got != from.AddrPort {
		t.Fatalf("reply says %v (%v), want %v", got, ok, from.AddrPort)
	}
	var other [control.WhoAmINonce]byte
	if _, ok := control.ParseWhoAmIReply(base.sent[0], other); ok {
		t.Fatal("reply accepted with another nonce")
	}
}

func TestWhoAmIRateLimited(t *testing.T) {
	wb := newWhoAmIBind(newMemBind())
	now := time.Unix(1000, 0)
	wb.now = func() time.Time { return now }
	n := 0
	for range 1000 {
		if wb.take() {
			n++
		}
	}
	if n != whoAmIBurst {
		t.Fatalf("%d replies in a burst, want %d", n, whoAmIBurst)
	}
	now = now.Add(time.Second)
	if !wb.take() {
		t.Fatal("no token after a second")
	}
}
