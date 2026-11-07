package p2psend

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// Regression tests for the F2 security findings (files rule on relayed
// offers, replay cache filled before authentication). 127.0.0.1 only.

// TestFilesRuleEnforcedForRelayedSender: a member without a files rule to
// the receiver must not reach the approval queue, neither directly nor
// through relays that do hold a rule (the packet filter only sees the
// last hop).
func TestFilesRuleEnforcedForRelayedSender(t *testing.T) {
	sender, r1id, r2id, recvID := newID(t), newID(t), newID(t), newID(t)
	dir := NewStaticDirectory(
		Peer{Name: "laptop", Key: sender.Public, Addr: loopback()},
		Peer{Name: "r1", Key: r1id.Public, Addr: loopback()},
		Peer{Name: "r2", Key: r2id.Public, Addr: loopback()},
	)
	r1 := startNode(t, r1id, dir, true, acceptAll, nil)
	r2 := startNode(t, r2id, dir, true, acceptAll, nil)
	var asks atomic.Int32
	dst := startNode(t, recvID, dir, false, func(context.Context, Offer) (bool, error) { asks.Add(1); return true, nil },
		func(c *Config) {
			// Only the relays have a files rule to this device.
			c.AllowFile = func(from string) bool { return from == "r1" || from == "r2" }
		})
	src := writeFile(t, "yasak.txt", []byte("kural yok"))
	_, err := Send(ctxT(t), sender, Target{Name: "dst", Key: recvID.Public, Addr: dst.addr}, src, &SendOptions{
		Route: RouteOnion, Hops: []Hop{{Key: r1id.Public, Addr: r1.addr}, {Key: r2id.Public, Addr: r2.addr}},
	})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("relayed offer without files rule: got %v, want rejected", err)
	}
	_, err = Send(ctxT(t), sender, Target{Key: recvID.Public, Addr: dst.addr}, src, &SendOptions{Route: RouteDirect})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("direct offer without files rule: got %v, want rejected", err)
	}
	if n := asks.Load(); n != 0 {
		t.Fatalf("offer reached the approval queue %d times", n)
	}
	if files, _ := (Quarantine{Dir: dst.dir}).List(); len(files) != 0 {
		t.Fatalf("quarantine holds %d files", len(files))
	}
}

// TestFilesRuleRecheckedAfterApproval: a rule removed while the offer
// waited for the owner stops the transfer.
func TestFilesRuleRecheckedAfterApproval(t *testing.T) {
	sender, recvID := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	var allowed atomic.Bool
	allowed.Store(true)
	dst := startNode(t, recvID, dir, false, func(context.Context, Offer) (bool, error) {
		allowed.Store(false) // document changed during approval
		return true, nil
	}, func(c *Config) { c.AllowFile = func(string) bool { return allowed.Load() } })
	_, err := Send(ctxT(t), sender, Target{Key: recvID.Public, Addr: dst.addr}, writeFile(t, "a.txt", []byte("a")),
		&SendOptions{Route: RouteDirect})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want rejected after rule removal", err)
	}
}

func TestNewServerRequiresAllowFile(t *testing.T) {
	id := newID(t)
	_, err := NewServer(Config{Identity: id, Directory: NewStaticDirectory(), QuarantineDir: t.TempDir(), Ask: acceptAll})
	if err == nil {
		t.Fatal("server without files rule check was created")
	}
}

// TestForgedHellosDoNotFillReplayCache: hellos that fail header
// authentication (anyone can put a member's public key in the sender
// field) must not use replay cache space; afterwards a real transfer works.
func TestForgedHellosDoNotFillReplayCache(t *testing.T) {
	sender, recvID := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	dst := startNode(t, recvID, dir, false, acceptAll, nil)
	ctx := ctxT(t)
	for i := 0; i < maxReplayEntries+16; i++ {
		var b bytes.Buffer
		b.Write(sender.Public[:])
		eph := newID(t).Public
		b.Write(eph[:])
		_ = binary.Write(&b, binary.BigEndian, uint16(16))
		b.Write(randBytes(t, 16))
		a, c := net.Pipe()
		dst.srv.handleFile(ctx, a, bufio.NewReader(&b))
		_ = a.Close()
		_ = c.Close()
	}
	if _, err := Send(ctx, sender, Target{Key: recvID.Public, Addr: dst.addr}, writeFile(t, "a.txt", []byte("gerçek")),
		&SendOptions{Route: RouteDirect}); err != nil {
		t.Fatalf("legitimate transfer refused after forged hellos: %v", err)
	}
	<-dst.recv
}

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// TestRelayFloodFromOneHopDoesNotStopRelay: one member flooding a relay
// with valid layers fills only its own replay quota; other members are
// still relayed.
func TestRelayFloodFromOneHopDoesNotStopRelay(t *testing.T) {
	relayID := newID(t)
	evil := netip.MustParseAddr("127.0.0.2")
	good := netip.MustParseAddr("127.0.0.3")
	target := netip.MustParseAddr("127.0.0.4")
	dir := NewStaticDirectory(
		Peer{Name: "evil", Key: newID(t).Public, Addr: evil},
		Peer{Name: "good", Key: newID(t).Public, Addr: good},
		Peer{Name: "target", Key: newID(t).Public, Addr: target},
	)
	var dials atomic.Int32
	r := startNode(t, relayID, dir, true, acceptAll, func(c *Config) {
		c.Dial = func(context.Context, netip.AddrPort) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("test: no dial")
		}
	})
	ctx := ctxT(t)
	relayOnce := func(from netip.Addr, next netip.AddrPort) {
		t.Helper()
		layer, err := sealLayer(relayID.Public, next, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		a, c := net.Pipe()
		conn := addrConn{Conn: a, remote: &net.TCPAddr{IP: from.AsSlice(), Port: 40000}}
		r.srv.handleRelay(ctx, conn, bufio.NewReader(bytes.NewReader(layer[6:])))
		_ = a.Close()
		_ = c.Close()
	}
	outsider := netip.MustParseAddrPort("127.0.0.9:4054") // not a member: no dial
	for i := 0; i < maxReplayEntries+16; i++ {
		relayOnce(evil, outsider)
	}
	if dials.Load() != 0 {
		t.Fatal("relay dialled a non-member")
	}
	relayOnce(good, netip.AddrPortFrom(target, 4054))
	if dials.Load() != 1 {
		t.Fatal("relay refused another member after one member's flood")
	}
}

// TestReplayCacheQuotaKeepsOtherSourcesEntries: eviction under pressure
// only removes the flooding source's own entries.
func TestReplayCacheQuotaKeepsOtherSourcesEntries(t *testing.T) {
	r := startNode(t, newID(t), NewStaticDirectory(), false, acceptAll, nil)
	keep := newID(t).Public
	if r.srv.seen("good", keep) {
		t.Fatal("fresh key reported as replay")
	}
	for i := 0; i < 3*maxReplayPerSource; i++ {
		if r.srv.seen("evil", newID(t).Public) {
			t.Fatal("fresh key reported as replay")
		}
	}
	if !r.srv.seen("good", keep) {
		t.Fatal("other source's entry was evicted by the flood")
	}
	r.srv.mu.Lock()
	n := len(r.srv.replay.bySrc["evil"])
	r.srv.mu.Unlock()
	if n > maxReplayPerSource {
		t.Fatalf("source holds %d entries, cap %d", n, maxReplayPerSource)
	}
}
