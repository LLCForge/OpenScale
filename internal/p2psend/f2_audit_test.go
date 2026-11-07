package p2psend

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// Regression test from the independent review of the F2 fixes. 127.0.0.1
// only.

// TestFilesRuleRecheckedBeforePlacing: the packet filter sees only the last
// relay, so nothing else stops a relayed stream when the sender's rule is
// removed mid-transfer. The file must not enter quarantine and its partial
// data must not stay behind for a later resume.
func TestFilesRuleRecheckedBeforePlacing(t *testing.T) {
	sender, recvID := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	// The first two checks are before the queue and after approval; the rule
	// is gone from the third on.
	var checks atomic.Int32
	dst := startNode(t, recvID, dir, false, acceptAll, func(c *Config) {
		c.AllowFile = func(string) bool { return checks.Add(1) <= 2 }
	})
	_, err := Send(ctxT(t), sender, Target{Key: recvID.Public, Addr: dst.addr}, writeFile(t, "a.txt", []byte("kural aktarimda kalkti")),
		&SendOptions{Route: RouteDirect})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want rejected after mid-transfer rule removal", err)
	}
	if n := checks.Load(); n < 3 {
		t.Fatalf("files rule checked %d times, want a check after the data arrived", n)
	}
	files, err := (Quarantine{Dir: dst.dir}).List()
	if err != nil || len(files) != 0 {
		t.Fatalf("quarantine: %+v %v", files, err)
	}
	parts, err := os.ReadDir(filepath.Join(dst.dir, partialDirName))
	if err != nil || len(parts) != 0 {
		t.Fatalf("partial data left behind: %v %v", parts, err)
	}
}

// TestForgedInputTakesNoReplayEntries: since a full quota evicts instead of
// refusing, a flood no longer blocks transfers even when forged input does
// reach the cache, but it would silently evict the victim's entries and
// reopen the replay window. So the entries themselves must stay untouched.
func TestForgedInputTakesNoReplayEntries(t *testing.T) {
	sender, recvID := newID(t), newID(t)
	member := netip.MustParseAddr("127.0.0.2")
	dir := NewStaticDirectory(
		Peer{Name: "laptop", Key: sender.Public, Addr: loopback()},
		Peer{Name: "uye", Key: newID(t).Public, Addr: member},
	)
	dst := startNode(t, recvID, dir, true, acceptAll, nil)
	ctx := ctxT(t)

	// A hello naming a member's key without knowing that member's secret.
	var hello bytes.Buffer
	hello.Write(sender.Public[:])
	eph := newID(t).Public
	hello.Write(eph[:])
	_ = binary.Write(&hello, binary.BigEndian, uint16(16))
	hello.Write(randBytes(t, 16))
	a, c := net.Pipe()
	dst.srv.handleFile(ctx, a, bufio.NewReader(&hello))
	_ = a.Close()
	_ = c.Close()

	// A relay layer whose ciphertext does not open.
	layer, err := sealLayer(recvID.Public, netip.MustParseAddrPort("127.0.0.3:4054"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	layer[len(layer)-1] ^= 0xff
	a, c = net.Pipe()
	conn := addrConn{Conn: a, remote: &net.TCPAddr{IP: member.AsSlice(), Port: 40000}}
	dst.srv.handleRelay(ctx, conn, bufio.NewReader(bytes.NewReader(layer[6:])))
	_ = a.Close()
	_ = c.Close()

	dst.srv.mu.Lock()
	n := len(dst.srv.replay.byKey)
	dst.srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("forged input took %d replay entries", n)
	}
}

// TestFilesRuleStillAllowsCompleteTransfer is the control for the test
// above: with the rule in place all three checks pass and the file arrives.
func TestFilesRuleStillAllowsCompleteTransfer(t *testing.T) {
	sender, recvID := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	dst := startNode(t, recvID, dir, false, acceptAll, nil)
	if _, err := Send(ctxT(t), sender, Target{Key: recvID.Public, Addr: dst.addr}, writeFile(t, "a.txt", []byte("izinli")),
		&SendOptions{Route: RouteDirect}); err != nil {
		t.Fatal(err)
	}
	<-dst.recv
}
