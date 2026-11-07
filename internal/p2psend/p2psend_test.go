package p2psend

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every test listens on 127.0.0.1 only.

type node struct {
	id   Identity
	addr netip.AddrPort
	srv  *Server
	dir  string
	recv chan Received
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newID(t *testing.T) Identity {
	t.Helper()
	id, err := GenerateIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// startNode runs a server on 127.0.0.1; ask decides offers.
func startNode(t *testing.T, id Identity, dir Directory, relay bool, ask func(context.Context, Offer) (bool, error), mod func(*Config)) *node {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := &node{id: id, addr: ln.Addr().(*net.TCPAddr).AddrPort(), dir: t.TempDir(), recv: make(chan Received, 4)}
	cfg := Config{Identity: id, Directory: dir, QuarantineDir: n.dir, Ask: ask, Relay: relay,
		AllowFile:  func(string) bool { return true },
		OnReceived: func(r Received) { n.recv <- r }, IdleTimeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return n
}

func acceptAll(context.Context, Offer) (bool, error) { return true, nil }

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func loopback() netip.Addr { return netip.MustParseAddr("127.0.0.1") }

func TestDirectSendRoundTrip(t *testing.T) {
	sender, recv := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	var offered Offer
	r := startNode(t, recv, dir, false, func(_ context.Context, o Offer) (bool, error) { offered = o; return true, nil }, nil)
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, 3*ChunkSize + 17} {
		data := randBytes(t, size)
		src := writeFile(t, "rapor.bin", data)
		var last int64
		reg := NewRegistry()
		res, err := Send(ctxT(t), sender, Target{Name: "masa", Key: recv.Public, Addr: r.addr}, src,
			&SendOptions{Route: RouteDirect, Progress: func(d, _ int64) { last = d }, Registry: reg})
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		got := <-r.recv
		b, err := os.ReadFile(got.Path)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("size %d: content mismatch", size)
		}
		if res.Path != PathDirect || got.From != "laptop" || offered.Name != "rapor.bin" || offered.Size != int64(size) {
			t.Fatalf("unexpected result %+v %+v %+v", res, got, offered)
		}
		if last != int64(size) {
			t.Fatalf("progress %d, want %d", last, size)
		}
		if l := reg.List(); len(l) != 1 || l[0].State != StateDone || l[0].Done != int64(size) {
			t.Fatalf("registry %+v", l)
		}
	}
	files, _ := Quarantine{Dir: r.dir}.List()
	if len(files) != 5 {
		t.Fatalf("quarantine holds %d files", len(files))
	}
}

func TestRejectAndUnknownSender(t *testing.T) {
	sender, recv, stranger := newID(t), newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	r := startNode(t, recv, dir, false, func(context.Context, Offer) (bool, error) { return false, nil }, nil)
	src := writeFile(t, "a.txt", []byte("merhaba"))
	_, err := Send(ctxT(t), sender, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want rejected", err)
	}
	// A key that is not in the signed document gets no answer at all.
	_, err = Send(ctxT(t), stranger, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect})
	if err == nil {
		t.Fatal("unknown sender was accepted")
	}
}

func TestWrongRecipientKeyFails(t *testing.T) {
	sender, recv, other := newID(t), newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	var asked atomic.Bool
	r := startNode(t, recv, dir, false, func(context.Context, Offer) (bool, error) { asked.Store(true); return true, nil }, nil)
	src := writeFile(t, "a.txt", []byte("gizli"))
	// Encrypting to another key: the receiver cannot open the header.
	if _, err := Send(ctxT(t), sender, Target{Key: other.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect}); err == nil {
		t.Fatal("send to the wrong key succeeded")
	}
	if asked.Load() {
		t.Fatal("receiver was asked about a header it cannot have decrypted")
	}
}

func TestTooLarge(t *testing.T) {
	sender, recv := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	r := startNode(t, recv, dir, false, acceptAll, func(c *Config) { c.MaxSize = 10 })
	src := writeFile(t, "b.bin", randBytes(t, 11))
	if _, err := Send(ctxT(t), sender, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

// cutConn closes after n bytes are written, simulating a dropped link.
type cutConn struct {
	net.Conn
	left int
}

func (c *cutConn) Write(p []byte) (int, error) {
	if c.left <= 0 {
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	if len(p) > c.left {
		n, _ := c.Conn.Write(p[:c.left])
		c.left = 0
		_ = c.Conn.Close()
		return n, io.ErrClosedPipe
	}
	c.left -= len(p)
	return c.Conn.Write(p)
}

func TestResume(t *testing.T) {
	sender, recv := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	r := startNode(t, recv, dir, false, acceptAll, nil)
	data := randBytes(t, 5*ChunkSize+100)
	src := writeFile(t, "film.bin", data)
	cut := func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", a.String())
		if err != nil {
			return nil, err
		}
		// Hello (~600 bytes) plus three full records.
		return &cutConn{Conn: c, left: 2048 + 3*RecordSize}, nil
	}
	if _, err := Send(ctxT(t), sender, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect, Dial: cut}); err == nil {
		t.Fatal("cut transfer succeeded")
	}
	// Wait until the receiver released the partial file.
	deadline := time.Now().Add(10 * time.Second)
	var res SendResult
	var err error
	for time.Now().Before(deadline) {
		res, err = Send(ctxT(t), sender, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect})
		if !errors.Is(err, ErrBusy) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.Resumed < 2*ChunkSize {
		t.Fatalf("resumed only %d bytes", res.Resumed)
	}
	got := <-r.recv
	b, _ := os.ReadFile(got.Path)
	if !bytes.Equal(b, data) {
		t.Fatal("resumed content mismatch")
	}
}

// flipConn flips one byte in the data records.
type flipConn struct {
	net.Conn
	written int
	at      int
}

func (c *flipConn) Write(p []byte) (int, error) {
	q := bytes.Clone(p)
	if c.at >= c.written && c.at < c.written+len(q) {
		q[c.at-c.written] ^= 0x40
	}
	c.written += len(q)
	return c.Conn.Write(q)
}

func TestTamperedRecordIsRejected(t *testing.T) {
	sender, recv := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	r := startNode(t, recv, dir, false, acceptAll, nil)
	src := writeFile(t, "c.bin", randBytes(t, 2*ChunkSize))
	flip := func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", a.String())
		if err != nil {
			return nil, err
		}
		return &flipConn{Conn: c, at: 2000 + RecordSize + 10}, nil
	}
	_, err := Send(ctxT(t), sender, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect, Dial: flip})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("got %v, want integrity", err)
	}
	select {
	case <-r.recv:
		t.Fatal("tampered file was stored")
	default:
	}
}

// recorder records every byte a relay or sender writes on the wire.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) dial(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", a.String())
	if err != nil {
		return nil, err
	}
	return &tapConn{Conn: c, r: r}, nil
}

type tapConn struct {
	net.Conn
	r *recorder
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.r.mu.Lock()
	c.r.buf.Write(p)
	c.r.mu.Unlock()
	return c.Conn.Write(p)
}

func TestOnionRouteTwoRelays(t *testing.T) {
	sender, r1id, r2id, recvID := newID(t), newID(t), newID(t), newID(t)
	dir := NewStaticDirectory(
		Peer{Name: "laptop", Key: sender.Public, Addr: loopback()},
		Peer{Name: "r1", Key: r1id.Public, Addr: loopback()},
		Peer{Name: "r2", Key: r2id.Public, Addr: loopback()},
	)
	wire := &recorder{}
	r1 := startNode(t, r1id, dir, true, acceptAll, func(c *Config) { c.Dial = wire.dial })
	r2 := startNode(t, r2id, dir, true, acceptAll, func(c *Config) { c.Dial = wire.dial })
	dst := startNode(t, recvID, dir, false, acceptAll, nil)
	secret := []byte("çok gizli rapor içeriği: " + string(randBytes(t, 16)))
	name := "maaş-bordrosu-2026.txt"
	src := writeFile(t, name, secret)
	res, err := Send(ctxT(t), sender, Target{Name: "dst", Key: recvID.Public, Addr: dst.addr}, src, &SendOptions{
		Route: RouteOnion, Hops: []Hop{{Key: r1id.Public, Addr: r1.addr}, {Key: r2id.Public, Addr: r2.addr}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != PathOnion || res.Hops != 2 {
		t.Fatalf("result %+v", res)
	}
	got := <-dst.recv
	b, _ := os.ReadFile(got.Path)
	if !bytes.Equal(b, secret) || got.From != "laptop" {
		t.Fatal("onion content mismatch")
	}
	// Neither the name nor the content appears in what the relays sent on.
	wire.mu.Lock()
	seen := wire.buf.Bytes()
	wire.mu.Unlock()
	if bytes.Contains(seen, []byte(name)) || bytes.Contains(seen, secret[:20]) {
		t.Fatal("relay traffic leaks the file name or content")
	}
}

func TestOnionRouteRules(t *testing.T) {
	a, b := newID(t), newID(t)
	dest := netip.MustParseAddrPort("127.0.0.1:9")
	if _, err := BuildOnion([]Hop{{Key: a.Public, Addr: dest}}, dest, b.Public, nil); !errors.Is(err, ErrRoute) {
		t.Fatal("single hop accepted")
	}
	if _, err := BuildOnion([]Hop{{Key: a.Public, Addr: dest}, {Key: a.Public, Addr: dest}}, dest, b.Public, nil); !errors.Is(err, ErrRoute) {
		t.Fatal("repeated hop accepted")
	}
	if _, err := BuildOnion([]Hop{{Key: a.Public, Addr: dest}, {Key: b.Public, Addr: dest}}, dest, b.Public, nil); !errors.Is(err, ErrRoute) {
		t.Fatal("destination as hop accepted")
	}
	c := newID(t)
	onion, err := BuildOnion([]Hop{{Key: a.Public, Addr: dest}, {Key: c.Public, Addr: netip.MustParseAddrPort("127.0.0.1:10")}}, dest, b.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseLayer(a, onion)
	if err != nil || next != netip.MustParseAddrPort("127.0.0.1:10") {
		t.Fatalf("first layer next %v err %v", next, err)
	}
	if _, err := ParseLayer(c, onion); err == nil {
		t.Fatal("second relay opened the first layer")
	}
	if _, err := Send(ctxT(t), a, Target{Key: b.Public, Addr: dest}, writeFile(t, "x", []byte("x")), &SendOptions{Route: RouteOnion}); !errors.Is(err, ErrRoute) {
		t.Fatalf("onion without hops: %v", err)
	}
}

func TestRelayRefusesNonMemberTarget(t *testing.T) {
	sender, r1id, r2id, recvID := newID(t), newID(t), newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	// The relays are not in the directory, and relaying is off on r2.
	r1 := startNode(t, r1id, NewStaticDirectory(), true, acceptAll, nil)
	r2 := startNode(t, r2id, dir, false, acceptAll, nil)
	dst := startNode(t, recvID, dir, false, acceptAll, nil)
	_, err := Send(ctxT(t), sender, Target{Key: recvID.Public, Addr: dst.addr}, writeFile(t, "a", []byte("a")), &SendOptions{
		Route: RouteOnion, Hops: []Hop{{Key: r1id.Public, Addr: r1.addr}, {Key: r2id.Public, Addr: r2.addr}},
	})
	if err == nil {
		t.Fatal("relay forwarded for a non-member")
	}
}

func TestReplayedHelloIsDropped(t *testing.T) {
	sender, recv := newID(t), newID(t)
	dir := NewStaticDirectory(Peer{Name: "laptop", Key: sender.Public, Addr: loopback()})
	var asks atomic.Int32
	r := startNode(t, recv, dir, false, func(context.Context, Offer) (bool, error) { asks.Add(1); return true, nil }, nil)
	wire := &recorder{}
	src := writeFile(t, "a.txt", []byte("bir kez"))
	if _, err := Send(ctxT(t), sender, Target{Key: recv.Public, Addr: r.addr}, src, &SendOptions{Route: RouteDirect, Dial: wire.dial}); err != nil {
		t.Fatal(err)
	}
	<-r.recv
	c, err := net.Dial("tcp", r.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wire.mu.Lock()
	_, _ = c.Write(wire.buf.Bytes())
	wire.mu.Unlock()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if n, _ := c.Read(one[:]); n != 0 {
		t.Fatal("replayed hello got an answer")
	}
	if asks.Load() != 1 {
		t.Fatalf("receiver asked %d times", asks.Load())
	}
}

func TestHeaderPaddingHidesNameLength(t *testing.T) {
	short, err := encodeHeader(header{V: 1, ID: "00112233445566778899aabbccddeeff", Name: "a", SHA256: string(bytes.Repeat([]byte("0"), 64)), Chunk: ChunkSize})
	if err != nil {
		t.Fatal(err)
	}
	long, err := encodeHeader(header{V: 1, ID: "00112233445566778899aabbccddeeff", Name: "abcdefghijklmnopqrstuvwxyz0123456789", SHA256: string(bytes.Repeat([]byte("0"), 64)), Chunk: ChunkSize})
	if err != nil {
		t.Fatal(err)
	}
	if len(short) != len(long) || len(short)%headerPad != 0 {
		t.Fatalf("header sizes %d and %d", len(short), len(long))
	}
	h, err := decodeHeader(long)
	if err != nil || h.validate(0) != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestApprovals(t *testing.T) {
	a := NewApprovals(time.Second)
	res := make(chan bool, 1)
	go func() {
		ok, _ := a.Ask(context.Background(), Offer{From: "x", Name: "y"})
		res <- ok
	}()
	var p []Offer
	for i := 0; i < 100 && len(p) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		p = a.Pending()
	}
	if len(p) != 1 {
		t.Fatal("offer not pending")
	}
	if err := a.Decide(p[0].ID, true); err != nil || !<-res {
		t.Fatal("accept not delivered")
	}
	if err := a.Decide(p[0].ID, true); !errors.Is(err, ErrNoOffer) {
		t.Fatal("double decision accepted")
	}
	ok, _ := a.Ask(context.Background(), Offer{})
	if ok {
		t.Fatal("unanswered offer accepted after timeout")
	}
}

func TestQuarantineRelease(t *testing.T) {
	q := Quarantine{Dir: t.TempDir(), Inbox: filepath.Join(t.TempDir(), "gelen")}
	if err := os.WriteFile(filepath.Join(q.Dir, "kur.exe"), []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := q.List()
	if err != nil || len(l) != 1 || !l[0].Executable || l[0].Warning == "" {
		t.Fatalf("list %+v %v", l, err)
	}
	if _, err := q.Release("../kur.exe"); !errors.Is(err, ErrNotInQuarantine) {
		t.Fatal("traversal accepted")
	}
	dst, err := q.Release("kur.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryFromDevices(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	k1, k2 := newID(t), newID(t)
	d := DirectoryFromDevices([]DeviceRecord{
		{Name: "a", WireGuard: k1.Public, IPv4: netip.MustParseAddr("100.64.0.1"), ExpiresAt: now.Add(time.Hour)},
		{Name: "b", WireGuard: k2.Public, IPv4: netip.MustParseAddr("100.64.0.2"), ExpiresAt: now.Add(-time.Hour)},
	}, now)
	if _, ok := d.ByKey(k1.Public); !ok {
		t.Fatal("live device missing")
	}
	if _, ok := d.ByKey(k2.Public); ok {
		t.Fatal("expired device listed")
	}
}
