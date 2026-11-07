package obfs

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func testKey(t *testing.T) Key {
	t.Helper()
	k, err := DeriveKey("net-test-1")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wgInit() []byte {
	b := make([]byte, 148)
	b[0] = 1
	for i := 4; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	s, err := NewSealer(testKey(t), DefaultPadding())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 32, 92, 148, 600, 1200, 1400, 2000} {
		p := bytes.Repeat([]byte{0xab}, n)
		w, err := s.Wrap(nil, p)
		if err != nil {
			t.Fatal(err)
		}
		if w[0]&0xc0 != 0x40 {
			t.Fatalf("first byte %#x is not a QUIC short header", w[0])
		}
		if LooksLikeWireGuard(w) {
			t.Fatal("disguised datagram looks like WireGuard")
		}
		got, err := s.Unwrap(w)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("n=%d: unwrap = %v, %v", n, len(got), err)
		}
	}
}

func TestPaddingHidesHandshakeSizes(t *testing.T) {
	s, _ := NewSealer(testKey(t), DefaultPadding())
	sizes := map[int]int{148: 256, 92: 256, 64: 256, 300: 512, 1000: 1280, 1300: 1452, 1500: 1500 + Overhead}
	for in, want := range sizes {
		w, err := s.Wrap(nil, make([]byte, in))
		if err != nil {
			t.Fatal(err)
		}
		if len(w) != want {
			t.Errorf("%d bytes -> %d on the wire, want %d", in, len(w), want)
		}
	}
	none, _ := NewSealer(testKey(t), Padding{})
	w, _ := none.Wrap(nil, make([]byte, 148))
	if len(w) != 148+Overhead {
		t.Errorf("no padding: %d", len(w))
	}
}

func TestPaddingValidate(t *testing.T) {
	bad := []Padding{{Buckets: []int{10}}, {Buckets: []int{512, 256}}, {Buckets: []int{256, 256}}, {Buckets: []int{2000}}}
	for _, p := range bad {
		if err := p.Validate(); !errors.Is(err, ErrPadding) {
			t.Errorf("%v: %v", p, err)
		}
	}
	if err := DefaultPadding().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUnwrapRejects(t *testing.T) {
	s, _ := NewSealer(testKey(t), Padding{})
	w, _ := s.Wrap(nil, wgInit())
	w[len(w)-1] ^= 1
	if _, err := s.Unwrap(w); !errors.Is(err, ErrNotObfuscated) {
		t.Fatal("tampered datagram accepted")
	}
	other, _ := DeriveKey("other-net")
	o, _ := NewSealer(other, Padding{})
	w2, _ := s.Wrap(nil, wgInit())
	if _, err := o.Unwrap(w2); err == nil {
		t.Fatal("other network's key opened the datagram")
	}
	if _, err := s.Unwrap(wgInit()); err == nil {
		t.Fatal("plain WireGuard unwrapped")
	}
	if _, err := DeriveKey(""); err == nil {
		t.Fatal("empty network id accepted")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"off": ModeOff, "auto": ModeAuto, "on": ModeOn, "açık": ModeOn} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseMode("x"); err == nil {
		t.Fatal("bad mode accepted")
	}
}

// memEP and memBind connect two Binds in memory.
type memEP string

func (e memEP) ClearSrc()           {}
func (e memEP) SrcToString() string { return "" }
func (e memEP) DstToString() string { return string(e) }
func (e memEP) DstToBytes() []byte  { return []byte(e) }
func (e memEP) DstIP() netip.Addr   { return netip.Addr{} }
func (e memEP) SrcIP() netip.Addr   { return netip.Addr{} }

type memBind struct {
	name string
	in   chan []byte
	peer *memBind
	mu   sync.Mutex
	sent [][]byte
}

func (b *memBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{func(p [][]byte, s []int, eps []conn.Endpoint) (int, error) {
		d, ok := <-b.in
		if !ok {
			return 0, net.ErrClosed
		}
		s[0] = copy(p[0], d)
		eps[0] = memEP(b.peer.name)
		return 1, nil
	}}, 1, nil
}
func (b *memBind) Close() error                                  { return nil }
func (b *memBind) SetMark(uint32) error                          { return nil }
func (b *memBind) ParseEndpoint(s string) (conn.Endpoint, error) { return memEP(s), nil }
func (b *memBind) BatchSize() int                                { return 1 }
func (b *memBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, x := range bufs {
		c := append([]byte(nil), x...)
		b.mu.Lock()
		b.sent = append(b.sent, c)
		b.mu.Unlock()
		b.peer.in <- c
	}
	return nil
}

func pair() (*memBind, *memBind) {
	a := &memBind{name: "a", in: make(chan []byte, 16)}
	b := &memBind{name: "b", in: make(chan []byte, 16)}
	a.peer, b.peer = b, a
	return a, b
}

func recv(t *testing.T, fn conn.ReceiveFunc) []byte {
	t.Helper()
	p := [][]byte{make([]byte, 2048)}
	s := []int{0}
	eps := []conn.Endpoint{nil}
	n, err := fn(p, s, eps)
	if err != nil || n != 1 {
		t.Fatalf("receive: %d %v", n, err)
	}
	return p[0][:s[0]]
}

func TestBindOnAndAuto(t *testing.T) {
	a, b := pair()
	k := testKey(t)
	on, err := NewBind(a, Options{Mode: ModeOn, Key: k, Padding: DefaultPadding()})
	if err != nil {
		t.Fatal(err)
	}
	auto, err := NewBind(b, Options{Mode: ModeAuto, Key: k})
	if err != nil {
		t.Fatal(err)
	}
	fa, _, _ := on.Open(0)
	fb, _, _ := auto.Open(0)

	// Auto sends plain until it has heard a disguised datagram.
	if err := auto.Send([][]byte{wgInit()}, memEP("a")); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, fa[0]); !bytes.Equal(got, wgInit()) {
		t.Fatal("plain datagram changed")
	}
	if !LooksLikeWireGuard(b.sent[0]) {
		t.Fatal("auto disguised before hearing a disguised datagram")
	}
	// On disguises; auto unwraps and from then on answers disguised.
	if err := on.Send([][]byte{wgInit()}, memEP("b")); err != nil {
		t.Fatal(err)
	}
	if LooksLikeWireGuard(a.sent[0]) || len(a.sent[0]) != 256 {
		t.Fatalf("on sent %d bytes, plain=%v", len(a.sent[0]), LooksLikeWireGuard(a.sent[0]))
	}
	if got := recv(t, fb[0]); !bytes.Equal(got, wgInit()) {
		t.Fatal("auto did not unwrap")
	}
	if err := auto.Send([][]byte{wgInit()}, memEP("a")); err != nil {
		t.Fatal(err)
	}
	if LooksLikeWireGuard(b.sent[1]) {
		t.Fatal("auto answered plain after a disguised datagram")
	}
	if got := recv(t, fa[0]); !bytes.Equal(got, wgInit()) {
		t.Fatal("on did not unwrap the answer")
	}
	if st := auto.Stats(); st.Unwrapped != 1 || st.Wrapped != 1 {
		t.Fatalf("stats %+v", st)
	}
	if _, err := NewBind(a, Options{Mode: ModeOff, Key: k}); err == nil {
		t.Fatal("off mode accepted")
	}
}

func TestBindDropsForgedDisguise(t *testing.T) {
	a, b := pair()
	on, _ := NewBind(b, Options{Mode: ModeOn, Key: testKey(t)})
	fns, _, _ := on.Open(0)
	junk := bytes.Repeat([]byte{0x55}, 100) // 0x55 has the fixed bit
	a.in <- nil
	b.in <- junk
	b.in <- wgInit()
	if got := recv(t, fns[0]); !bytes.Equal(got, wgInit()) {
		t.Fatal("forged disguised datagram not dropped")
	}
}

func TestJitterOnlyBulk(t *testing.T) {
	a, _ := pair()
	go func() {
		for range a.peer.in {
		}
	}()
	var slept []time.Duration
	var mu sync.Mutex
	bnd, err := NewBind(a, Options{Mode: ModeOn, Key: testKey(t), Jitter: Jitter{Max: 20 * time.Millisecond},
		Rand: func() float64 { return 0.5 }, Sleep: func(d time.Duration) { mu.Lock(); slept = append(slept, d); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	_ = bnd.Send([][]byte{make([]byte, 100)}, memEP("b"))
	_ = bnd.Send([][]byte{make([]byte, 1200)}, memEP("b"))
	mu.Lock()
	defer mu.Unlock()
	if len(slept) != 1 || slept[0] != 10*time.Millisecond {
		t.Fatalf("slept %v, want one 10ms delay for the bulk datagram", slept)
	}
	if err := (Jitter{Max: time.Second}).Validate(); err == nil {
		t.Fatal("1s jitter accepted")
	}
	if err := (Jitter{BulkSize: 10}).Validate(); err == nil {
		t.Fatal("tiny bulk size accepted")
	}
}

func TestPins(t *testing.T) {
	c, pin, err := GenerateCertificate([]string{"cdn.example.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePin(pin.String())
	if err != nil || p != pin {
		t.Fatalf("round trip: %v", err)
	}
	if SPKIPin(c.Leaf) != pin {
		t.Fatal("pin mismatch")
	}
	for _, bad := range []string{"", "sha256/xx", "abcd", strings.Repeat("z", 64)} {
		if _, err := ParsePin(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParsePins(make([]string, MaxPins+1)); err == nil {
		t.Fatal("too many pins accepted")
	}
}

func loopListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

const magic = "OSWGTCP1"

// serveOnce accepts one connection: TLS, demux, echo of the next 4 bytes.
func serveOnce(ln net.Listener, cfg *tls.Config, res chan<- bool) {
	c, err := ln.Accept()
	if err != nil {
		res <- false
		return
	}
	tc, err := Handshake(c, cfg, 5*time.Second)
	if err != nil {
		res <- false
		return
	}
	s, ok := Demux(tc, magic, 5*time.Second)
	if !ok {
		res <- false
		return
	}
	buf := make([]byte, len(magic)+4)
	if _, err := io.ReadFull(s, buf); err != nil || string(buf[:len(magic)]) != magic {
		res <- false
		return
	}
	_, _ = s.Write(buf[len(magic):])
	_ = s.Close()
	res <- true
}

func TestTLSCamouflage(t *testing.T) {
	cert, pin, err := GenerateCertificate([]string{"cdn.example.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln := loopListener(t)
	res := make(chan bool, 1)
	go serveOnce(ln, ServerConfig(cert), res)
	cfg, err := ClientTLS{ServerName: "cdn.example.test", Pins: []string{pin.String()}}.Config(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialTLS(raw, cfg, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st := c.(*tls.Conn).ConnectionState(); st.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN %q", st.NegotiatedProtocol)
	}
	_, _ = io.WriteString(c, magic+"ping")
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q %v", got, err)
	}
	_ = c.Close()
	if !<-res {
		t.Fatal("server side failed")
	}
}

func TestTLSWrongPinAndProbe(t *testing.T) {
	cert, _, _ := GenerateCertificate([]string{"cdn.example.test"}, time.Now())
	_, other, _ := GenerateCertificate([]string{"cdn.example.test"}, time.Now())
	ln := loopListener(t)
	res := make(chan bool, 2)
	go serveOnce(ln, ServerConfig(cert), res)
	cfg, _ := ClientTLS{ServerName: "cdn.example.test", Pins: []string{other.String()}}.Config(nil)
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DialTLS(raw, cfg, 5*time.Second); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("wrong pin: %v", err)
	}
	<-res

	// A prober that speaks HTTP gets a 404, not a VPN preamble.
	go serveOnce(ln, ServerConfig(cert), res)
	raw, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialTLS(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "cdn.example.test"}, 5*time.Second) //nolint:gosec // test prober
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	body, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(body), "HTTP/1.1 404") {
		t.Fatalf("prober got %q", body)
	}
	if <-res {
		t.Fatal("prober accepted")
	}
	if _, err := (ClientTLS{}).Config(nil); err == nil {
		t.Fatal("empty SNI accepted")
	}
}

func TestLoadOrCreateCertificate(t *testing.T) {
	dir := t.TempDir()
	_, pin1, err := LoadOrCreateCertificate(dir, []string{"a.example.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, pin2, err := LoadOrCreateCertificate(dir, []string{"a.example.test"}, time.Now())
	if err != nil || pin1 != pin2 {
		t.Fatalf("reload changed pin: %v", err)
	}
}
