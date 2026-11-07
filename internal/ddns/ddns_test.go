package ddns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKey(t *testing.T, secret string) Key {
	t.Helper()
	k, err := ParseKey("ev-anahtari", "hmac-sha256", base64.StdEncoding.EncodeToString([]byte(secret)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fakeServer is an authoritative server stand-in on 127.0.0.1.
type fakeServer struct {
	key      Key
	mu       sync.Mutex
	records  map[string][]netip.Addr // "name type" -> addrs
	mode     string                  // "", "unsigned", "forged", "truncate", "refuse"
	requests int
}

func (s *fakeServer) handle(t *testing.T, req []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	h, err := parseHeader(req)
	if err != nil {
		return nil
	}
	reply := func(rcode int, prior []byte, key *Key, tsigErr uint16) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[0:], h.id)
		flags := uint16(0x8000 | opUpdate<<11 | rcode)
		if s.mode == "truncate" {
			flags |= 0x0200
		}
		binary.BigEndian.PutUint16(b[2:], flags)
		if key == nil {
			return b
		}
		if tsigErr != 0 {
			v := tsigVars{time: uint64(time.Now().Unix()), fudge: DefaultFudge, err: tsigErr, origID: h.id}
			out := append(b, key.tsigRR(v)...)
			binary.BigEndian.PutUint16(out[10:], 1)
			return out
		}
		out, _ := key.sign(b, prior, tsigVars{time: uint64(time.Now().Unix()), fudge: DefaultFudge})
		return out
	}
	v, err := s.key.verify(req, nil, uint64(time.Now().Unix()))
	if err != nil {
		return reply(rcodeNotAuth, nil, &s.key, tsigBadSig)
	}
	if s.mode == "refuse" {
		return reply(rcodeRefused, v.mac, &s.key, 0)
	}
	_, rrs, err := records(req, h)
	if err != nil {
		t.Errorf("parse: %v", err)
		return reply(rcodeFormErr, v.mac, &s.key, 0)
	}
	for _, r := range rrs {
		name, _, err := readName(req, r.name)
		if err != nil || r.typ == typeTSIG {
			continue
		}
		key := name + " " + map[uint16]string{typeA: "A", typeAAAA: "AAAA"}[r.typ]
		switch r.class {
		case classANY:
			delete(s.records, key)
		case classIN:
			a, _ := netip.AddrFromSlice(r.rdata)
			s.records[key] = append(s.records[key], a)
		}
	}
	switch s.mode {
	case "unsigned":
		return reply(rcodeNoError, nil, nil, 0)
	case "forged":
		other := testKey(t, "başka bir gizli değer 123456")
		return reply(rcodeNoError, v.mac, &other, 0)
	}
	return reply(rcodeNoError, v.mac, &s.key, 0)
}

func startFake(t *testing.T, s *fakeServer) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, maxMessage)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := s.handle(t, append([]byte{}, buf[:n]...)); out != nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey("a", "hmac-md5", base64.StdEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("md5 accepted")
	}
	if _, err := ParseKey("a", "", "kısa"); err == nil {
		t.Fatal("bad secret accepted")
	}
	k, err := ParseKey("Ev.Anahtar", "", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil || k.Name != "ev.anahtar." || k.Algorithm != HMACSHA256 {
		t.Fatalf("%+v %v", k, err)
	}
}

func TestUpdateValidate(t *testing.T) {
	good := Update{Zone: "ornek.test", Name: "ev.ornek.test", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, u := range []Update{
		{Zone: "ornek.test", Name: "ev.baska.test", Addrs: good.Addrs},
		{Zone: "ornek.test", Name: "e v.ornek.test", Addrs: good.Addrs},
		{Zone: "ornek.test", Name: "ev.ornek.test"},
		{Zone: "ornek.test", Name: "ev.ornek.test", Addrs: good.Addrs, TTL: 5},
		{Zone: "ornek.test", Name: "-ev.ornek.test", Addrs: good.Addrs},
		{Zone: "ornek.test", Name: strings.Repeat("a", 64) + ".ornek.test", Addrs: good.Addrs},
	} {
		if u.Validate() == nil {
			t.Errorf("accepted %+v", u)
		}
	}
}

func TestSendUpdate(t *testing.T) {
	key := testKey(t, "ev sunucusu gizli değeri 2026")
	srv := &fakeServer{key: key, records: map[string][]netip.Addr{
		"ev.ornek.test. A": {netip.MustParseAddr("198.51.100.1")},
	}}
	addr := startFake(t, srv)
	c := &Client{Server: addr, Key: key, Timeout: 5 * time.Second}
	u := Update{Zone: "ornek.test.", Name: "ev.ornek.test", Addrs: []netip.Addr{
		netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("203.0.113.7")}}
	if err := c.Send(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	a, aaaa := srv.records["ev.ornek.test. A"], srv.records["ev.ornek.test. AAAA"]
	srv.mu.Unlock()
	if len(a) != 1 || a[0].String() != "203.0.113.7" || len(aaaa) != 1 || aaaa[0].String() != "2001:db8::7" {
		t.Fatalf("records A=%v AAAA=%v", a, aaaa)
	}

	// Wrong secret: the server answers BADSIG.
	bad := &Client{Server: addr, Key: testKey(t, "yanlış gizli değer 1234567"), Timeout: 5 * time.Second}
	if err := bad.Send(context.Background(), u); err == nil || !strings.Contains(err.Error(), "BADSIG") {
		t.Fatalf("wrong key: %v", err)
	}
	for mode, want := range map[string]error{"unsigned": ErrUnsigned, "forged": ErrBadResponse} {
		srv.mu.Lock()
		srv.mode = mode
		srv.mu.Unlock()
		if err := c.Send(context.Background(), u); !errors.Is(err, want) {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	srv.mu.Lock()
	srv.mode = "refuse"
	srv.mu.Unlock()
	if err := c.Send(context.Background(), u); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("refuse: %v", err)
	}
	// A wrong clock is refused.
	srv.mu.Lock()
	srv.mode = ""
	srv.mu.Unlock()
	skewed := &Client{Server: addr, Key: key, Timeout: 5 * time.Second, Now: func() time.Time { return time.Now().Add(-time.Hour) }}
	if err := skewed.Send(context.Background(), u); err == nil {
		t.Fatal("skewed clock accepted")
	}
}

func TestSendNoServer(t *testing.T) {
	key := testKey(t, "ev sunucusu gizli değeri 2026")
	// A closed port on loopback: the exchange times out or is refused.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = pc.Close()
	c := &Client{Server: addr, Key: key, Timeout: 500 * time.Millisecond}
	u := Update{Zone: "ornek.test", Name: "ev.ornek.test", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}
	if err := c.Send(context.Background(), u); err == nil {
		t.Fatal("no error without a server")
	}
	if err := (&Client{Key: key}).Send(context.Background(), u); err == nil {
		t.Fatal("no server address accepted")
	}
}

func TestCheck(t *testing.T) {
	lookup := func(addrs ...string) Lookup {
		return func(context.Context, string) ([]netip.Addr, error) {
			if len(addrs) == 0 {
				return nil, errors.New("yok")
			}
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
	}
	obs := netip.MustParseAddr("203.0.113.7")
	cases := []struct {
		host string
		l    Lookup
		obs  netip.Addr
		want Status
	}{
		{"ev.ornek.test", lookup("203.0.113.7"), obs, StatusOK},
		{"ev.ornek.test", lookup("198.51.100.1", "203.0.113.7"), obs, StatusOK},
		{"ev.ornek.test", lookup("198.51.100.1"), obs, StatusStale},
		{"ev.ornek.test", lookup(), obs, StatusUnresolved},
		{"203.0.113.7", lookup(), obs, StatusUnknown},
		{"ev.ornek.test", lookup("198.51.100.1"), netip.MustParseAddr("192.168.1.10"), StatusUnknown},
		{"ev.ornek.test", lookup("198.51.100.1"), netip.MustParseAddr("100.70.1.1"), StatusUnknown},
		{"ev.ornek.test", lookup("198.51.100.1"), netip.Addr{}, StatusUnknown},
	}
	for _, c := range cases {
		r := Check(context.Background(), c.l, c.host, c.obs)
		if r.Status != c.want || r.Message == "" {
			t.Errorf("%s %v: %+v", c.host, c.obs, r)
		}
	}
}
