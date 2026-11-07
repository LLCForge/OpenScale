package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsQuery(t *testing.T, id uint16, name string, typ dnsmessage.Type, ednsSize int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if ednsSize > 0 {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		var h dnsmessage.ResourceHeader
		if err := h.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// answerFor builds a response to query: count A records with ttl, or
// NXDOMAIN with an SOA when count is negative.
func answerFor(query []byte, count int, ttl uint32) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil || len(m.Questions) != 1 {
		return nil
	}
	q := m.Questions[0]
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: m.RecursionDesired, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q},
	}
	if count < 0 {
		resp.RCode = dnsmessage.RCodeNameError
		resp.Authorities = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 900},
			Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("root.example."),
				Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: 600},
		}}
	}
	for i := 0; i < count; i++ {
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i)}},
		})
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func unpack(t *testing.T, data []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(data); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return m
}

// udpUpstream is a fake resolver. Before the real answer it sends a
// response with a wrong ID and one with the right ID but another
// question; the forwarder must ignore both.
type udpUpstream struct {
	conn    *net.UDPConn
	queries atomic.Int32
	mu      sync.Mutex
	ids     map[uint16]bool
	ports   map[int]bool
	answer  func(query []byte) []byte
}

func newUDPUpstream(t *testing.T, answer func([]byte) []byte) *udpUpstream {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := &udpUpstream{conn: c, ids: map[uint16]bool{}, ports: map[int]bool{}, answer: answer}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			u.queries.Add(1)
			u.mu.Lock()
			u.ids[binary.BigEndian.Uint16(q)] = true
			u.ports[addr.Port] = true
			u.mu.Unlock()
			resp := u.answer(q)
			if resp == nil {
				continue
			}
			wrongID := append([]byte(nil), resp...)
			binary.BigEndian.PutUint16(wrongID, binary.BigEndian.Uint16(resp)+1)
			_, _ = c.WriteToUDP(wrongID, addr)
			var m dnsmessage.Message
			if m.Unpack(q) == nil {
				m.Questions[0].Name = dnsmessage.MustNewName("baska.example.")
				if other := answerFor(mustPack(m), 1, 30); other != nil {
					_, _ = c.WriteToUDP(other, addr)
				}
			}
			_, _ = c.WriteToUDP(resp, addr)
		}
	}()
	return u
}

func mustPack(m dnsmessage.Message) []byte {
	out, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return out
}

func (u *udpUpstream) addr() string { return u.conn.LocalAddr().String() }

func testForwarder(t *testing.T, spec string) *dnsForwarder {
	t.Helper()
	up, err := parseDNSUpstream(spec)
	if err != nil {
		t.Fatal(err)
	}
	return newDNSForwarder(up, nil)
}

func TestParseDNSUpstream(t *testing.T) {
	good := map[string]upstreamKind{
		"":                                    upstreamUDP,
		"9.9.9.9":                             upstreamUDP,
		"127.0.0.1:5353":                      upstreamUDP,
		"[2620:fe::fe]:53":                    upstreamUDP,
		"2620:fe::fe":                         upstreamUDP,
		"tls://dns.quad9.net":                 upstreamDoT,
		"tls://9.9.9.9:853":                   upstreamDoT,
		"https://dns.quad9.net/dns-query":     upstreamDoH,
		"https://[2620:fe::fe]:443/dns-query": upstreamDoH,
	}
	for s, kind := range good {
		up, err := parseDNSUpstream(s)
		if err != nil || up.kind != kind {
			t.Errorf("%q: %v %v", s, up.kind, err)
		}
	}
	if up, _ := parseDNSUpstream("tls://dns.quad9.net"); up.addr != "dns.quad9.net:853" || up.serverName != "dns.quad9.net" {
		t.Errorf("DoT default port: %+v", up)
	}
	if up, _ := parseDNSUpstream("9.9.9.9"); up.addr != "9.9.9.9:53" {
		t.Errorf("plain default port: %+v", up)
	}
	for _, s := range []string{
		"http://dns.example/dns-query", "udp://9.9.9.9", "https:///dns-query", "tls://", "https://user:pw@dns.example/q",
		"tls://dns.example/path", "tls://dns.example:99999", "dns.example", "9.9.9.9:0", "https://dns.example/q#x", "fe80::1%eth0",
	} {
		if err := ValidateExitDNSUpstream(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestForwarderRandomIDAndMatching(t *testing.T) {
	up := newUDPUpstream(t, func(q []byte) []byte { return answerFor(q, 1, 0) }) // TTL 0: never cached
	f := testForwarder(t, up.addr())
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		resp, err := f.forward(ctx, dnsQuery(t, 4242, "a.example.", dnsmessage.TypeA, 0))
		if err != nil {
			t.Fatal(err)
		}
		m := unpack(t, resp)
		if m.ID != 4242 || len(m.Answers) != 1 || m.Questions[0].Name.String() != "a.example." {
			t.Fatalf("answer %+v", m)
		}
	}
	up.mu.Lock()
	ids, ports := len(up.ids), len(up.ports)
	up.mu.Unlock()
	if ids < 2 || ports < 2 {
		t.Fatalf("upstream saw %d IDs and %d source ports for 8 queries", ids, ports)
	}
	if f.cache.len() != 0 {
		t.Fatal("TTL 0 answer cached")
	}
}

func TestForwarderRejectsBadQueries(t *testing.T) {
	f := testForwarder(t, "127.0.0.1:1")
	ctx := context.Background()
	if _, err := f.forward(ctx, []byte("soru")); err == nil {
		t.Fatal("garbage forwarded")
	}
	resp := answerFor(dnsQuery(t, 1, "a.example.", dnsmessage.TypeA, 0), 1, 30)
	if _, err := f.forward(ctx, resp); err == nil {
		t.Fatal("response packet forwarded")
	}
}

func TestForwarderCache(t *testing.T) {
	up := newUDPUpstream(t, func(q []byte) []byte {
		var m dnsmessage.Message
		if m.Unpack(q) == nil && m.Questions[0].Name.String() == "yok.example." {
			return answerFor(q, -1, 0)
		}
		return answerFor(q, 2, 300)
	})
	f := testForwarder(t, up.addr())
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := f.forward(ctx, dnsQuery(t, 1, "a.example.", dnsmessage.TypeA, 0)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(100 * time.Second)
	resp, err := f.forward(ctx, dnsQuery(t, 77, "A.Example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if up.queries.Load() != 1 {
		t.Fatalf("cached question sent upstream again (%d queries)", up.queries.Load())
	}
	m := unpack(t, resp)
	if m.ID != 77 || len(m.Answers) != 2 || m.Answers[0].Header.TTL != 200 || m.Answers[1].Header.TTL != 200 {
		t.Fatalf("cached answer %+v", m)
	}
	// Another type or EDNS is another question.
	if _, err := f.forward(ctx, dnsQuery(t, 2, "a.example.", dnsmessage.TypeAAAA, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.forward(ctx, dnsQuery(t, 3, "a.example.", dnsmessage.TypeA, 1232)); err != nil {
		t.Fatal(err)
	}
	if up.queries.Load() != 3 {
		t.Fatalf("queries %d, want 3", up.queries.Load())
	}
	now = now.Add(201 * time.Second)
	if _, err := f.forward(ctx, dnsQuery(t, 4, "a.example.", dnsmessage.TypeA, 0)); err != nil {
		t.Fatal(err)
	}
	if up.queries.Load() != 4 {
		t.Fatal("expired answer served from the cache")
	}

	// NXDOMAIN with SOA minimum 600 s is kept for 60 s only.
	before := up.queries.Load()
	for i := 0; i < 2; i++ {
		resp, err := f.forward(ctx, dnsQuery(t, 9, "yok.example.", dnsmessage.TypeA, 0))
		if err != nil {
			t.Fatal(err)
		}
		if m := unpack(t, resp); m.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("rcode %v", m.RCode)
		}
	}
	if up.queries.Load() != before+1 {
		t.Fatal("negative answer not cached")
	}
	now = now.Add(61 * time.Second)
	if _, err := f.forward(ctx, dnsQuery(t, 9, "yok.example.", dnsmessage.TypeA, 0)); err != nil {
		t.Fatal(err)
	}
	if up.queries.Load() != before+2 {
		t.Fatal("negative answer cached for more than 60 s")
	}
}

func TestDNSCacheLRUAndTTLCap(t *testing.T) {
	c := newDNSCache(2)
	now := time.Unix(1_800_000_000, 0)
	msg := func(name string, ttl uint32) dnsmessage.Message {
		var m dnsmessage.Message
		_ = m.Unpack(answerFor(dnsQueryRaw(name), 1, ttl))
		return m
	}
	key := func(name string) cacheKey {
		return cacheKey{name: name, qtype: dnsmessage.TypeA, class: dnsmessage.ClassINET}
	}
	c.put(key("a."), msg("a.", 30), 100, now)
	c.put(key("b."), msg("b.", 30), 100, now)
	if _, ok := c.get(key("a."), now); !ok {
		t.Fatal("a missing")
	}
	c.put(key("c."), msg("c.", 30), 100, now) // evicts b, the least recently used
	if _, ok := c.get(key("b."), now); ok {
		t.Fatal("LRU entry not evicted")
	}
	if _, ok := c.get(key("a."), now); !ok || c.len() != 2 {
		t.Fatal("recently used entry evicted")
	}
	c.put(key("d."), msg("d.", 86400), 100, now)
	if _, ok := c.get(key("d."), now.Add(time.Hour)); ok {
		t.Fatal("TTL not capped at one hour")
	}
	c.put(key("e."), msg("e.", 30), maxCachedMessage+1, now)
	if _, ok := c.get(key("e."), now); ok {
		t.Fatal("oversized answer cached")
	}

	// Concurrent use is safe.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := key(strconv.Itoa((i + j) % 5))
				c.put(k, msg("x.", 30), 100, now)
				if m, ok := c.get(k, now.Add(time.Second)); ok && m.Answers[0].Header.TTL != 29 {
					t.Errorf("TTL %d", m.Answers[0].Header.TTL)
				}
			}
		}(i)
	}
	wg.Wait()
}

func dnsQueryRaw(name string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, _ := b.Finish()
	return out
}

// serveStreamDNS answers length-prefixed DNS queries on l.
func serveStreamDNS(l net.Listener, answer func([]byte) []byte, count *atomic.Int32) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			var lb [2]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			count.Add(1)
			resp := answer(q)
			out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
			_, _ = c.Write(append(out, resp...))
		}()
	}
}

func TestForwarderTruncatedRetriesOverTCP(t *testing.T) {
	// UDP and TCP on the same port, like a real resolver.
	var up *udpUpstream
	var l net.Listener
	for i := 0; i < 20 && l == nil; i++ {
		up = newUDPUpstream(t, func(q []byte) []byte {
			m := unpack(t, answerFor(q, 0, 0))
			m.Truncated = true
			return mustPack(m)
		})
		var err error
		l, err = net.Listen("tcp4", up.addr())
		if err != nil {
			l = nil
		}
	}
	if l == nil {
		t.Skip("no free port for both UDP and TCP")
	}
	defer l.Close()
	var tcpQueries atomic.Int32
	go serveStreamDNS(l, func(q []byte) []byte { return answerFor(q, 60, 300) }, &tcpQueries)

	f := testForwarder(t, up.addr())
	resp, err := f.forward(context.Background(), dnsQuery(t, 5, "buyuk.example.", dnsmessage.TypeA, 4096))
	if err != nil {
		t.Fatal(err)
	}
	m := unpack(t, resp)
	if tcpQueries.Load() != 1 || m.ID != 5 || len(m.Answers) != 60 || m.Truncated {
		t.Fatalf("TCP retry: %d queries, answer %d records, TC %v", tcpQueries.Load(), len(m.Answers), m.Truncated)
	}
	// A member without EDNS gets the large answer truncated: 512 bytes.
	resp, err = f.forward(context.Background(), dnsQuery(t, 6, "buyuk.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpack(t, resp); !m.Truncated || len(resp) > 512 || m.ID != 6 {
		t.Fatalf("answer for a non-EDNS member: %d bytes, TC %v", len(resp), m.Truncated)
	}
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.test"},
		DNSNames:     []string{"dns.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func poolConfig(pool *x509.CertPool) func(string) *tls.Config {
	return func(serverName string) *tls.Config {
		return &tls.Config{ServerName: serverName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
}

func TestForwarderDoT(t *testing.T) {
	cert, pool := testCert(t)
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var n atomic.Int32
	go serveStreamDNS(l, func(q []byte) []byte { return answerFor(q, 1, 30) }, &n)

	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	up, err := parseDNSUpstream("tls://127.0.0.1:" + port)
	if err != nil {
		t.Fatal(err)
	}
	f := newDNSForwarder(up, poolConfig(pool))
	resp, err := f.forward(context.Background(), dnsQuery(t, 11, "a.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpack(t, resp); m.ID != 11 || len(m.Answers) != 1 {
		t.Fatalf("DoT answer %+v", m)
	}
	// An untrusted certificate is refused.
	f = newDNSForwarder(up, nil)
	if _, err := f.forward(context.Background(), dnsQuery(t, 12, "b.example.", dnsmessage.TypeA, 0)); err == nil {
		t.Fatal("DoT server with an untrusted certificate accepted")
	}
}

func TestForwarderDoH(t *testing.T) {
	var bad atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != dnsMediaType || r.URL.Path != "/dns-query" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q, err := io.ReadAll(io.LimitReader(r.Body, maxDNSMessage))
		if err != nil || binary.BigEndian.Uint16(q) != 0 {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if bad.Load() {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>"))
			return
		}
		w.Header().Set("Content-Type", dnsMediaType)
		_, _ = w.Write(answerFor(q, 1, 30))
	}))
	cert, pool := testCert(t)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	up, err := parseDNSUpstream(srv.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	f := newDNSForwarder(up, poolConfig(pool))
	resp, err := f.forward(context.Background(), dnsQuery(t, 21, "a.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpack(t, resp); m.ID != 21 || len(m.Answers) != 1 {
		t.Fatalf("DoH answer %+v", m)
	}
	bad.Store(true)
	if _, err := f.forward(context.Background(), dnsQuery(t, 22, "b.example.", dnsmessage.TypeA, 0)); err == nil {
		t.Fatal("non-DNS DoH response accepted")
	}
	f = newDNSForwarder(up, nil)
	if _, err := f.forward(context.Background(), dnsQuery(t, 23, "c.example.", dnsmessage.TypeA, 0)); err == nil {
		t.Fatal("DoH server with an untrusted certificate accepted")
	}
}

func TestForwarderTimeout(t *testing.T) {
	up := newUDPUpstream(t, func([]byte) []byte { return nil }) // never answers
	f := testForwarder(t, up.addr())
	f.timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := f.forward(context.Background(), dnsQuery(t, 1, "a.example.", dnsmessage.TypeA, 0))
	var ne net.Error
	if err == nil || !(errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}
	if _, err := exitForwarder("http://x"); err == nil {
		t.Fatal("invalid upstream accepted")
	}
	a, _ := exitForwarder("127.0.0.1:5300")
	b, _ := exitForwarder("127.0.0.1:5300")
	if a == nil || a != b {
		t.Fatal("forwarder not shared per upstream")
	}
}
