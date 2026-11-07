package node

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/trust"
)

func netDNSDoc() *trust.Document {
	return &trust.Document{
		DNSDomain:  "openscale.internal",
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd00::/48"),
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.2"), IPv6: netip.MustParseAddr("fd00::2")},
			{Name: "pihole", IPv4: netip.MustParseAddr("100.80.0.5"), IPv6: netip.MustParseAddr("fd00::5")},
			{Name: "vps", IPv4: netip.MustParseAddr("100.80.0.6"), IPv6: netip.MustParseAddr("fd00::6")},
		},
		DNS: &trust.DNSSettings{
			Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.6")},
			Split: []trust.SplitDNS{
				{Domain: "lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")}},
				{Domain: "ofis.lan", Nameservers: []netip.Addr{netip.MustParseAddr("fd00::6")}},
			},
		},
	}
}

func TestNetworkRoute(t *testing.T) {
	doc := netDNSDoc()
	e := &Engine{}
	route := func(name string) string {
		r := e.networkRoute(doc, dnsQuery(t, 1, name, dnsmessage.TypeA, 0))
		if len(r) == 0 {
			return ""
		}
		return r[0].String()
	}
	cases := map[string]string{
		"nas.lan.":        "100.80.0.5",
		"lan.":            "100.80.0.5",
		"x.ofis.lan.":     "fd00::6", // the longest split domain wins
		"example.com.":    "100.80.0.6",
		"notlan.example.": "100.80.0.6",
	}
	for name, want := range cases {
		if got := route(name); got != want {
			t.Errorf("%s -> %q, want %q", name, got, want)
		}
	}
	// With an exit node in use the rest goes to the exit node, split
	// domains still to their resolvers.
	e.exitActive = "vps"
	if got := route("example.com."); got != "100.80.0.6" {
		t.Errorf("exit route %q", got)
	}
	e.exitActive = "laptop"
	if got := route("example.com."); got != "100.80.0.2" {
		t.Errorf("exit route %q", got)
	}
	if got := route("nas.lan."); got != "100.80.0.5" {
		t.Errorf("split with exit %q", got)
	}
	// F-065: the device's own choice turns the network's settings off,
	// the exit node stays.
	e.SetNetworkDNSRejected(true)
	if got := route("nas.lan."); got != "100.80.0.2" {
		t.Errorf("rejected split went to %q", got)
	}
	e.exitActive = ""
	if got := route("example.com."); got != "" {
		t.Errorf("rejected network DNS went to %q", got)
	}
	// A resolver outside the network is never used, even from a wrong
	// document.
	e.SetNetworkDNSRejected(false)
	doc.DNS.Nameservers = []netip.Addr{netip.MustParseAddr("9.9.9.9"), doc.DNSResolverIPv4()}
	if got := route("example.com."); got != "" {
		t.Errorf("outside resolver used: %q", got)
	}
}

func TestForwardPlain(t *testing.T) {
	up := newUDPUpstream(t, func(q []byte) []byte { return answerFor(q, 1, 30) })
	ap := netip.MustParseAddrPort(up.addr())
	prev := netDNSServerPort
	netDNSServerPort = ap.Port()
	t.Cleanup(func() { netDNSServerPort = prev })

	q := dnsQuery(t, 777, "nas.lan.", dnsmessage.TypeA, 0)
	out, err := forwardPlain(context.Background(), []netip.Addr{ap.Addr()}, q, false)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil || m.ID != 777 || len(m.Answers) != 1 {
		t.Fatalf("answer %+v %v", m, err)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.ids[777] {
		t.Fatal("the client's ID was sent upstream")
	}
	if _, err := forwardPlain(context.Background(), nil, q, false); err == nil {
		t.Fatal("no resolvers accepted")
	}
}

func TestFailureAnswer(t *testing.T) {
	var m dnsmessage.Message
	if err := m.Unpack(failureAnswer(dnsQuery(t, 9, "x.lan.", dnsmessage.TypeA, 0))); err != nil {
		t.Fatal(err)
	}
	if m.ID != 9 || m.RCode != dnsmessage.RCodeServerFailure || len(m.Questions) != 1 {
		t.Fatalf("%+v", m)
	}
	if failureAnswer([]byte{1}) != nil {
		t.Fatal("garbage answered")
	}
}

// tcpClient drives the TCP endpoint like an OS stack would.
type tcpClient struct {
	t      *testing.T
	ep     *tcpDNS
	answer tcpAnswerFunc
	client netip.AddrPort
	server netip.AddrPort
	seq    uint32
	got    []tcpSeg
	now    time.Time
}

func (c *tcpClient) send(flags uint8, ack uint32, payload []byte) {
	c.t.Helper()
	pkt := buildTCP4(c.client, c.server, c.seq, ack, flags, 1460, payload)
	s, ok := parseTCP4(pkt)
	if !ok {
		c.t.Fatal("own segment does not parse")
	}
	c.ep.handle(s, c.now, c.answer, func(p []byte) {
		if onesSum(p[:20], 0) != 0xffff {
			c.t.Fatal("bad IPv4 checksum")
		}
		r, ok := parseTCP4(p)
		if !ok {
			c.t.Fatal("reply does not parse")
		}
		var pseudo [12]byte
		s4, d4 := r.src.Addr().As4(), r.dst.Addr().As4()
		copy(pseudo[0:4], s4[:])
		copy(pseudo[4:8], d4[:])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(p)-20))
		if onesSum(p[20:], uint32(onesSum(pseudo[:], 0))) != 0xffff {
			c.t.Fatal("bad TCP checksum")
		}
		c.got = append(c.got, r)
	})
	c.seq += uint32(len(payload))
	if flags&(tcpFlagSyn|tcpFlagFin) != 0 {
		c.seq++
	}
}

func (c *tcpClient) take() []tcpSeg {
	out := c.got
	c.got = nil
	return out
}

func TestTCPDNSAnswersOneQuery(t *testing.T) {
	doc := netDNSDoc()
	c := &tcpClient{
		t: t, ep: &tcpDNS{}, now: time.Unix(1000, 0), seq: 5000,
		client: netip.MustParseAddrPort("100.80.0.2:40000"),
		server: netip.AddrPortFrom(doc.DNSResolverIPv4(), 53),
		answer: func(q []byte, reply func([]byte)) { reply(magicdns.AnswerStream(doc, q)) },
	}
	c.send(tcpFlagSyn, 0, nil)
	segs := c.take()
	if len(segs) != 1 || segs[0].flags != tcpFlagSyn|tcpFlagAck || segs[0].ack != 5001 || segs[0].mss != tcpDNSMSS {
		t.Fatalf("SYN-ACK %+v", segs)
	}
	srvNext := segs[0].seq + 1
	c.send(tcpFlagAck, srvNext, nil)
	if len(c.take()) != 0 {
		t.Fatal("pure ACK answered")
	}
	q := dnsQuery(t, 31, "laptop.openscale.internal.", dnsmessage.TypeA, 0)
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	// The length prefix and the query in two segments.
	c.send(tcpFlagAck|tcpFlagPsh, srvNext, framed[:1])
	if segs := c.take(); len(segs) != 1 || segs[0].ack != c.seq || len(segs[0].payload) != 0 {
		t.Fatalf("ACK of partial query %+v", segs)
	}
	c.send(tcpFlagAck|tcpFlagPsh, srvNext, append(framed[1:], q...))
	segs = c.take()
	if len(segs) != 1 || segs[0].flags&tcpFlagFin == 0 || segs[0].seq != srvNext {
		t.Fatalf("answer segments %+v", segs)
	}
	resp := segs[0].payload
	if n := int(binary.BigEndian.Uint16(resp)); n != len(resp)-2 {
		t.Fatalf("length prefix %d of %d", n, len(resp))
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp[2:]); err != nil || m.ID != 31 || len(m.Answers) != 1 {
		t.Fatalf("answer %+v %v", m, err)
	}
	// The client retransmits its query: the answer is sent again.
	c.seq -= uint32(len(q) + 1)
	c.send(tcpFlagAck|tcpFlagPsh, srvNext, append(framed[1:], q...))
	if segs := c.take(); len(segs) != 1 || segs[0].seq != srvNext {
		t.Fatalf("retransmission %+v", segs)
	}
	ourFin := srvNext + uint32(len(resp)) + 1
	c.send(tcpFlagAck|tcpFlagFin, ourFin, nil)
	if segs := c.take(); len(segs) != 1 || segs[0].flags != tcpFlagAck || segs[0].ack != c.seq {
		t.Fatalf("ACK of FIN %+v", segs)
	}
	if len(c.ep.conns) != 0 {
		t.Fatal("connection left behind")
	}
	// Segments of an unknown connection are reset.
	c.send(tcpFlagAck, 1, []byte{0, 1})
	if segs := c.take(); len(segs) != 1 || segs[0].flags&tcpFlagRst == 0 {
		t.Fatalf("unknown connection %+v", segs)
	}
}

func TestTCPDNSLimits(t *testing.T) {
	ep := &tcpDNS{}
	now := time.Unix(1000, 0)
	server := netip.MustParseAddrPort("100.80.255.254:53")
	never := func([]byte, func([]byte)) { t.Fatal("garbage answered") }
	for i := 0; i < tcpDNSMaxConns; i++ {
		c := &tcpClient{t: t, ep: ep, now: now, answer: never, server: server, client: netip.MustParseAddrPort("100.80.0.2:" + strconv.Itoa(1000+i))}
		c.send(tcpFlagSyn, 0, nil)
	}
	c := &tcpClient{t: t, ep: ep, now: now, answer: never, server: server, client: netip.MustParseAddrPort("100.80.0.3:9")}
	c.send(tcpFlagSyn, 0, nil)
	if segs := c.take(); len(segs) != 1 || segs[0].flags&tcpFlagRst == 0 {
		t.Fatalf("connection over the limit %+v", segs)
	}
	// Idle connections expire and make room.
	c.now = now.Add(time.Minute)
	c.send(tcpFlagSyn, 0, nil)
	segs := c.take()
	if len(segs) != 1 || segs[0].flags != tcpFlagSyn|tcpFlagAck || len(ep.conns) != 1 {
		t.Fatalf("after expiry %+v, %d connections", segs, len(ep.conns))
	}
	// A bad length prefix resets.
	c.send(tcpFlagAck, segs[0].seq+1, []byte{0, 3})
	if segs := c.take(); len(segs) != 1 || segs[0].flags&tcpFlagRst == 0 {
		t.Fatalf("bad length %+v", segs)
	}
	if _, ok := parseTCP4([]byte{0x45, 0, 0, 20}); ok {
		t.Fatal("short packet parsed")
	}
}
