package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/packet"
)

// DNS over TCP without an OS socket (F-066, ADR-0034). The MagicDNS
// resolver address has no listener; the OS's TCP segments to port 53 are
// answered here by a minimal TCP endpoint that takes one length-prefixed
// query per connection, answers it and closes. On an exit node the same
// endpoint answers members' TCP queries to the exit node's address.

const (
	tcpDNSMaxConns = 128
	tcpDNSIdle     = 30 * time.Second
	// tcpDNSMaxQuery bounds the buffered query with its length prefix.
	tcpDNSMaxQuery = 2 + 4096
	tcpDNSWindow   = 65535
	// tcpDNSMSS is the segment size advertised and used at most; it fits
	// the tunnel MTU.
	tcpDNSMSS        = 1220
	tcpDNSDefaultMSS = 536
	ipv4HeaderLen    = 20
	tcpHeaderLen     = 20

	tcpFlagFin = packet.TCPFin
	tcpFlagSyn = packet.TCPSyn
	tcpFlagRst = packet.TCPRst
	tcpFlagPsh = 0x08
	tcpFlagAck = packet.TCPAck
)

// tcpSeg is a parsed IPv4 TCP segment.
type tcpSeg struct {
	src, dst netip.AddrPort
	seq, ack uint32
	flags    uint8
	mss      int
	payload  []byte
}

// parseTCP4 parses an unfragmented IPv4 TCP segment.
func parseTCP4(pkt []byte) (tcpSeg, bool) {
	if len(pkt) < ipv4HeaderLen || pkt[0]>>4 != 4 || pkt[9] != packet.ProtoTCP {
		return tcpSeg{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	frag := binary.BigEndian.Uint16(pkt[6:8])
	if ihl < ipv4HeaderLen || total < ihl+tcpHeaderLen || total > len(pkt) || frag&0x3fff != 0 {
		return tcpSeg{}, false
	}
	seg := pkt[ihl:total]
	off := int(seg[12]>>4) * 4
	if off < tcpHeaderLen || off > len(seg) {
		return tcpSeg{}, false
	}
	src, _ := netip.AddrFromSlice(pkt[12:16])
	dst, _ := netip.AddrFromSlice(pkt[16:20])
	s := tcpSeg{
		src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(seg[0:2])),
		dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(seg[2:4])),
		seq:     binary.BigEndian.Uint32(seg[4:8]),
		ack:     binary.BigEndian.Uint32(seg[8:12]),
		flags:   seg[13],
		mss:     tcpDNSDefaultMSS,
		payload: seg[off:],
	}
	// Options: only MSS matters.
	opts := seg[tcpHeaderLen:off]
	for len(opts) > 0 {
		switch kind := opts[0]; kind {
		case 0:
			opts = nil
		case 1:
			opts = opts[1:]
		default:
			if len(opts) < 2 || int(opts[1]) < 2 || int(opts[1]) > len(opts) {
				opts = nil
				continue
			}
			if kind == 2 && opts[1] == 4 {
				s.mss = int(binary.BigEndian.Uint16(opts[2:4]))
			}
			opts = opts[opts[1]:]
		}
	}
	return s, true
}

// buildTCP4 returns an IPv4 TCP segment with valid checksums; mss > 0
// adds the MSS option (SYN-ACK).
func buildTCP4(src, dst netip.AddrPort, seq, ack uint32, flags uint8, mss uint16, payload []byte) []byte {
	hl := tcpHeaderLen
	if mss > 0 {
		hl += 4
	}
	total := ipv4HeaderLen + hl + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total)) //nolint:gosec // segments are at most MSS bytes
	pkt[6] = 0x40
	pkt[8] = 64
	pkt[9] = packet.ProtoTCP
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ^onesSum(pkt[:ipv4HeaderLen], 0))

	seg := pkt[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(seg[0:2], src.Port())
	binary.BigEndian.PutUint16(seg[2:4], dst.Port())
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = byte(hl/4) << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], tcpDNSWindow)
	if mss > 0 {
		seg[20], seg[21] = 2, 4
		binary.BigEndian.PutUint16(seg[22:24], mss)
	}
	copy(seg[hl:], payload)
	var pseudo [12]byte
	copy(pseudo[0:4], s4[:])
	copy(pseudo[4:8], d4[:])
	pseudo[9] = packet.ProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg))) //nolint:gosec // bounded above
	binary.BigEndian.PutUint16(seg[16:18], ^onesSum(seg, uint32(onesSum(pseudo[:], 0))))
	return pkt
}

// onesSum is the folded one's complement sum used by IP and TCP.
func onesSum(b []byte, initial uint32) uint16 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) //nolint:gosec // folded to 16 bits above
}

type tcpKey struct{ client, server netip.AddrPort }

type tcpConnState int

const (
	tcpReceiving tcpConnState = iota // reading the query
	tcpWaiting                       // the answer is being prepared
	tcpAnswered                      // the answer and our FIN were sent
)

type tcpDNSConn struct {
	clientNext uint32 // next sequence number expected from the client
	ourNext    uint32 // next sequence number we send
	respSeq    uint32 // sequence number of the first answer byte
	resp       []byte // the framed answer, kept for retransmission
	buf        []byte
	state      tcpConnState
	clientFin  bool
	mss        int
	seen       time.Time
}

// tcpDNS is a set of DNS-over-TCP connections.
type tcpDNS struct {
	mu    sync.Mutex
	conns map[tcpKey]*tcpDNSConn
}

// tcpAnswerFunc answers one query, now or later, by calling reply once;
// a nil answer resets the connection.
type tcpAnswerFunc func(query []byte, reply func(answer []byte))

func randISN() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// seqBefore reports a < b in sequence space.
func seqBefore(a, b uint32) bool { return int32(a-b) < 0 } //nolint:gosec // serial arithmetic

// handle processes one segment from a client; out sends segments back.
func (t *tcpDNS) handle(s tcpSeg, now time.Time, answer tcpAnswerFunc, out func([]byte)) {
	key := tcpKey{client: s.src, server: s.dst}
	reply := func(seq, ack uint32, flags uint8, payload []byte) []byte {
		return buildTCP4(s.dst, s.src, seq, ack, flags, 0, payload)
	}
	t.mu.Lock()
	if t.conns == nil {
		t.conns = make(map[tcpKey]*tcpDNSConn)
	}
	c := t.conns[key]
	switch {
	case s.flags&tcpFlagRst != 0:
		delete(t.conns, key)
		t.mu.Unlock()
		return
	case s.flags&tcpFlagSyn != 0 && s.flags&tcpFlagAck == 0:
		t.expireLocked(now)
		if c == nil && len(t.conns) >= tcpDNSMaxConns {
			t.mu.Unlock()
			out(reply(0, s.seq+1, tcpFlagRst|tcpFlagAck, nil))
			return
		}
		isn := randISN()
		mss := min(max(s.mss, tcpDNSDefaultMSS), tcpDNSMSS)
		t.conns[key] = &tcpDNSConn{clientNext: s.seq + 1, ourNext: isn + 1, mss: mss, seen: now}
		t.mu.Unlock()
		out(buildTCP4(s.dst, s.src, isn, s.seq+1, tcpFlagSyn|tcpFlagAck, tcpDNSMSS, nil))
		return
	case c == nil:
		t.mu.Unlock()
		if s.flags&tcpFlagAck != 0 {
			out(reply(s.ack, 0, tcpFlagRst, nil))
		}
		return
	}
	c.seen = now
	var pkts [][]byte
	var query []byte
	if len(s.payload) > 0 {
		switch {
		case s.seq == c.clientNext && c.state == tcpReceiving:
			if len(c.buf)+len(s.payload) > tcpDNSMaxQuery {
				delete(t.conns, key)
				t.mu.Unlock()
				out(reply(c.ourNext, 0, tcpFlagRst, nil))
				return
			}
			c.buf = append(c.buf, s.payload...)
			c.clientNext += uint32(len(s.payload)) //nolint:gosec // bounded by tcpDNSMaxQuery
			if len(c.buf) >= 2 {
				n := int(binary.BigEndian.Uint16(c.buf))
				if n < 12 || 2+n > tcpDNSMaxQuery {
					delete(t.conns, key)
					t.mu.Unlock()
					out(reply(c.ourNext, 0, tcpFlagRst, nil))
					return
				}
				if len(c.buf) >= 2+n {
					query = append([]byte(nil), c.buf[2:2+n]...)
					c.state = tcpWaiting
				}
			}
			if query == nil {
				pkts = append(pkts, reply(c.ourNext, c.clientNext, tcpFlagAck, nil))
			}
		case c.state == tcpAnswered && seqBefore(s.seq, c.clientNext):
			// Our answer was lost: send it again.
			pkts = append(pkts, c.segments(reply)...)
		default:
			pkts = append(pkts, reply(c.ourNext, c.clientNext, tcpFlagAck, nil))
		}
	}
	if s.flags&tcpFlagFin != 0 && !c.clientFin {
		if s.seq+uint32(len(s.payload)) == c.clientNext { //nolint:gosec // segment length
			c.clientNext++
			c.clientFin = true
			switch c.state {
			case tcpAnswered:
				pkts = append(pkts, reply(c.ourNext, c.clientNext, tcpFlagAck, nil))
				delete(t.conns, key)
			case tcpReceiving:
				// Closed before a whole query arrived.
				pkts = append(pkts, reply(c.ourNext, c.clientNext, tcpFlagFin|tcpFlagAck, nil))
				delete(t.conns, key)
			}
		}
	} else if s.flags&tcpFlagAck != 0 && c.state == tcpAnswered && c.clientFin && s.ack == c.ourNext {
		delete(t.conns, key)
	}
	t.mu.Unlock()
	for _, p := range pkts {
		out(p)
	}
	if query != nil {
		answer(query, func(resp []byte) { t.respond(key, resp, reply, out) })
	}
}

// respond sends the answer and our FIN.
func (t *tcpDNS) respond(key tcpKey, resp []byte, reply func(seq, ack uint32, flags uint8, payload []byte) []byte, out func([]byte)) {
	t.mu.Lock()
	c := t.conns[key]
	if c == nil || c.state != tcpWaiting {
		t.mu.Unlock()
		return
	}
	if len(resp) == 0 || len(resp) > 0xffff {
		delete(t.conns, key)
		seq := c.ourNext
		t.mu.Unlock()
		out(reply(seq, 0, tcpFlagRst, nil))
		return
	}
	framed := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(framed, uint16(len(resp))) //nolint:gosec // checked above
	copy(framed[2:], resp)
	c.resp, c.respSeq, c.state = framed, c.ourNext, tcpAnswered
	c.ourNext = c.respSeq + uint32(len(framed)) + 1 //nolint:gosec // at most 65537 bytes
	c.buf = nil
	pkts := c.segments(reply)
	t.mu.Unlock()
	for _, p := range pkts {
		out(p)
	}
}

// segments cuts the framed answer into segments; the last one carries
// our FIN.
func (c *tcpDNSConn) segments(reply func(seq, ack uint32, flags uint8, payload []byte) []byte) [][]byte {
	var out [][]byte
	for off := 0; off < len(c.resp); off += c.mss {
		end := min(off+c.mss, len(c.resp))
		flags := uint8(tcpFlagAck | tcpFlagPsh)
		if end == len(c.resp) {
			flags |= tcpFlagFin
		}
		out = append(out, reply(c.respSeq+uint32(off), c.clientNext, flags, c.resp[off:end])) //nolint:gosec // offsets within 64 KiB
	}
	return out
}

func (t *tcpDNS) expireLocked(now time.Time) {
	for k, c := range t.conns {
		if now.Sub(c.seen) > tcpDNSIdle {
			delete(t.conns, k)
		}
	}
}

// answerDNSTCP answers the OS's TCP query to the MagicDNS resolver.
func (e *Engine) answerDNSTCP(pkt []byte) {
	s, ok := parseTCP4(pkt)
	if !ok {
		return
	}
	e.netDNS.tcp.handle(s, e.cfg.Now(), e.answerOrForward, func(p []byte) {
		if e.wrap != nil {
			e.wrap.writeOS(p)
		}
	})
}

// serveExitDNSTCP answers a member's TCP query to this exit node's
// address through the exit node's resolver (F-066), with the same checks
// as the UDP path.
func (e *Engine) serveExitDNSTCP(pkt []byte) bool {
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoTCP || in.DstPort != dnsPort || in.Fragment {
		return false
	}
	e.mu.Lock()
	role, self := e.exitRole, e.self
	e.mu.Unlock()
	if !role || in.Dst != self.IPv4 {
		return false
	}
	doc := e.cfg.Store.Document()
	member, allowed := false, false
	var client exitClient
	var peer string
	for _, d := range doc.Devices {
		if d.IPv4 == in.Src && d.Name != self.Name {
			member, allowed = true, doc.MayUseExitNode(d.Name) && e.cfg.Now().Before(d.ExpiresAt)
			client = exitClientFor(doc, d.Name) // P05: rate limit, profile
			peer = d.Name
			break
		}
	}
	if !member {
		return false
	}
	if !allowed || e.exitDNSRefused(peer) {
		// Quarantine and lost mode as in the filter (exitdns_g3.go): no
		// handshake, no answer.
		return true
	}
	s, ok := parseTCP4(pkt)
	if !ok {
		return true
	}
	answer := func(query []byte, reply func([]byte)) { e.exitStreamAnswer(client, query, reply) }
	e.netDNS.exitTCP.handle(s, e.cfg.Now(), answer, func(p []byte) {
		if e.wrap != nil && !e.exitDNSRefused(peer) {
			e.wrap.Inject(p)
		}
	})
	return true
}

// exitStreamAnswer forwards a member's TCP query to the exit node's
// resolver without the UDP size limit.
func (e *Engine) exitStreamAnswer(client exitClient, query []byte, reply func([]byte)) {
	select {
	case e.dnsSem <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-e.dnsSem }()
		fwd, err := e.exitDNSForwarder() // ADR-0142
		if err != nil {
			e.logExitDNSUpstream(err)
			reply(failureAnswer(query))
			return
		}
		answer, err := fwd.forwardFrom(context.Background(), client, query, true)
		if err != nil {
			e.logger.Debug("exit DNS", "error", err.Error())
			answer = failureAnswer(query)
		}
		reply(answer)
	}()
}
