package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Network DNS through the MagicDNS resolver (ADR-0034). The OS sends the
// network domain, the split domains and, with network-wide resolvers or an
// exit node, every other name to the MagicDNS resolver address. MagicDNS
// names are answered here and never leave this computer; the rest is
// forwarded through the tunnel to the resolvers the signed document names
// (split DNS, network-wide resolvers) or to the exit node in use.

const (
	// netDNSServerTimeout is how long one resolver may take before the
	// next one in the list is asked.
	netDNSServerTimeout = 2 * time.Second
	// netDNSTimeout bounds one forwarded query over all resolvers.
	netDNSTimeout = 4 * time.Second
)

// netDNSServerPort is the port of the network's resolvers; tests point it
// at a local server.
var netDNSServerPort uint16 = dnsPort

// netDNSState is the engine's network DNS state.
type netDNSState struct {
	// reject is the device's own choice to ignore the document's DNS
	// settings (F-065). The exit node's resolver is used regardless.
	reject atomic.Bool
	tcp    tcpDNS
	// exitTCP serves members' TCP queries on an exit node.
	exitTCP tcpDNS

	mu    sync.Mutex
	stats DNSForwardStats
}

// DNSForwardStats describes the forwarded queries, for the health checks
// (F-062).
type DNSForwardStats struct {
	Forwarded uint64
	Failed    uint64
	// LastError and LastErrorAt describe the last failed forward;
	// LastOKAt is the last answered one.
	LastError   string
	LastErrorAt time.Time
	LastOKAt    time.Time
}

// SetNetworkDNSRejected records the device's choice to ignore the
// document's DNS settings (F-065): MagicDNS then forwards no query to the
// network's resolvers. The default is to use them.
func (e *Engine) SetNetworkDNSRejected(reject bool) { e.netDNS.reject.Store(reject) }

// DNSForwardStats returns the forwarding counters.
func (e *Engine) DNSForwardStats() DNSForwardStats {
	e.netDNS.mu.Lock()
	defer e.netDNS.mu.Unlock()
	return e.netDNS.stats
}

func (s *netDNSState) record(err error, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Forwarded++
	if err != nil {
		s.stats.Failed++
		s.stats.LastError, s.stats.LastErrorAt = err.Error(), now
		return
	}
	s.stats.LastOKAt = now
}

// queryName returns the lowercase name of a single-question query without
// the trailing dot.
func queryName(msg []byte) (string, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response || h.OpCode != 0 {
		return "", false
	}
	q, err := p.Question()
	if err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSuffix(q.Name.String(), ".")), true
}

// splitRoute returns the resolvers of the longest split domain covering
// name.
func splitRoute(doc *trust.Document, name string) []netip.Addr {
	if doc.DNS == nil {
		return nil
	}
	best := -1
	for i, s := range doc.DNS.Split {
		if name == s.Domain || strings.HasSuffix(name, "."+s.Domain) {
			if best < 0 || len(s.Domain) > len(doc.DNS.Split[best].Domain) {
				best = i
			}
		}
	}
	if best < 0 {
		return nil
	}
	return doc.DNS.Split[best].Nameservers
}

// networkRoute returns where a query MagicDNS does not answer goes: the
// split domain's resolvers, otherwise the exit node in use, otherwise the
// network-wide resolvers. None means MagicDNS refuses it.
func (e *Engine) networkRoute(doc *trust.Document, msg []byte) []netip.Addr {
	name, ok := queryName(msg)
	if !ok {
		return nil
	}
	if !e.netDNS.reject.Load() {
		if s := splitRoute(doc, name); len(s) > 0 {
			return e.insideTunnel(doc, s)
		}
	}
	e.mu.Lock()
	active := e.exitActive
	e.mu.Unlock()
	if active != "" {
		// Never past the exit node: the OS sends here only what the tunnel
		// should resolve.
		if d, ok := doc.DeviceByName(active); ok && d.IPv4.IsValid() {
			return []netip.Addr{d.IPv4}
		}
		return nil
	}
	if e.netDNS.reject.Load() || doc.DNS == nil {
		return nil
	}
	return e.insideTunnel(doc, doc.DNS.Nameservers)
}

// exitSplitRoute returns the split resolvers for a query the OS sent to
// the exit node's resolver: split domains keep going to their own
// resolvers while an exit node is in use.
func (e *Engine) exitSplitRoute(doc *trust.Document, msg []byte) []netip.Addr {
	if e.netDNS.reject.Load() {
		return nil
	}
	name, ok := queryName(msg)
	if !ok {
		return nil
	}
	return e.insideTunnel(doc, splitRoute(doc, name))
}

// insideTunnel keeps only resolvers inside the network ranges: a query is
// never forwarded outside the network (the document already requires
// device addresses, ADR-0024), nor back to the MagicDNS resolver.
func (e *Engine) insideTunnel(doc *trust.Document, addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a == doc.DNSResolverIPv4() || a == doc.DNSResolverIPv6() {
			continue
		}
		if (doc.IPv4Prefix.IsValid() && doc.IPv4Prefix.Contains(a)) || (doc.IPv6Prefix.IsValid() && doc.IPv6Prefix.Contains(a)) {
			out = append(out, a)
		}
	}
	return out
}

// forwardUDP forwards the OS's query in the background and writes the
// answer back as coming from src (the MagicDNS resolver or the exit
// node's address).
func (e *Engine) forwardUDP(in packet.Info, src netip.Addr, servers []netip.Addr) {
	query := bytes.Clone(in.Payload)
	client, clientPort := in.Src, in.SrcPort
	e.forwardAsync(servers, query, false, func(answer []byte) {
		reply, err := packet.BuildUDP4(src, client, dnsPort, clientPort, answer)
		if err == nil && e.wrap != nil {
			e.wrap.writeOS(reply)
		}
	})
}

// forwardAsync asks servers in the background and hands the answer (or a
// SERVFAIL) to reply. Too many queries in flight drop the new one; the
// client retries.
func (e *Engine) forwardAsync(servers []netip.Addr, query []byte, stream bool, reply func([]byte)) {
	select {
	case e.dnsSem <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-e.dnsSem }()
		ctx, cancel := context.WithTimeout(context.Background(), netDNSTimeout)
		defer cancel()
		answer, err := forwardPlain(ctx, servers, query, stream)
		e.netDNS.record(err, e.cfg.Now())
		if err != nil {
			e.logger.Debug("network DNS", "error", err.Error())
			answer = failureAnswer(query)
		}
		if answer != nil {
			reply(answer)
		}
	}()
}

// forwardPlain asks each server in turn (plain DNS through the tunnel:
// UDP, TCP when truncated or when the client asked over TCP) under a fresh
// random ID, and returns the answer with the client's ID, fitted to its
// UDP limit unless stream is set.
func forwardPlain(ctx context.Context, servers []netip.Addr, query []byte, stream bool) ([]byte, error) {
	cq, err := parseClientQuery(query)
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, errors.New("no resolver")
	}
	var last error
	for _, s := range servers {
		sctx, cancel := context.WithTimeout(ctx, netDNSServerTimeout)
		resp, err := exchangePlain(sctx, netip.AddrPortFrom(s, netDNSServerPort).String(), query, cq.question, stream)
		cancel()
		if err != nil {
			last = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		out := bytes.Clone(resp)
		binary.BigEndian.PutUint16(out, cq.id)
		if !stream {
			out = fitUDP(out, cq.limit)
		}
		return out, nil
	}
	return nil, last
}

// exchangePlain sends one query to addr with a fresh random ID.
func exchangePlain(ctx context.Context, addr string, query []byte, q dnsmessage.Question, stream bool) ([]byte, error) {
	msg := bytes.Clone(query)
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(b[:])
	binary.BigEndian.PutUint16(msg, id)
	if !stream {
		resp, err := exchangeUDP(ctx, addr, msg, id, q)
		if err != nil {
			return nil, err
		}
		if len(resp) <= 2 || resp[2]&0x02 == 0 {
			return resp, nil
		}
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return exchangeStream(ctx, c, msg, id, q)
}

// failureAnswer is a SERVFAIL for query, so the client does not wait for
// its timeout.
func failureAnswer(query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 64), dnsmessage.Header{
		ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure,
	})
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// answerOrForward is the TCP answer path of the MagicDNS resolver.
func (e *Engine) answerOrForward(query []byte, reply func([]byte)) {
	doc := e.cfg.Store.Document()
	if !magicdns.Handles(doc, query) {
		if servers := e.networkRoute(doc, query); len(servers) > 0 {
			e.forwardAsync(servers, query, true, reply)
			return
		}
	}
	reply(magicdns.AnswerStream(e.dnsDocument(doc), query))
}
