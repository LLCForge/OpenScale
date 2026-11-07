package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Recursive resolver for exit nodes (#88, ADR-0034): with the upstream
// setting "recursive" the exit node resolves members' queries itself,
// starting from the root servers, so no public DNS provider sees them.
// Each server sees only the part of the name it needs (QNAME
// minimisation, RFC 9156). Answers are accepted only from the servers
// responsible for the name (bailiwick checks), under random IDs and source
// ports. DNSSEC is validated only with the "recursive-dnssec" setting
// (recursive_dnssec.go, ADR-0102).

// UpstreamRecursive is the ExitDNSUpstream value of the recursive resolver.
const UpstreamRecursive = "recursive"

const (
	// recBudget bounds the queries one member query may cause.
	recBudget = 64
	// recMaxDepth bounds nested resolutions (name server addresses).
	recMaxDepth = 4
	// recMaxCNAME bounds the CNAME chain of one answer.
	recMaxCNAME = 8
	// recMaxMinimised bounds the extra labels asked one at a time.
	recMaxMinimised  = 10
	recServerTimeout = 1500 * time.Millisecond
	recMaxServers    = 4
	recCutCacheSize  = 512
	recCutMaxTTL     = time.Hour
	recEDNSSize      = 1232
)

// rootServers are the IPv4 addresses of the root servers (root hints).
var rootServers = []netip.Addr{
	netip.MustParseAddr("198.41.0.4"),     // a
	netip.MustParseAddr("170.247.170.2"),  // b
	netip.MustParseAddr("192.33.4.12"),    // c
	netip.MustParseAddr("199.7.91.13"),    // d
	netip.MustParseAddr("192.203.230.10"), // e
	netip.MustParseAddr("192.5.5.241"),    // f
	netip.MustParseAddr("192.112.36.4"),   // g
	netip.MustParseAddr("198.97.190.53"),  // h
	netip.MustParseAddr("192.36.148.17"),  // i
	netip.MustParseAddr("192.58.128.30"),  // j
	netip.MustParseAddr("193.0.14.129"),   // k
	netip.MustParseAddr("199.7.83.42"),    // l
	netip.MustParseAddr("202.12.27.33"),   // m
}

// errRecursion is returned when a name cannot be resolved.
var errRecursion = errors.New("recursive resolution failed")

// recQueryFunc asks one authoritative server one question.
type recQueryFunc func(ctx context.Context, server netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error)

type recursiveResolver struct {
	roots []netip.Addr
	query recQueryFunc
	now   func() time.Time

	mu   sync.Mutex
	cuts map[string]zoneCut
}

// zoneCut is a cached delegation: the servers of a zone.
type zoneCut struct {
	servers []netip.Addr
	expires time.Time
}

func newRecursiveResolver() *recursiveResolver {
	return &recursiveResolver{roots: rootServers, query: askAuthoritative, now: time.Now, cuts: map[string]zoneCut{}}
}

// askAuthoritative sends a non-recursive query over UDP (TCP when the
// answer is truncated) under a random ID.
func askAuthoritative(ctx context.Context, server netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	return askAuthoritativeEDNS(ctx, server, name, qtype, false)
}

// askAuthoritativeDO asks with the DNSSEC OK bit (RFC 3225), so answers
// carry their signatures (#89).
func askAuthoritativeDO(ctx context.Context, server netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	return askAuthoritativeEDNS(ctx, server, name, qtype, true)
}

func askAuthoritativeEDNS(ctx context.Context, server netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type, dnssecOK bool) (*dnsmessage.Message, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(b[:])
	q := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	bld := dnsmessage.NewBuilder(make([]byte, 0, 128), dnsmessage.Header{ID: id})
	if err := bld.StartQuestions(); err != nil {
		return nil, err
	}
	if err := bld.Question(q); err != nil {
		return nil, err
	}
	if err := bld.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(recEDNSSize, dnsmessage.RCodeSuccess, dnssecOK); err != nil {
		return nil, err
	}
	if err := bld.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	msg, err := bld.Finish()
	if err != nil {
		return nil, err
	}
	addr := netip.AddrPortFrom(server, dnsPort).String()
	resp, err := exchangeUDP(ctx, addr, msg, id, q)
	if err != nil {
		return nil, err
	}
	if len(resp) > 2 && resp[2]&0x02 != 0 {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if resp, err = exchangeStream(ctx, c, msg, id, q); err != nil {
			return nil, err
		}
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil, err
	}
	return &m, nil
}

// recState is the work left for one member query.
type recState struct{ budget int }

// resolve answers a member's query (msg, already carrying id) and returns
// the packed response.
func (r *recursiveResolver) resolve(ctx context.Context, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	if q.Class != dnsmessage.ClassINET {
		return nil, errors.New("only class IN is resolved")
	}
	st := &recState{budget: recBudget}
	answers, auth, rcode, err := r.lookup(ctx, st, q.Name, q.Type, 0)
	if err != nil {
		return nil, err
	}
	out := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: id, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true,
			CheckingDisabled: h.CheckingDisabled, RCode: rcode,
		},
		Questions:   []dnsmessage.Question{q},
		Answers:     answers,
		Authorities: auth,
	}
	return out.Pack()
}

// lookup resolves name and follows CNAME records. The answers keep the
// chain in order; auth holds the SOA of a negative answer.
func (r *recursiveResolver) lookup(ctx context.Context, st *recState, name dnsmessage.Name, qtype dnsmessage.Type, depth int) (answers, auth []dnsmessage.Resource, rcode dnsmessage.RCode, err error) {
	cur := name
	for hop := 0; hop <= recMaxCNAME; hop++ {
		resp, zone, err := r.iterate(ctx, st, cur, qtype, depth)
		if err != nil {
			return nil, nil, 0, err
		}
		var target *dnsmessage.Name
		found := false
		for _, rr := range resp.Answers {
			if rr.Header.Class != dnsmessage.ClassINET || !sameName(rr.Header.Name, cur) || !under(cur.String(), zone) {
				continue // only the asked name, from its own servers
			}
			if c, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && qtype != dnsmessage.TypeCNAME {
				if target == nil {
					answers = append(answers, rr)
					t := c.CNAME
					target = &t
				}
				continue
			}
			if rr.Header.Type == qtype || qtype == dnsmessage.TypeALL {
				answers = append(answers, rr)
				found = true
			}
		}
		if found || target == nil {
			if !found && resp.RCode == dnsmessage.RCodeNameError {
				rcode = dnsmessage.RCodeNameError
			}
			for _, rr := range resp.Authorities {
				if rr.Header.Type == dnsmessage.TypeSOA && under(rr.Header.Name.String(), zone) && !found {
					auth = append(auth, rr)
				}
			}
			return answers, auth, rcode, nil
		}
		cur = *target
	}
	return nil, nil, 0, errors.New("CNAME chain too long")
}

// iterate walks down from the closest known zone cut to the servers of
// name and returns their answer and the zone they serve.
func (r *recursiveResolver) iterate(ctx context.Context, st *recState, name dnsmessage.Name, qtype dnsmessage.Type, depth int) (*dnsmessage.Message, string, error) {
	fqdn := strings.ToLower(name.String())
	zone, servers := r.closestCut(fqdn)
	return r.iterateFrom(ctx, st, name, qtype, depth, fqdn, zone, servers)
}

// iterateFrom is iterate starting at the given zone cut; DNSSEC asks the
// parent zone for DS records (recursive_dnssec.go, ADR-0102).
func (r *recursiveResolver) iterateFrom(ctx context.Context, st *recState, name dnsmessage.Name, qtype dnsmessage.Type, depth int, fqdn, zone string, servers []netip.Addr) (*dnsmessage.Message, string, error) {
	extra, minimise := 1, true
	for {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		qname, qt, minimised := name, qtype, false
		if minimise && extra <= recMaxMinimised {
			if part := lastLabels(fqdn, labelCount(zone)+extra); part != fqdn {
				n, err := dnsmessage.NewName(part)
				if err != nil {
					return nil, "", err
				}
				qname, qt, minimised = n, dnsmessage.TypeA, true
			}
		}
		resp, err := r.ask(ctx, st, servers, qname, qt)
		if err != nil {
			return nil, "", err
		}
		if cut, addrs, ok := r.referral(ctx, st, resp, zone, strings.ToLower(qname.String()), depth); ok {
			zone, servers, extra = cut, addrs, 1
			continue
		}
		if minimised {
			if resp.RCode == dnsmessage.RCodeSuccess {
				extra++ // no zone cut at this label: one more
			} else {
				minimise = false // a server that mishandles minimised names
			}
			continue
		}
		if lame(resp) {
			return nil, "", errRecursion
		}
		return resp, zone, nil
	}
}

// ask sends the question to up to recMaxServers servers until one gives
// a usable answer.
func (r *recursiveResolver) ask(ctx context.Context, st *recState, servers []netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	var last error = errRecursion
	for i, s := range servers {
		if i >= recMaxServers {
			break
		}
		if st.budget <= 0 {
			return nil, errors.New("too many queries for one name")
		}
		st.budget--
		qctx, cancel := context.WithTimeout(ctx, recServerTimeout)
		m, err := r.query(qctx, s, name, qtype)
		cancel()
		if err != nil {
			last = err
			continue
		}
		if m.RCode == dnsmessage.RCodeSuccess || m.RCode == dnsmessage.RCodeNameError {
			return m, nil
		}
		last = errors.New("server answered " + m.RCode.String())
	}
	return nil, last
}

// referral recognises a delegation to a zone strictly below zone that
// covers qname, and returns the zone and its server addresses. Glue is
// accepted only inside zone; other server names are resolved.
func (r *recursiveResolver) referral(ctx context.Context, st *recState, m *dnsmessage.Message, zone, qname string, depth int) (string, []netip.Addr, bool) {
	if len(m.Answers) > 0 || m.RCode != dnsmessage.RCodeSuccess {
		return "", nil, false
	}
	cut := ""
	var names []string
	ttl := uint32(recCutMaxTTL / time.Second)
	for _, rr := range m.Authorities {
		ns, ok := rr.Body.(*dnsmessage.NSResource)
		if !ok {
			continue
		}
		owner := strings.ToLower(rr.Header.Name.String())
		if owner == zone || !under(owner, zone) || !under(qname, owner) {
			continue
		}
		if cut == "" {
			cut = owner
		}
		if owner != cut {
			continue
		}
		names = append(names, strings.ToLower(ns.NS.String()))
		ttl = min(ttl, rr.Header.TTL)
	}
	if cut == "" {
		return "", nil, false
	}
	var addrs []netip.Addr
	for _, rr := range m.Additionals {
		a, ok := rr.Body.(*dnsmessage.AResource)
		owner := strings.ToLower(rr.Header.Name.String())
		if !ok || !under(owner, zone) || !slices.Contains(names, owner) {
			continue
		}
		addrs = append(addrs, netip.AddrFrom4(a.A))
	}
	if len(addrs) == 0 && depth < recMaxDepth {
		for i, n := range names {
			if i >= recMaxServers {
				break
			}
			nsName, err := dnsmessage.NewName(n)
			if err != nil || under(n, cut) {
				continue // in-zone server without glue cannot be reached
			}
			ans, _, _, err := r.lookup(ctx, st, nsName, dnsmessage.TypeA, depth+1)
			if err != nil {
				continue
			}
			for _, rr := range ans {
				if a, ok := rr.Body.(*dnsmessage.AResource); ok {
					addrs = append(addrs, netip.AddrFrom4(a.A))
				}
			}
			if len(addrs) > 0 {
				break
			}
		}
	}
	addrs = usableServers(addrs)
	if len(addrs) == 0 {
		return "", nil, false
	}
	r.storeCut(cut, addrs, time.Duration(ttl)*time.Second)
	return cut, addrs, true
}

// lame reports a response that neither answers nor delegates further: no
// records, not authoritative, name servers but no SOA (an upward or
// self referral).
func lame(m *dnsmessage.Message) bool {
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) > 0 || m.Authoritative {
		return false
	}
	ns := false
	for _, rr := range m.Authorities {
		switch rr.Header.Type {
		case dnsmessage.TypeSOA:
			return false
		case dnsmessage.TypeNS:
			ns = true
		}
	}
	return ns
}

// usableServers drops addresses no public name server has.
func usableServers(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0]
	for _, a := range addrs {
		if a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			out = append(out, a)
		}
	}
	return out
}

func (r *recursiveResolver) closestCut(fqdn string) (string, []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for name := fqdn; name != "."; name = parentZone(name) {
		if c, ok := r.cuts[name]; ok {
			if now.Before(c.expires) {
				return name, c.servers
			}
			delete(r.cuts, name)
		}
	}
	return ".", r.roots
}

func (r *recursiveResolver) storeCut(zone string, servers []netip.Addr, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cuts) >= recCutCacheSize {
		clear(r.cuts)
	}
	r.cuts[zone] = zoneCut{servers: servers, expires: r.now().Add(min(ttl, recCutMaxTTL))}
}

// under reports whether name equals zone or is below it; both are
// absolute names with the trailing dot.
func under(name, zone string) bool {
	name, zone = strings.ToLower(name), strings.ToLower(zone)
	return zone == "." || name == zone || strings.HasSuffix(name, "."+zone)
}

func sameName(a, b dnsmessage.Name) bool { return strings.EqualFold(a.String(), b.String()) }

func parentZone(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return "."
	}
	return name[i+1:]
}

func labelCount(name string) int {
	if name == "." {
		return 0
	}
	return strings.Count(name, ".")
}

// lastLabels returns the last n labels of an absolute name.
func lastLabels(name string, n int) string {
	if n >= labelCount(name) {
		return name
	}
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	return strings.Join(parts[len(parts)-n:], ".") + "."
}
