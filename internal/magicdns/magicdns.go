// Package magicdns answers DNS queries for device names inside the network
// domain, e.g. "laptop.openscale.internal" (ADR-0016), and reverse (PTR)
// queries for addresses inside the network ranges (ADR-0024, F-056).
// Answers come only from the root-signed document; nothing is forwarded
// anywhere.
package magicdns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

// TTL of every answer in seconds. Short, so renamed or removed devices
// disappear quickly.
const TTL = 60

// MaxQuery bounds the accepted query size.
const MaxQuery = 512

// Limits for answers sent over UDP: 512 bytes without EDNS (RFC 1035),
// otherwise the client's advertised size within these bounds.
const (
	MinUDPSize = 512
	MaxUDPSize = 4096
)

// CoordinatorLabel is the name the coordinator answers to under the domain.
const CoordinatorLabel = trust.CoordinatorName

// request is the part of a query every answer needs.
type request struct {
	hdr  dnsmessage.Header
	q    dnsmessage.Question
	name string // lowercase, without the trailing dot
}

// parseQuery accepts a single standard query with exactly one question.
func parseQuery(msg []byte) (request, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil || hdr.Response || hdr.OpCode != 0 {
		return request{}, false
	}
	q, err := p.Question()
	if err != nil {
		return request{}, false
	}
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return request{}, false // exactly one question
	}
	return request{hdr: hdr, q: q, name: strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))}, true
}

// Handles reports whether query asks for a name this package answers: one
// under the network domain or the reverse name of an address inside the
// network. Everything else belongs to another resolver.
func Handles(doc *trust.Document, msg []byte) bool {
	if doc == nil || len(msg) > MaxQuery {
		return false
	}
	q, ok := parseQuery(msg)
	if !ok {
		return false
	}
	if q.name == doc.DNSDomain || strings.HasSuffix(q.name, "."+doc.DNSDomain) {
		return true
	}
	a, ok := reverseAddr(q.name)
	return ok && inNetwork(doc, a)
}

// Answer builds the response to one DNS query against doc. It returns nil
// for packets that are not a single standard query, which are dropped. An
// answer larger than the client's UDP limit is truncated (TC set).
func Answer(doc *trust.Document, msg []byte) []byte {
	return answer(doc, msg, UDPLimit(msg))
}

// AnswerStream builds the response for a query that arrived over TCP
// (F-066): there is no UDP size limit, only the DNS message limit.
func AnswerStream(doc *trust.Document, msg []byte) []byte {
	return answer(doc, msg, MaxStreamMessage)
}

// MaxStreamMessage is the largest DNS message over TCP (RFC 1035 4.2.2).
const MaxStreamMessage = 65535

func answer(doc *trust.Document, msg []byte, limit int) []byte {
	if doc == nil || len(msg) > MaxQuery {
		return nil
	}
	in, ok := parseQuery(msg)
	if !ok {
		return nil
	}
	q, name := in.q, in.name

	resp := dnsmessage.Header{
		ID:                 in.hdr.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   in.hdr.RecursionDesired,
		RecursionAvailable: false,
		RCode:              dnsmessage.RCodeSuccess,
	}
	domain := doc.DNSDomain
	var answers, extra []rr
	rev, isRev := reverseAddr(name)
	switch {
	case q.Class != dnsmessage.ClassINET:
		resp.RCode = dnsmessage.RCodeNotImplemented
	case isRev && inNetwork(doc, rev):
		if label, ok := nameOf(doc, rev); ok {
			if q.Type == dnsmessage.TypePTR || q.Type == dnsmessage.TypeALL {
				answers = append(answers, rr{name: q.Name, typ: dnsmessage.TypePTR, target: label + "." + domain + "."})
			}
		} else {
			resp.RCode = dnsmessage.RCodeNameError
		}
	case name != domain && !strings.HasSuffix(name, "."+domain):
		// Only the network domain and its reverse zones are ours; the OS
		// routes nothing else here.
		resp.RCode = dnsmessage.RCodeRefused
		resp.Authoritative = false
	default:
		rel := strings.TrimSuffix(strings.TrimSuffix(name, domain), ".")
		var found bool
		found, answers, extra = newZone(doc).lookup(rel, q.Name, q.Type, 0)
		if !found {
			resp.RCode = dnsmessage.RCodeNameError
		}
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 128), resp)
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	for _, a := range answers {
		if a.write(&b) != nil {
			return nil
		}
	}
	if len(extra) > 0 {
		if b.StartAuthorities() != nil || b.StartAdditionals() != nil {
			return nil
		}
		for _, a := range extra {
			if a.write(&b) != nil {
				return nil
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	if len(out) > limit {
		return Truncate(out)
	}
	return out
}

// inNetwork reports whether a is inside one of the network ranges.
func inNetwork(doc *trust.Document, a netip.Addr) bool {
	return (doc.IPv4Prefix.IsValid() && doc.IPv4Prefix.Contains(a)) ||
		(doc.IPv6Prefix.IsValid() && doc.IPv6Prefix.Contains(a))
}

// nameOf returns the label of the device or coordinator owning a.
func nameOf(doc *trust.Document, a netip.Addr) (string, bool) {
	for _, d := range doc.Devices {
		if d.IPv4 == a || d.IPv6 == a {
			return d.Name, true
		}
	}
	if c := doc.Coordinator; c != nil && (c.IPv4 == a || c.IPv6 == a) {
		return CoordinatorLabel, true
	}
	return "", false
}

// reverseAddr parses a full reverse name: "4.3.2.1.in-addr.arpa" or the 32
// nibbles of an "ip6.arpa" name. Partial (zone) names are not addresses.
func reverseAddr(name string) (netip.Addr, bool) {
	if s, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		labels := strings.Split(s, ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}
		var b [4]byte
		for i, l := range labels {
			if l == "" || len(l) > 3 || (len(l) > 1 && l[0] == '0') {
				return netip.Addr{}, false
			}
			n, err := strconv.ParseUint(l, 10, 8)
			if err != nil {
				return netip.Addr{}, false
			}
			b[3-i] = byte(n)
		}
		return netip.AddrFrom4(b), true
	}
	if s, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		labels := strings.Split(s, ".")
		if len(labels) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i, l := range labels {
			if len(l) != 1 {
				return netip.Addr{}, false
			}
			n, err := strconv.ParseUint(l, 16, 8)
			if err != nil {
				return netip.Addr{}, false
			}
			nibble := 31 - i
			if nibble%2 == 0 {
				b[nibble/2] |= byte(n) << 4
			} else {
				b[nibble/2] |= byte(n)
			}
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// UDPLimit returns the largest answer the sender of query accepts over
// UDP: 512 bytes, or its EDNS(0) buffer size clamped to [512, 4096].
func UDPLimit(msg []byte) int {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return MinUDPSize
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return MinUDPSize
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return MinUDPSize
		}
		if h.Type == dnsmessage.TypeOPT {
			return min(max(int(h.Class), MinUDPSize), MaxUDPSize)
		}
		if p.SkipAdditional() != nil {
			return MinUDPSize
		}
	}
}

// Truncate returns msg reduced to its header and question with the TC bit
// set, telling the client to retry over TCP (RFC 1035 4.2.1). It returns
// nil if msg cannot be parsed.
func Truncate(msg []byte) []byte {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		// Every answer this is used for has exactly one question.
		return nil
	}
	// The header and the question are kept as sent: a compression pointer
	// in the question can only point back into them, and re-encoding a
	// pathological name could make the "truncated" message grow.
	end, ok := questionEnd(msg)
	if !ok {
		return nil
	}
	out := append([]byte(nil), msg[:end]...)
	out[2] |= 0x02 // TC
	binary.BigEndian.PutUint16(out[4:6], 1)
	clear(out[6:12]) // no answer, authority or additional records
	return out
}

// questionEnd returns the offset just after the first question.
func questionEnd(msg []byte) (int, bool) {
	off := 12
	for {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 == 0xc0 {
			off += 2
			break
		}
		if l&0xc0 != 0 {
			return 0, false
		}
		off += 1 + l
	}
	off += 4 // type and class
	return off, off <= len(msg)
}
