package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/dnssec"
)

// DNSSEC validation for the exit node's recursive resolver (#89,
// ADR-0102). With the upstream setting "recursive-dnssec" every answer is
// checked against the chain of trust from the built-in root anchors (or
// the owner's anchor file):
//
//   - secure: every RRset of the answer (CNAME hops included) and every
//     denial of existence is signed and the chain verifies; the member gets
//     the AD bit when it asked with DO or AD;
//   - insecure: the answer lies below a provably unsigned delegation, or
//     the zone uses only algorithms this build does not verify (SHA-1,
//     Ed448); it is passed on without AD, like any unsigned answer;
//   - bogus: a signature is missing, broken, expired or does not lead to a
//     trusted key; the member gets SERVFAIL (unless it set CD).
//
// The resolver keeps every other rule of recursive.go (QNAME minimisation,
// bailiwick, budgets); validation adds DNSKEY and DS lookups that count
// against a larger per-query budget.

// UpstreamRecursiveDNSSEC is the ExitDNSUpstream value of the recursive
// resolver with DNSSEC validation.
const UpstreamRecursiveDNSSEC = "recursive-dnssec"

const (
	// dnssecBudget bounds the queries one member query may cause with
	// validation (chain lookups included).
	dnssecBudget = 160
	// dnssecChainDepth bounds nested zone trust lookups (one per label up
	// to the root at most).
	dnssecChainDepth = 40
	// dnssecWalk bounds the DS lookups made to find an unsigned delegation
	// between a signed zone cut and an unsigned answer.
	dnssecWalk          = 6
	dnssecZoneCacheSize = 1024
	dnssecMaxTTL        = time.Hour
	dnssecInsecureTTL   = 10 * time.Minute
	dnssecBogusTTL      = 30 * time.Second
)

type secStatus int

// Ordered from best to worst: an answer is as good as its worst part.
const (
	secSecure secStatus = iota
	secInsecure
	secBogus
)

// zoneTrust is the validated state of a zone.
type zoneTrust struct {
	status  secStatus
	keys    []dnssec.DNSKEY // secure zones: the usable zone keys
	expires time.Time
}

type dnssecValidator struct {
	r       *recursiveResolver
	anchors []dnssec.DS
	now     func() time.Time

	mu    sync.Mutex
	zones map[string]zoneTrust
}

// Process-wide validation counters (no names are kept).
var dnssecSecure, dnssecInsecure, dnssecBogus atomic.Uint64

// DNSSECStats reports how many answers the validating resolver found
// secure, insecure and bogus since the process started.
func DNSSECStats() (secure, insecure, bogus uint64) {
	return dnssecSecure.Load(), dnssecInsecure.Load(), dnssecBogus.Load()
}

// dnssecAnchors replaces the built-in root anchors when the owner gives a
// file (SetDNSSECTrustAnchors).
var dnssecAnchors atomic.Pointer[[]dnssec.DS]

// maxAnchorFile bounds an owner's anchor file.
const maxAnchorFile = 64 << 10

// SetDNSSECTrustAnchors makes the validating resolver trust the root DS
// records in path instead of the built-in ones (for a root key rollover
// after this build); "" goes back to the built-in anchors. Forwarders
// created earlier are dropped so the next query uses the new anchors.
func SetDNSSECTrustAnchors(path string) error {
	if path == "" {
		dnssecAnchors.Store(nil)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("DNSSEC güven çapası dosyası açılamadı: %w", err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Size() > maxAnchorFile {
			return errors.New("DNSSEC güven çapası dosyası düzenli ve 64 KiB'tan küçük bir dosya olmalı")
		}
		ds, err := dnssec.ParseAnchors(f)
		if err != nil {
			return err
		}
		dnssecAnchors.Store(&ds)
	}
	forwardersMu.Lock()
	clear(forwarders)
	forwardersMu.Unlock()
	return nil
}

func newDNSSECValidator(r *recursiveResolver) *dnssecValidator {
	anchors := dnssec.RootAnchors()
	if p := dnssecAnchors.Load(); p != nil {
		anchors = *p
	}
	r.query = askAuthoritativeDO
	return &dnssecValidator{r: r, anchors: anchors, now: r.now, zones: map[string]zoneTrust{}}
}

// resolve answers a member's query (msg, already carrying id) with
// validation and returns the packed response.
func (v *dnssecValidator) resolve(ctx context.Context, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	if q.Class != dnsmessage.ClassINET {
		return nil, errors.New("only class IN is resolved")
	}
	do := queryDO(msg)
	out := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: id, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true,
			CheckingDisabled: h.CheckingDisabled,
		},
		Questions: []dnsmessage.Question{q},
	}
	if do {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(recEDNSSize, dnsmessage.RCodeSuccess, true); err != nil {
			return nil, err
		}
		out.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	}
	switch q.Type {
	case dnsmessage.TypeALL, dnssec.TypeRRSIG, dnssec.TypeNSEC, dnssec.TypeNSEC3:
		// Meta queries cannot be validated as one RRset (RFC 8482).
		out.Header.RCode = dnsmessage.RCodeNotImplemented
		return out.Pack()
	}
	if q.Type == dnssec.TypeDS && strings.ToLower(q.Name.String()) == "." {
		out.Header.RCode = dnsmessage.RCodeSuccess
		return out.Pack()
	}
	st := &recState{budget: dnssecBudget}
	res, err := v.lookup(ctx, st, q.Name, q.Type)
	if err != nil {
		return nil, err
	}
	switch res.status {
	case secSecure:
		dnssecSecure.Add(1)
	case secInsecure:
		dnssecInsecure.Add(1)
	default:
		dnssecBogus.Add(1)
	}
	if res.status == secBogus && !h.CheckingDisabled {
		out.Header.RCode = dnsmessage.RCodeServerFailure
		return out.Pack()
	}
	out.Header.RCode = res.rcode
	out.Header.AuthenticData = res.status == secSecure && (do || h.AuthenticData)
	out.Answers = res.answers
	out.Authorities = res.auth
	if do {
		out.Answers = append(out.Answers, res.sigs...)
		out.Authorities = append(out.Authorities, res.authProof...)
	}
	return out.Pack()
}

// secResult is a validated answer.
type secResult struct {
	answers, sigs   []dnsmessage.Resource
	auth, authProof []dnsmessage.Resource
	rcode           dnsmessage.RCode
	status          secStatus
}

// ask resolves one name; DS questions go to the parent zone.
func (v *dnssecValidator) ask(ctx context.Context, st *recState, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, string, error) {
	if qtype == dnssec.TypeDS {
		return v.r.iterateDS(ctx, st, name)
	}
	return v.r.iterate(ctx, st, name, qtype, 0)
}

// iterateDS asks the parent zone of name for its DS records: the
// iteration starts above name, so a cached cut at name itself (the child,
// which cannot answer for DS) is never asked first.
func (r *recursiveResolver) iterateDS(ctx context.Context, st *recState, name dnsmessage.Name) (*dnsmessage.Message, string, error) {
	fqdn := strings.ToLower(name.String())
	if fqdn == "." {
		return nil, "", errors.New("the root has no DS records")
	}
	zone, servers := r.closestCut(parentZone(fqdn))
	return r.iterateFrom(ctx, st, name, dnssec.TypeDS, 0, fqdn, zone, servers)
}

// lookup resolves and validates name, following CNAME records.
func (v *dnssecValidator) lookup(ctx context.Context, st *recState, name dnsmessage.Name, qtype dnsmessage.Type) (secResult, error) {
	res := secResult{status: secSecure}
	cur := name
	for hop := 0; hop <= recMaxCNAME; hop++ {
		resp, zone, err := v.ask(ctx, st, cur, qtype)
		if err != nil {
			return secResult{}, err
		}
		owner := strings.ToLower(cur.String())
		inZone := under(owner, zone)
		var set []dnsmessage.Resource
		setType := qtype
		var target *dnsmessage.Name
		for _, rr := range resp.Answers {
			if inZone && rr.Header.Class == dnsmessage.ClassINET && sameName(rr.Header.Name, cur) && rr.Header.Type == qtype {
				set = append(set, rr)
			}
		}
		if len(set) == 0 && qtype != dnsmessage.TypeCNAME {
			for _, rr := range resp.Answers {
				c, ok := rr.Body.(*dnsmessage.CNAMEResource)
				if ok && inZone && rr.Header.Class == dnsmessage.ClassINET && sameName(rr.Header.Name, cur) {
					set, setType = []dnsmessage.Resource{rr}, dnsmessage.TypeCNAME
					t := c.CNAME
					target = &t
					break
				}
			}
		}
		if len(set) > 0 {
			sigs := rrsigsFor(resp.Answers, owner, setType)
			status, used := v.validateRRset(ctx, st, set, sigs, owner, zone, resp)
			res.status = max(res.status, status)
			// A bogus set is kept only for members that set CD; resolve
			// answers SERVFAIL otherwise.
			res.answers = append(res.answers, capTTL(set, used, v.now())...)
			for _, s := range sigs {
				res.sigs = append(res.sigs, s.rr)
			}
			if target == nil || status == secBogus {
				return res, nil
			}
			cur = *target
			continue
		}
		rcode := dnsmessage.RCodeSuccess
		if resp.RCode == dnsmessage.RCodeNameError {
			rcode = dnsmessage.RCodeNameError
		}
		res.status = max(res.status, v.validateNegative(ctx, st, resp, owner, qtype, zone, rcode))
		res.rcode = rcode
		for _, rr := range resp.Authorities {
			if !under(strings.ToLower(rr.Header.Name.String()), zone) {
				continue
			}
			switch rr.Header.Type {
			case dnsmessage.TypeSOA:
				res.auth = append(res.auth, rr)
			case dnssec.TypeNSEC, dnssec.TypeNSEC3, dnssec.TypeRRSIG:
				res.authProof = append(res.authProof, rr)
			}
		}
		return res, nil
	}
	return secResult{}, errors.New("CNAME chain too long")
}

// sigRR is a parsed RRSIG and its record.
type sigRR struct {
	rr  dnsmessage.Resource
	sig dnssec.RRSIG
}

// rrsigsFor returns the signatures in section over owner's RRset of type
// covered.
func rrsigsFor(section []dnsmessage.Resource, owner string, covered dnsmessage.Type) []sigRR {
	var out []sigRR
	for _, rr := range section {
		if rr.Header.Type != dnssec.TypeRRSIG || rr.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(rr.Header.Name.String(), owner) {
			continue
		}
		u, ok := rr.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		s, err := dnssec.ParseRRSIG(u.Data)
		if err != nil || s.TypeCovered != uint16(covered) {
			continue
		}
		out = append(out, sigRR{rr: rr, sig: s})
	}
	return out
}

func toRRs(set []dnsmessage.Resource) ([]dnssec.RR, error) {
	out := make([]dnssec.RR, 0, len(set))
	for _, rr := range set {
		c, err := dnssec.FromResource(rr)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// capTTL limits the TTLs of a validated set to the signature's original
// TTL and its remaining validity (RFC 4035 5.3.3).
func capTTL(set []dnsmessage.Resource, sig *dnssec.RRSIG, now time.Time) []dnsmessage.Resource {
	if sig == nil {
		return set
	}
	left := max(int64(sig.ValidUntil(now).Sub(now)/time.Second), 0)
	out := make([]dnsmessage.Resource, len(set))
	for i, rr := range set {
		rr.Header.TTL = uint32(min(int64(rr.Header.TTL), int64(sig.OrigTTL), left))
		out[i] = rr
	}
	return out
}

// validateRRset checks a positive RRset of owner.
func (v *dnssecValidator) validateRRset(ctx context.Context, st *recState, set []dnsmessage.Resource, sigs []sigRR, owner, cutZone string, resp *dnsmessage.Message) (secStatus, *dnssec.RRSIG) {
	rrs, err := toRRs(set)
	if err != nil {
		return secBogus, nil
	}
	if len(sigs) == 0 {
		return v.unsignedStatus(ctx, st, owner, cutZone), nil
	}
	tried := map[string]bool{}
	for _, s := range sigs {
		signer := s.sig.SignerName
		if tried[signer] || !under(owner, signer) {
			continue
		}
		tried[signer] = true
		zt, err := v.zoneTrust(ctx, st, signer, 0)
		if err != nil {
			return secBogus, nil
		}
		switch zt.status {
		case secInsecure:
			return secInsecure, nil
		case secBogus:
			continue
		}
		for _, s2 := range sigs {
			if s2.sig.SignerName != signer {
				continue
			}
			for _, k := range zt.keys {
				if dnssec.VerifyRRSIG(s2.sig, k, rrs, v.now()) != nil {
					continue
				}
				if int(s2.sig.Labels) < dnssec.LabelCount(owner) {
					// A wildcard answered: the name itself must not exist.
					ce := lastLabels(owner, int(s2.sig.Labels))
					if v.denial(resp.Authorities, signer, zt.keys).WildcardAnswer(owner, ce) == dnssec.NotProved {
						return secBogus, nil
					}
				}
				sig := s2.sig
				return secSecure, &sig
			}
		}
	}
	return secBogus, nil
}

// validateNegative checks an NXDOMAIN or NODATA answer for owner.
func (v *dnssecValidator) validateNegative(ctx context.Context, st *recState, resp *dnsmessage.Message, owner string, qtype dnsmessage.Type, cutZone string, rcode dnsmessage.RCode) secStatus {
	signer := ""
	for _, rr := range resp.Authorities {
		if rr.Header.Type != dnssec.TypeRRSIG {
			continue
		}
		u, ok := rr.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		s, err := dnssec.ParseRRSIG(u.Data)
		if err != nil {
			continue
		}
		switch dnsmessage.Type(s.TypeCovered) {
		case dnsmessage.TypeSOA, dnssec.TypeNSEC, dnssec.TypeNSEC3:
			if under(owner, s.SignerName) && len(s.SignerName) > len(signer) {
				signer = s.SignerName
			}
		}
	}
	if signer == "" {
		return v.unsignedStatus(ctx, st, owner, cutZone)
	}
	zt, err := v.zoneTrust(ctx, st, signer, 0)
	if err != nil {
		return secBogus
	}
	if zt.status != secSecure {
		return zt.status
	}
	d := v.denial(resp.Authorities, signer, zt.keys)
	var p dnssec.Proof
	if rcode == dnsmessage.RCodeNameError {
		p = d.NXDomain(owner)
	} else {
		p = d.NoData(owner, uint16(qtype))
	}
	switch p {
	case dnssec.Proved:
		return secSecure
	case dnssec.ProvedInsecure:
		return secInsecure
	}
	return secBogus
}

// denial collects the NSEC and NSEC3 records of zone in section whose
// signatures verify with keys.
func (v *dnssecValidator) denial(section []dnsmessage.Resource, zone string, keys []dnssec.DNSKEY) dnssec.Denial {
	d := dnssec.Denial{Zone: zone}
	type key struct {
		owner string
		typ   dnsmessage.Type
	}
	groups := map[key][]dnsmessage.Resource{}
	var order []key
	for _, rr := range section {
		if rr.Header.Type != dnssec.TypeNSEC && rr.Header.Type != dnssec.TypeNSEC3 {
			continue
		}
		owner := strings.ToLower(rr.Header.Name.String())
		if rr.Header.Class != dnsmessage.ClassINET || !under(owner, zone) {
			continue
		}
		k := key{owner, rr.Header.Type}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rr)
	}
	now := v.now()
	for _, k := range order {
		set := groups[k]
		rrs, err := toRRs(set)
		if err != nil {
			continue
		}
		verified := false
		for _, s := range rrsigsFor(section, k.owner, k.typ) {
			if !strings.EqualFold(s.sig.SignerName, zone) {
				continue
			}
			for _, key := range keys {
				if dnssec.VerifyRRSIG(s.sig, key, rrs, now) == nil {
					verified = true
					break
				}
			}
			if verified {
				break
			}
		}
		if !verified {
			continue
		}
		for _, rr := range rrs {
			switch dnsmessage.Type(rr.Type) {
			case dnssec.TypeNSEC:
				if n, err := dnssec.ParseNSEC(rr.Rdata); err == nil {
					d.NSEC = append(d.NSEC, dnssec.NSECRecord{Owner: rr.Name, NSEC: n})
				}
			case dnssec.TypeNSEC3:
				if n, err := dnssec.ParseNSEC3(rr.Rdata); err == nil {
					d.NSEC3 = append(d.NSEC3, dnssec.NSEC3Record{Owner: rr.Name, NSEC3: n})
				}
			}
		}
	}
	return d
}

// unsignedStatus decides an unsigned answer for owner that came from the
// servers of cutZone: insecure only when cutZone is insecure or a
// provably unsigned delegation lies between cutZone and owner.
func (v *dnssecValidator) unsignedStatus(ctx context.Context, st *recState, owner, cutZone string) secStatus {
	zt, err := v.zoneTrust(ctx, st, cutZone, 0)
	if err != nil {
		return secBogus
	}
	if zt.status != secSecure {
		return zt.status
	}
	extra := labelCount(owner) - labelCount(cutZone)
	for i := 1; i <= extra && i <= dnssecWalk; i++ {
		name := lastLabels(owner, labelCount(cutZone)+i)
		kind, _, err := v.dsLookup(ctx, st, name, 0)
		if err != nil {
			return secBogus
		}
		switch kind {
		case dsNoneDelegation, dsInsecure:
			return secInsecure
		case dsNotCut:
			continue
		}
		return secBogus // a signed child, or no proof: the signatures were stripped
	}
	return secBogus
}

type dsKind int

const (
	dsBogus          dsKind = iota
	dsPositive              // a validated DS RRset
	dsInsecure              // the parent is insecure, or an opt-out span
	dsNoneDelegation        // proved: a delegation without DS (unsigned child)
	dsNotCut                // proved: no DS and no delegation at this name
)

// dsLookup asks the parent of name for name's DS records and validates the
// answer with the parent's keys.
func (v *dnssecValidator) dsLookup(ctx context.Context, st *recState, name string, depth int) (dsKind, []dnssec.DS, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dsBogus, nil, err
	}
	resp, cut, err := v.r.iterateDS(ctx, st, n)
	if err != nil {
		return dsBogus, nil, err
	}
	var set []dnsmessage.Resource
	var ds []dnssec.DS
	for _, rr := range resp.Answers {
		if rr.Header.Type != dnssec.TypeDS || rr.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(rr.Header.Name.String(), name) {
			continue
		}
		u, ok := rr.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		d, err := dnssec.ParseDS(u.Data)
		if err != nil {
			continue
		}
		set = append(set, rr)
		ds = append(ds, d)
	}
	properAbove := func(z string) bool { return under(name, z) && !strings.EqualFold(z, name) }
	if len(set) > 0 {
		sigs := rrsigsFor(resp.Answers, name, dnssec.TypeDS)
		rrs, err := toRRs(set)
		if err != nil {
			return dsBogus, nil, nil
		}
		var parents []string
		for _, s := range sigs {
			if properAbove(s.sig.SignerName) && !containsFold(parents, s.sig.SignerName) {
				parents = append(parents, s.sig.SignerName)
			}
		}
		if len(parents) == 0 && properAbove(cut) {
			parents = []string{cut}
		}
		for _, p := range parents {
			pt, err := v.zoneTrust(ctx, st, p, depth+1)
			if err != nil {
				return dsBogus, nil, err
			}
			if pt.status == secInsecure {
				return dsInsecure, nil, nil
			}
			if pt.status != secSecure {
				continue
			}
			for _, s := range sigs {
				if !strings.EqualFold(s.sig.SignerName, p) {
					continue
				}
				for _, k := range pt.keys {
					if dnssec.VerifyRRSIG(s.sig, k, rrs, v.now()) == nil {
						return dsPositive, ds, nil
					}
				}
			}
		}
		return dsBogus, nil, nil
	}
	parent := ""
	for _, rr := range resp.Authorities {
		if rr.Header.Type == dnsmessage.TypeSOA && properAbove(strings.ToLower(rr.Header.Name.String())) {
			parent = strings.ToLower(rr.Header.Name.String())
			break
		}
	}
	if parent == "" {
		for _, rr := range resp.Authorities {
			if rr.Header.Type != dnssec.TypeRRSIG {
				continue
			}
			if u, ok := rr.Body.(*dnsmessage.UnknownResource); ok {
				if s, err := dnssec.ParseRRSIG(u.Data); err == nil && properAbove(s.SignerName) {
					parent = s.SignerName
					break
				}
			}
		}
	}
	if parent == "" && properAbove(cut) {
		parent = cut
	}
	if parent == "" {
		return dsBogus, nil, nil
	}
	pt, err := v.zoneTrust(ctx, st, parent, depth+1)
	if err != nil {
		return dsBogus, nil, err
	}
	switch pt.status {
	case secInsecure:
		return dsInsecure, nil, nil
	case secBogus:
		return dsBogus, nil, nil
	}
	p, deleg := v.denial(resp.Authorities, parent, pt.keys).NoDS(name)
	switch {
	case p == dnssec.Proved && deleg:
		return dsNoneDelegation, nil, nil
	case p == dnssec.Proved:
		return dsNotCut, nil, nil
	case p == dnssec.ProvedInsecure:
		return dsInsecure, nil, nil
	}
	return dsBogus, nil, nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// zoneTrust returns the validated keys of zone, or that it is insecure or
// bogus. The root is checked against the trust anchors, every other zone
// against the DS records its parent signed.
func (v *dnssecValidator) zoneTrust(ctx context.Context, st *recState, zone string, depth int) (zoneTrust, error) {
	zone = strings.ToLower(zone)
	if zt, ok := v.cached(zone); ok {
		return zt, nil
	}
	if depth > dnssecChainDepth {
		return zoneTrust{}, errors.New("DNSSEC chain too deep")
	}
	var dsSet []dnssec.DS
	if zone == "." {
		dsSet = v.anchors
	} else {
		kind, ds, err := v.dsLookup(ctx, st, zone, depth)
		if err != nil {
			return zoneTrust{}, err
		}
		switch kind {
		case dsPositive:
			dsSet = ds
		case dsInsecure, dsNoneDelegation:
			return v.store(zone, zoneTrust{status: secInsecure}, dnssecInsecureTTL), nil
		default:
			// No DS proof, or a signer name that is no zone cut.
			return v.store(zone, zoneTrust{status: secBogus}, dnssecBogusTTL), nil
		}
	}
	supported := false
	for _, d := range dsSet {
		supported = supported || d.Supported()
	}
	if !supported {
		// Only algorithms or digests this build does not verify: the zone
		// is treated as unsigned (RFC 4035 5.2), never as validated.
		return v.store(zone, zoneTrust{status: secInsecure}, dnssecInsecureTTL), nil
	}
	name, err := dnsmessage.NewName(zone)
	if err != nil {
		return zoneTrust{}, err
	}
	resp, _, err := v.r.iterate(ctx, st, name, dnssec.TypeDNSKEY, 0)
	if err != nil {
		return zoneTrust{}, err
	}
	var set []dnsmessage.Resource
	var keys []dnssec.DNSKEY
	for _, rr := range resp.Answers {
		if rr.Header.Type != dnssec.TypeDNSKEY || rr.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(rr.Header.Name.String(), zone) {
			continue
		}
		u, ok := rr.Body.(*dnsmessage.UnknownResource)
		if !ok {
			continue
		}
		k, err := dnssec.ParseDNSKEY(u.Data)
		if err != nil {
			continue
		}
		set = append(set, rr)
		keys = append(keys, k)
	}
	rrs, err := toRRs(set)
	if err != nil || len(rrs) == 0 {
		return v.store(zone, zoneTrust{status: secBogus}, dnssecBogusTTL), nil
	}
	sigs := rrsigsFor(resp.Answers, zone, dnssec.TypeDNSKEY)
	now := v.now()
	for _, d := range dsSet {
		if !d.Supported() {
			continue
		}
		for _, k := range keys {
			if !k.Usable() || !d.Matches(zone, k) {
				continue
			}
			for _, s := range sigs {
				if !strings.EqualFold(s.sig.SignerName, zone) || s.sig.KeyTag != k.KeyTag() {
					continue
				}
				if dnssec.VerifyRRSIG(s.sig, k, rrs, now) != nil {
					continue
				}
				var usable []dnssec.DNSKEY
				for _, k2 := range keys {
					if k2.Usable() {
						usable = append(usable, k2)
					}
				}
				ttl := dnssecMaxTTL
				for _, rr := range set {
					ttl = min(ttl, time.Duration(rr.Header.TTL)*time.Second)
				}
				ttl = min(ttl, s.sig.ValidUntil(now).Sub(now))
				return v.store(zone, zoneTrust{status: secSecure, keys: usable}, ttl), nil
			}
		}
	}
	return v.store(zone, zoneTrust{status: secBogus}, dnssecBogusTTL), nil
}

func (v *dnssecValidator) cached(zone string) (zoneTrust, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	zt, ok := v.zones[zone]
	if !ok {
		return zoneTrust{}, false
	}
	if !v.now().Before(zt.expires) {
		delete(v.zones, zone)
		return zoneTrust{}, false
	}
	return zt, true
}

// store caches zt for ttl (not at all when ttl is not positive) and
// returns it.
func (v *dnssecValidator) store(zone string, zt zoneTrust, ttl time.Duration) zoneTrust {
	if ttl <= 0 {
		return zt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.zones) >= dnssecZoneCacheSize {
		clear(v.zones)
	}
	zt.expires = v.now().Add(ttl)
	v.zones[zone] = zt
	return zt
}

// queryDO reports whether a member's query carries the DNSSEC OK bit.
func queryDO(msg []byte) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return false
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return false
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return false
		}
		if h.Type == dnsmessage.TypeOPT {
			return h.DNSSECAllowed()
		}
		if p.SkipAdditional() != nil {
			return false
		}
	}
}
