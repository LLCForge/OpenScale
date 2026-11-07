package dnssec

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"strings"
)

// Proof is the outcome of a denial of existence check.
type Proof int

const (
	// NotProved: the records do not prove the claim; a signed zone's
	// answer is then bogus.
	NotProved Proof = iota
	// Proved: the claim is proved by signed records.
	Proved
	// ProvedInsecure: the claim holds only in an NSEC3 opt-out span or
	// with too many NSEC3 iterations; the answer is insecure, not bogus.
	ProvedInsecure
)

// MaxNSEC3Iterations is the largest NSEC3 iteration count validated;
// above it answers are treated as insecure (RFC 9276 3.2), which bounds the
// hashing work a zone can demand.
const MaxNSEC3Iterations = 150

// Types used by the proofs.
const (
	typeNS    = 2
	typeCNAME = 5
	typeSOA   = 6
	typeDNAME = 39
	typeDS    = 43
)

// NSECRecord is an NSEC record and its owner.
type NSECRecord struct {
	Owner string
	NSEC
}

// NSEC3Record is an NSEC3 record and its owner.
type NSEC3Record struct {
	Owner string
	NSEC3
}

// Denial holds the validated NSEC and NSEC3 records one response carried
// for one zone. Records whose signatures were not verified must not be
// put here.
type Denial struct {
	Zone  string
	NSEC  []NSECRecord
	NSEC3 []NSEC3Record
}

// NXDomain proves that qname does not exist.
func (d Denial) NXDomain(qname string) Proof {
	qname = CanonicalName(qname)
	if !IsSubdomain(qname, d.Zone) {
		return NotProved
	}
	if p := d.nsecNXDomain(qname); p != NotProved {
		return p
	}
	return d.nsec3NXDomain(qname)
}

// NoData proves that qname exists without records of type qtype.
func (d Denial) NoData(qname string, qtype uint16) Proof {
	qname = CanonicalName(qname)
	if !IsSubdomain(qname, d.Zone) {
		return NotProved
	}
	if qtype == typeDS {
		p, _ := d.NoDS(qname)
		return p
	}
	if p := d.nsecNoData(qname, qtype); p != NotProved {
		return p
	}
	return d.nsec3NoData(qname, qtype)
}

// NoDS proves that name has no DS records; delegation reports that name
// is a zone cut (an unsigned child zone) rather than a name inside the
// zone or a name that does not exist.
func (d Denial) NoDS(name string) (Proof, bool) {
	name = CanonicalName(name)
	if !IsSubdomain(name, d.Zone) {
		return NotProved, false
	}
	if p, deleg := d.nsecNoDS(name); p != NotProved {
		return p, deleg
	}
	return d.nsec3NoDS(name)
}

// WildcardAnswer proves that qname, answered by expanding the wildcard
// at ce ("*." + ce), does not exist itself (RFC 4035 5.3.4, RFC 5155 8.8).
func (d Denial) WildcardAnswer(qname, ce string) Proof {
	qname, ce = CanonicalName(qname), CanonicalName(ce)
	if !isProperSubdomain(qname, ce) || !IsSubdomain(ce, d.Zone) {
		return NotProved
	}
	for _, n := range d.nsecs() {
		if n.Owner != qname && n.covers(qname) && !n.delegationAbove(qname) {
			return Proved
		}
	}
	recs, insecure := d.nsec3s()
	if insecure {
		return ProvedInsecure
	}
	nc := lastLabels(qname, len(labels(ce))+1)
	for _, r := range recs {
		if r.coversName(nc) {
			return Proved
		}
	}
	return NotProved
}

// ---- NSEC (RFC 4035 5.4) ----

func (d Denial) nsecs() []NSECRecord {
	var out []NSECRecord
	for _, n := range d.NSEC {
		n.Owner, n.NextName = CanonicalName(n.Owner), CanonicalName(n.NextName)
		if IsSubdomain(n.Owner, d.Zone) && IsSubdomain(n.NextName, d.Zone) {
			out = append(out, n)
		}
	}
	return out
}

// covers reports owner < name < next in canonical order, with the last
// record of the chain wrapping around to the apex.
func (n NSECRecord) covers(name string) bool {
	if CompareNames(n.Owner, n.NextName) < 0 {
		return CompareNames(n.Owner, name) < 0 && CompareNames(name, n.NextName) < 0
	}
	return CompareNames(n.Owner, name) < 0 || CompareNames(name, n.NextName) < 0
}

// delegationAbove reports an NSEC at a delegation point or DNAME above
// name: it comes from the parent side and proves nothing below it
// (RFC 6840 4.1).
func (n NSECRecord) delegationAbove(name string) bool {
	if !isProperSubdomain(name, n.Owner) {
		return false
	}
	return (n.Types.Has(typeNS) && !n.Types.Has(typeSOA)) || n.Types.Has(typeDNAME)
}

// nsecCover returns the record covering name.
func nsecCover(recs []NSECRecord, name string) (NSECRecord, bool) {
	for _, n := range recs {
		if n.Owner != name && n.covers(name) && !n.delegationAbove(name) {
			return n, true
		}
	}
	return NSECRecord{}, false
}

// nsecClosestEncloser derives the closest encloser of qname from the
// record covering it.
func nsecClosestEncloser(cover NSECRecord, qname, zone string) string {
	a, b := commonAncestor(qname, cover.Owner), commonAncestor(qname, cover.NextName)
	ce := a
	if len(labels(b)) > len(labels(a)) {
		ce = b
	}
	if !IsSubdomain(ce, zone) {
		ce = CanonicalName(zone)
	}
	return ce
}

func wildcardOf(ce string) string {
	if ce == "." {
		return "*."
	}
	return "*." + ce
}

func (d Denial) nsecNXDomain(qname string) Proof {
	recs := d.nsecs()
	for _, n := range recs {
		if n.Owner == qname {
			return NotProved
		}
	}
	cover, ok := nsecCover(recs, qname)
	if !ok {
		return NotProved
	}
	wc := wildcardOf(nsecClosestEncloser(cover, qname, d.Zone))
	for _, n := range recs {
		if n.Owner == wc {
			return NotProved // the wildcard exists: it should have answered
		}
	}
	if _, ok := nsecCover(recs, wc); ok {
		return Proved
	}
	return NotProved
}

func (d Denial) nsecNoData(qname string, qtype uint16) Proof {
	recs := d.nsecs()
	for _, n := range recs {
		if n.Owner != qname {
			continue
		}
		if n.Types.Has(qtype) || n.Types.Has(typeCNAME) {
			return NotProved
		}
		if n.Types.Has(typeNS) && !n.Types.Has(typeSOA) {
			return NotProved // parent side of a delegation: the data lives below
		}
		return Proved
	}
	// An empty non-terminal: the next name lies below qname.
	for _, n := range recs {
		if n.covers(qname) && isProperSubdomain(n.NextName, qname) && !n.delegationAbove(qname) {
			return Proved
		}
	}
	cover, ok := nsecCover(recs, qname)
	if !ok {
		return NotProved
	}
	wc := wildcardOf(nsecClosestEncloser(cover, qname, d.Zone))
	for _, n := range recs {
		if n.Owner == wc && !n.Types.Has(qtype) && !n.Types.Has(typeCNAME) {
			return Proved
		}
	}
	return NotProved
}

func (d Denial) nsecNoDS(name string) (Proof, bool) {
	recs := d.nsecs()
	for _, n := range recs {
		if n.Owner != name {
			continue
		}
		if n.Types.Has(typeDS) || n.Types.Has(typeCNAME) || n.Types.Has(typeSOA) {
			return NotProved, false // a DS exists, or this is the child's apex
		}
		return Proved, n.Types.Has(typeNS)
	}
	for _, n := range recs {
		if n.covers(name) && isProperSubdomain(n.NextName, name) && !n.delegationAbove(name) {
			return Proved, false // empty non-terminal
		}
	}
	if d.nsecNXDomain(name) == Proved {
		return Proved, false
	}
	return NotProved, false
}

// ---- NSEC3 (RFC 5155 8) ----

var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// NSEC3Hash computes the hashed owner name (RFC 5155 5).
func NSEC3Hash(name string, salt []byte, iterations uint16) ([]byte, error) {
	w, err := nameWire(name)
	if err != nil {
		return nil, err
	}
	h := sha1.Sum(append(w, salt...))
	buf := make([]byte, 0, sha1.Size+len(salt))
	for i := 0; i < int(iterations); i++ {
		buf = append(append(buf[:0], h[:]...), salt...)
		h = sha1.Sum(buf)
	}
	return h[:], nil
}

// NSEC3Label encodes a hash as the first label of an NSEC3 owner.
func NSEC3Label(hash []byte) string { return strings.ToLower(b32.EncodeToString(hash)) }

type n3 struct {
	NSEC3Record
	ownerHash []byte
}

// nsec3s returns the usable records; insecure reports a record with more
// iterations than MaxNSEC3Iterations.
func (d Denial) nsec3s() (out []n3, insecure bool) {
	zone := CanonicalName(d.Zone)
	for _, r := range d.NSEC3 {
		r.Owner = CanonicalName(r.Owner)
		if r.HashAlgorithm != 1 || r.Flags&^NSEC3OptOut != 0 || parent(r.Owner) != zone {
			continue // unknown hash or flags are ignored (RFC 5155 8.1, 8.2)
		}
		l := labels(r.Owner)
		if len(l) == 0 {
			continue
		}
		h, err := b32.DecodeString(strings.ToUpper(l[0]))
		if err != nil || len(h) != sha1.Size || len(r.NextHashed) != sha1.Size {
			continue
		}
		if r.Iterations > MaxNSEC3Iterations {
			insecure = true
			continue
		}
		out = append(out, n3{NSEC3Record: r, ownerHash: h})
	}
	return out, insecure
}

func (r n3) matches(name string) bool {
	h, err := NSEC3Hash(name, r.Salt, r.Iterations)
	return err == nil && bytes.Equal(h, r.ownerHash)
}

func (r n3) coversName(name string) bool {
	h, err := NSEC3Hash(name, r.Salt, r.Iterations)
	if err != nil {
		return false
	}
	o, nx := r.ownerHash, r.NextHashed
	if bytes.Compare(o, nx) < 0 {
		return bytes.Compare(o, h) < 0 && bytes.Compare(h, nx) < 0
	}
	return bytes.Compare(o, h) < 0 || bytes.Compare(h, nx) < 0
}

func match3(recs []n3, name string) (n3, bool) {
	for _, r := range recs {
		if r.matches(name) {
			return r, true
		}
	}
	return n3{}, false
}

func cover3(recs []n3, name string) (n3, bool) {
	for _, r := range recs {
		if r.coversName(name) {
			return r, true
		}
	}
	return n3{}, false
}

// closestEncloser finds the closest encloser proof for qname (RFC 5155
// 8.3): the longest existing ancestor and a record covering the next
// closer name. qname itself must not exist.
func (d Denial) closestEncloser(recs []n3, qname string) (ce string, nextCloser n3, ok bool) {
	zone := CanonicalName(d.Zone)
	prev := ""
	for sname := qname; ; sname = parent(sname) {
		if !IsSubdomain(sname, zone) {
			return "", n3{}, false
		}
		if m, found := match3(recs, sname); found {
			if sname == qname {
				return "", n3{}, false
			}
			if (m.Types.Has(typeNS) && !m.Types.Has(typeSOA)) || m.Types.Has(typeDNAME) {
				return "", n3{}, false
			}
			c, found := cover3(recs, prev)
			if !found {
				return "", n3{}, false
			}
			return sname, c, true
		}
		if sname == zone || sname == "." {
			return "", n3{}, false
		}
		prev = sname
	}
}

func (d Denial) nsec3NXDomain(qname string) Proof {
	recs, insecure := d.nsec3s()
	if insecure {
		return ProvedInsecure
	}
	if _, ok := match3(recs, qname); ok {
		return NotProved
	}
	ce, nc, ok := d.closestEncloser(recs, qname)
	if !ok {
		return NotProved
	}
	wc := wildcardOf(ce)
	if _, ok := match3(recs, wc); ok {
		return NotProved
	}
	if _, ok := cover3(recs, wc); !ok {
		return NotProved
	}
	if nc.Flags&NSEC3OptOut != 0 {
		return ProvedInsecure
	}
	return Proved
}

func (d Denial) nsec3NoData(qname string, qtype uint16) Proof {
	recs, insecure := d.nsec3s()
	if insecure {
		return ProvedInsecure
	}
	if m, ok := match3(recs, qname); ok {
		if m.Types.Has(qtype) || m.Types.Has(typeCNAME) {
			return NotProved
		}
		if m.Types.Has(typeNS) && !m.Types.Has(typeSOA) {
			return NotProved
		}
		return Proved
	}
	ce, _, ok := d.closestEncloser(recs, qname)
	if !ok {
		return NotProved
	}
	if m, ok := match3(recs, wildcardOf(ce)); ok && !m.Types.Has(qtype) && !m.Types.Has(typeCNAME) {
		return Proved
	}
	return NotProved
}

func (d Denial) nsec3NoDS(name string) (Proof, bool) {
	recs, insecure := d.nsec3s()
	if insecure {
		return ProvedInsecure, true
	}
	if m, ok := match3(recs, name); ok {
		if m.Types.Has(typeDS) || m.Types.Has(typeCNAME) || m.Types.Has(typeSOA) {
			return NotProved, false
		}
		return Proved, m.Types.Has(typeNS)
	}
	ce, nc, ok := d.closestEncloser(recs, name)
	if !ok {
		return NotProved, false
	}
	if nc.Flags&NSEC3OptOut != 0 {
		// An unsigned delegation may hide in an opt-out span (RFC 5155 6).
		return ProvedInsecure, true
	}
	wc := wildcardOf(ce)
	if _, ok := match3(recs, wc); ok {
		return NotProved, false
	}
	if _, ok := cover3(recs, wc); ok {
		return Proved, false // the name does not exist
	}
	return NotProved, false
}
