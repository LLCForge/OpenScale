package node

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/dnssec"
)

// A signed fake hierarchy, built with keys generated for each test run;
// nothing leaves the process (the resolver's query function is replaced).
//
//	.               192.0.2.1  signed (ECDSA P-256)
//	test.           192.0.2.2  signed (Ed25519)
//	example.test.   192.0.2.3  signed: www A, alias CNAME, *.wild A
//	unsigned.test.  192.0.2.4  unsigned delegation (NSEC proves no DS)
//	broken.test.    192.0.2.5  DS does not match its key: bogus
//	sha1.test.      192.0.2.6  DS with RSA/SHA-1 only: insecure

var dnssecTestNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

type signKey struct {
	priv crypto.Signer
	key  dnssec.DNSKEY
}

func genSignKey(t *testing.T, alg uint8, flags uint16) signKey {
	t.Helper()
	var priv crypto.Signer
	var err error
	switch alg {
	case dnssec.AlgED25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case dnssec.AlgECDSAP256SHA256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	k, err := dnssec.NewDNSKEY(priv.Public(), alg, flags)
	if err != nil {
		t.Fatal(err)
	}
	return signKey{priv: priv, key: k}
}

type szone struct {
	name     string
	server   netip.Addr
	signed   bool
	ksk, zsk signKey
	records  map[string]map[dnsmessage.Type][]dnsmessage.Resource
	children []*szone
	// extraDS replaces the DS records the parent publishes for this zone.
	extraDS []dnssec.DS
	nsec    map[string]dnssec.NSEC
	sorted  []string
}

type signedNet struct {
	t     *testing.T
	zones map[netip.Addr]*szone
	root  *szone

	mu sync.Mutex
	// Attacks on example.test.'s answers.
	tamper, strip, stripNeg bool
}

func rr(name string, typ dnsmessage.Type, ttl uint32, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: ttl}, Body: body}
}

func unknown(name string, typ dnsmessage.Type, ttl uint32, data []byte) dnsmessage.Resource {
	return rr(name, typ, ttl, &dnsmessage.UnknownResource{Type: typ, Data: data})
}

func newZone(t *testing.T, name, server string, signed bool, alg uint8) *szone {
	z := &szone{name: name, server: netip.MustParseAddr(server), signed: signed, records: map[string]map[dnsmessage.Type][]dnsmessage.Resource{}}
	if signed {
		z.ksk = genSignKey(t, alg, dnssec.FlagZone|dnssec.FlagSEP)
		z.zsk = genSignKey(t, alg, dnssec.FlagZone)
	}
	z.add(rr(name, dnsmessage.TypeSOA, 300, &dnsmessage.SOAResource{
		NS: dnsmessage.MustNewName("ns." + strings.TrimPrefix(name, ".")), MBox: dnsmessage.MustNewName("host." + strings.TrimPrefix(name, ".")),
		Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: 60,
	}))
	if signed {
		z.add(unknown(name, dnssec.TypeDNSKEY, 3600, z.ksk.key.Rdata()))
		z.add(unknown(name, dnssec.TypeDNSKEY, 3600, z.zsk.key.Rdata()))
	}
	return z
}

func (z *szone) add(r dnsmessage.Resource) {
	n := strings.ToLower(r.Header.Name.String())
	if z.records[n] == nil {
		z.records[n] = map[dnsmessage.Type][]dnsmessage.Resource{}
	}
	z.records[n][r.Header.Type] = append(z.records[n][r.Header.Type], r)
}

func (z *szone) delegate(t *testing.T, c *szone) {
	z.children = append(z.children, c)
	z.add(rr(c.name, dnsmessage.TypeNS, 3600, &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns." + c.name)}))
	ds := c.extraDS
	if ds == nil && c.signed {
		d, err := dnssec.ComputeDS(c.name, c.ksk.key, dnssec.DigestSHA256)
		if err != nil {
			t.Fatal(err)
		}
		ds = []dnssec.DS{d}
	}
	for _, d := range ds {
		z.add(unknown(c.name, dnssec.TypeDS, 3600, d.Rdata()))
	}
}

// finish builds the NSEC chain.
func (z *szone) finish() {
	if !z.signed {
		return
	}
	z.sorted = nil
	for n := range z.records {
		z.sorted = append(z.sorted, n)
	}
	slices.SortFunc(z.sorted, dnssec.CompareNames)
	z.nsec = map[string]dnssec.NSEC{}
	for i, n := range z.sorted {
		var types []uint16
		for typ := range z.records[n] {
			types = append(types, uint16(typ))
		}
		delegation := z.records[n][dnsmessage.TypeNS] != nil && n != z.name
		if !delegation || z.records[n][dnssec.TypeDS] != nil {
			types = append(types, uint16(dnssec.TypeRRSIG))
		} else {
			types = append(types, uint16(dnssec.TypeRRSIG)) // the NSEC itself is signed
		}
		types = append(types, uint16(dnssec.TypeNSEC))
		slices.Sort(types)
		z.nsec[n] = dnssec.NSEC{NextName: z.sorted[(i+1)%len(z.sorted)], Types: types}
	}
}

func (n *signedNet) sign(z *szone, set []dnsmessage.Resource, key signKey) dnsmessage.Resource {
	n.t.Helper()
	rrs, err := toRRs(set)
	if err != nil {
		n.t.Fatal(err)
	}
	s := dnssec.RRSIG{
		TypeCovered: rrs[0].Type, Algorithm: key.key.Algorithm, Labels: uint8(dnssec.LabelCount(rrs[0].Name)), OrigTTL: rrs[0].TTL,
		Inception: uint32(dnssecTestNow.Add(-time.Hour).Unix()), Expiration: uint32(dnssecTestNow.Add(7 * 24 * time.Hour).Unix()),
		KeyTag: key.key.KeyTag(), SignerName: z.name,
	}
	s, err = dnssec.Sign(s, rrs, key.priv)
	if err != nil {
		n.t.Fatal(err)
	}
	data, err := s.Rdata()
	if err != nil {
		n.t.Fatal(err)
	}
	return unknown(rrs[0].Name, dnssec.TypeRRSIG, rrs[0].TTL, data)
}

// signed returns set followed by its signature in zone z.
func (n *signedNet) signed(z *szone, set []dnsmessage.Resource) []dnsmessage.Resource {
	if !z.signed || len(set) == 0 {
		return set
	}
	key := z.zsk
	if set[0].Header.Type == dnssec.TypeDNSKEY {
		key = z.ksk
	}
	return append(slices.Clone(set), n.sign(z, set, key))
}

func (n *signedNet) nsecRR(z *szone, owner string) []dnsmessage.Resource {
	rec := z.nsec[owner]
	data, err := rec.Rdata()
	if err != nil {
		n.t.Fatal(err)
	}
	return n.signed(z, []dnsmessage.Resource{unknown(owner, dnssec.TypeNSEC, 60, data)})
}

// covering returns the owner of the NSEC record covering name.
func (z *szone) covering(name string) string {
	for i, o := range z.sorted {
		next := z.sorted[(i+1)%len(z.sorted)]
		if dnssec.CompareNames(o, name) < 0 && (dnssec.CompareNames(name, next) < 0 || dnssec.CompareNames(next, o) <= 0) {
			return o
		}
	}
	return z.sorted[len(z.sorted)-1]
}

func (n *signedNet) query(_ context.Context, server netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	z, ok := n.zones[server]
	if !ok {
		return nil, context.DeadlineExceeded
	}
	n.mu.Lock()
	tamper, strip, stripNeg := n.tamper, n.strip, n.stripNeg
	n.mu.Unlock()
	q := strings.ToLower(name.String())
	m := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}}}
	if !under(q, z.name) {
		m.RCode = dnsmessage.RCodeRefused
		return m, nil
	}
	for _, c := range z.children {
		if under(q, c.name) && !(qtype == dnssec.TypeDS && q == c.name) {
			// Referral.
			m.Authorities = append(m.Authorities, z.records[c.name][dnsmessage.TypeNS]...)
			if ds := z.records[c.name][dnssec.TypeDS]; ds != nil {
				m.Authorities = append(m.Authorities, n.signed(z, ds)...)
			} else if z.signed {
				m.Authorities = append(m.Authorities, n.nsecRR(z, c.name)...)
			}
			m.Additionals = []dnsmessage.Resource{rrA("ns."+c.name, c.server.As4())}
			return m, nil
		}
	}
	m.Authoritative = true
	isEx := z.name == "example.test."
	answer := func(set []dnsmessage.Resource) {
		out := n.signed(z, set)
		if isEx && tamper && set[0].Header.Type == dnsmessage.TypeA {
			out = slices.Clone(out)
			out[0].Body = &dnsmessage.AResource{A: [4]byte{6, 6, 6, 6}}
		}
		if isEx && strip {
			out = slices.DeleteFunc(slices.Clone(out), func(r dnsmessage.Resource) bool { return r.Header.Type == dnssec.TypeRRSIG })
		}
		m.Answers = append(m.Answers, out...)
	}
	negative := func(nx bool) {
		if nx {
			m.RCode = dnsmessage.RCodeNameError
		}
		m.Authorities = n.signed(z, z.records[z.name][dnsmessage.TypeSOA])
		if !z.signed || (isEx && stripNeg) {
			return
		}
		if nx {
			c := z.covering(q)
			m.Authorities = append(m.Authorities, n.nsecRR(z, c)...)
			// Covering NSEC of the wildcard at the closest encloser (the apex here).
			if w := z.covering("*." + z.name); w != c {
				m.Authorities = append(m.Authorities, n.nsecRR(z, w)...)
			}
			return
		}
		m.Authorities = append(m.Authorities, n.nsecRR(z, q)...)
	}
	if types, ok := z.records[q]; ok {
		if set := types[qtype]; set != nil {
			answer(set)
		} else if c := types[dnsmessage.TypeCNAME]; c != nil {
			answer(c)
		} else {
			negative(false)
		}
		return m, nil
	}
	// Wildcard synthesis one label below an existing parent.
	if i := strings.IndexByte(q, '.'); i > 0 {
		if w, ok := z.records["*."+q[i+1:]]; ok && w[qtype] != nil {
			set := w[qtype]
			sigd := n.signed(z, set)
			for j := range sigd {
				sigd[j].Header.Name = name
			}
			m.Answers = sigd
			if z.signed {
				m.Authorities = n.nsecRR(z, z.covering(q))
			}
			return m, nil
		}
	}
	negative(true)
	return m, nil
}

func newSignedNet(t *testing.T) (*signedNet, []dnssec.DS) {
	n := &signedNet{t: t, zones: map[netip.Addr]*szone{}}
	root := newZone(t, ".", "192.0.2.1", true, dnssec.AlgECDSAP256SHA256)
	tld := newZone(t, "test.", "192.0.2.2", true, dnssec.AlgED25519)
	ex := newZone(t, "example.test.", "192.0.2.3", true, dnssec.AlgED25519)
	ex.add(rrA("www.example.test.", [4]byte{198, 51, 100, 7}))
	ex.add(rr("alias.example.test.", dnsmessage.TypeCNAME, 300, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("www.example.test.")}))
	ex.add(rrA("*.wild.example.test.", [4]byte{198, 51, 100, 8}))
	uns := newZone(t, "unsigned.test.", "192.0.2.4", false, 0)
	uns.add(rrA("www.unsigned.test.", [4]byte{198, 51, 100, 9}))
	broken := newZone(t, "broken.test.", "192.0.2.5", true, dnssec.AlgED25519)
	broken.add(rrA("www.broken.test.", [4]byte{198, 51, 100, 10}))
	other := genSignKey(t, dnssec.AlgED25519, dnssec.FlagZone|dnssec.FlagSEP)
	wrong, err := dnssec.ComputeDS("broken.test.", other.key, dnssec.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	broken.extraDS = []dnssec.DS{wrong}
	sha1 := newZone(t, "sha1.test.", "192.0.2.6", false, 0)
	sha1.add(rrA("www.sha1.test.", [4]byte{198, 51, 100, 11}))
	sha1.extraDS = []dnssec.DS{{KeyTag: 1, Algorithm: dnssec.AlgRSASHA1, DigestType: dnssec.DigestSHA1, Digest: make([]byte, 20)}}

	root.delegate(t, tld)
	for _, c := range []*szone{ex, uns, broken, sha1} {
		tld.delegate(t, c)
	}
	for _, z := range []*szone{root, tld, ex, uns, broken, sha1} {
		z.finish()
		n.zones[z.server] = z
	}
	n.root = root
	anchor, err := dnssec.ComputeDS(".", root.ksk.key, dnssec.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return n, []dnssec.DS{anchor}
}

func testValidator(t *testing.T) (*dnssecValidator, *signedNet) {
	n, anchors := newSignedNet(t)
	r := newRecursiveResolver()
	r.roots = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	r.now = func() time.Time { return dnssecTestNow }
	v := newDNSSECValidator(r)
	r.query = n.query
	v.anchors = anchors
	return v, n
}

func dnssecQuery(t *testing.T, name string, qtype dnsmessage.Type, do, cd bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true, CheckingDisabled: cd})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	var h dnsmessage.ResourceHeader
	if err := h.SetEDNS0(1232, dnsmessage.RCodeSuccess, do); err != nil {
		t.Fatal(err)
	}
	if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func validate(t *testing.T, v *dnssecValidator, name string, qtype dnsmessage.Type, cd bool) dnsmessage.Message {
	t.Helper()
	q := dnssecQuery(t, name, qtype, true, cd)
	out, err := v.resolve(context.Background(), q, 7, dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDNSSECSecureAnswers(t *testing.T) {
	v, _ := testValidator(t)
	m := validate(t, v, "www.example.test.", dnsmessage.TypeA, false)
	if m.RCode != dnsmessage.RCodeSuccess || !m.AuthenticData || !slices.Contains(answerAddrs(m), "198.51.100.7") {
		t.Fatalf("www: %v %+v", answerAddrs(m), m.Header)
	}
	hasSig := false
	for _, a := range m.Answers {
		hasSig = hasSig || a.Header.Type == dnssec.TypeRRSIG
	}
	if !hasSig {
		t.Fatal("DO query got no signatures")
	}
	m = validate(t, v, "alias.example.test.", dnsmessage.TypeA, false)
	if !m.AuthenticData || !slices.Contains(answerAddrs(m), "198.51.100.7") {
		t.Fatalf("alias: %v %+v", answerAddrs(m), m.Header)
	}
	m = validate(t, v, "nope.example.test.", dnsmessage.TypeA, false)
	if m.RCode != dnsmessage.RCodeNameError || !m.AuthenticData {
		t.Fatalf("NXDOMAIN: %+v", m.Header)
	}
	m = validate(t, v, "www.example.test.", dnsmessage.TypeAAAA, false)
	if m.RCode != dnsmessage.RCodeSuccess || len(answerAddrs(m)) != 0 || !m.AuthenticData {
		t.Fatalf("NODATA: %+v", m.Header)
	}
	m = validate(t, v, "x.wild.example.test.", dnsmessage.TypeA, false)
	if !m.AuthenticData || !slices.Contains(answerAddrs(m), "198.51.100.8") {
		t.Fatalf("wildcard: %v %+v", answerAddrs(m), m.Header)
	}
	m = validate(t, v, "example.test.", dnssec.TypeDS, false)
	if m.RCode != dnsmessage.RCodeSuccess || !m.AuthenticData || len(m.Answers) == 0 {
		t.Fatalf("DS: %+v", m.Header)
	}
}

func TestDNSSECInsecureAnswers(t *testing.T) {
	v, _ := testValidator(t)
	for _, name := range []string{"www.unsigned.test.", "www.sha1.test."} {
		m := validate(t, v, name, dnsmessage.TypeA, false)
		if m.RCode != dnsmessage.RCodeSuccess || m.AuthenticData || len(answerAddrs(m)) != 1 {
			t.Fatalf("%s: %v %+v", name, answerAddrs(m), m.Header)
		}
	}
}

func TestDNSSECBogus(t *testing.T) {
	v, n := testValidator(t)
	m := validate(t, v, "www.broken.test.", dnsmessage.TypeA, false)
	if m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
		t.Fatalf("broken chain: %+v", m.Header)
	}
	// Checking disabled: the member gets the data, never AD.
	m = validate(t, v, "www.broken.test.", dnsmessage.TypeA, true)
	if m.RCode != dnsmessage.RCodeSuccess || m.AuthenticData || len(answerAddrs(m)) != 1 {
		t.Fatalf("CD: %+v", m.Header)
	}

	for _, attack := range []string{"tamper", "strip", "stripNeg"} {
		v, n = testValidator(t)
		n.mu.Lock()
		switch attack {
		case "tamper":
			n.tamper = true
		case "strip":
			n.strip = true
		case "stripNeg":
			n.stripNeg = true
		}
		n.mu.Unlock()
		name := "www.example.test."
		if attack == "stripNeg" {
			name = "nope.example.test."
		}
		m := validate(t, v, name, dnsmessage.TypeA, false)
		if m.RCode != dnsmessage.RCodeServerFailure || slices.Contains(answerAddrs(m), "6.6.6.6") {
			t.Fatalf("%s: %v %+v", attack, answerAddrs(m), m.Header)
		}
	}

	// Signatures out of their validity period.
	v, _ = testValidator(t)
	late := dnssecTestNow.Add(30 * 24 * time.Hour)
	v.now = func() time.Time { return late }
	v.r.now = v.now
	if m := validate(t, v, "www.example.test.", dnsmessage.TypeA, false); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("expired: %+v", m.Header)
	}

	// A wrong trust anchor makes everything bogus.
	v, _ = testValidator(t)
	k := genSignKey(t, dnssec.AlgED25519, dnssec.FlagZone|dnssec.FlagSEP)
	d, _ := dnssec.ComputeDS(".", k.key, dnssec.DigestSHA256)
	v.anchors = []dnssec.DS{d}
	if m := validate(t, v, "www.example.test.", dnsmessage.TypeA, false); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("wrong anchor: %+v", m.Header)
	}
}

func TestDNSSECMetaQueries(t *testing.T) {
	v, _ := testValidator(t)
	if m := validate(t, v, "example.test.", dnsmessage.TypeALL, false); m.RCode != dnsmessage.RCodeNotImplemented {
		t.Fatalf("ANY: %+v", m.Header)
	}
}

func TestDNSSECUpstreamSetting(t *testing.T) {
	up, err := parseDNSUpstream("Recursive-DNSSEC")
	if err != nil || up.kind != upstreamRecursive || !up.dnssec {
		t.Fatalf("%v %+v", err, up)
	}
	f := newDNSForwarder(up, nil)
	if f.validator == nil || f.recursive == nil {
		t.Fatal("no validator")
	}
	if up, _ := parseDNSUpstream("recursive"); up.dnssec {
		t.Fatal("plain recursive validates")
	}
}
