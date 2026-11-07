package dnssec

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParseRecords feeds arbitrary record data to every parser: none may
// panic, and what parses must encode back to data that parses the same.
func FuzzParseRecords(f *testing.F) {
	f.Add([]byte{1, 0, 3, 15, 1, 2, 3})
	f.Add(append([]byte{0, 1, 13, 1, 0, 0, 14, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, []byte("\x07example\x00sig")...))
	f.Add([]byte("\x01a\x07example\x00\x00\x01\x40"))
	f.Add([]byte{1, 1, 0, 2, 1, 0xab, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 1, 0x40})
	f.Fuzz(func(t *testing.T, b []byte) {
		if k, err := ParseDNSKEY(b); err == nil {
			if !bytes.Equal(k.Rdata(), b) {
				t.Fatal("DNSKEY round trip")
			}
			_ = k.KeyTag()
			_ = verifySignature(k.Algorithm, k.PublicKey, b, b)
		}
		if d, err := ParseDS(b); err == nil && !bytes.Equal(d.Rdata(), b) {
			t.Fatal("DS round trip")
		}
		if s, err := ParseRRSIG(b); err == nil {
			rd, err := s.Rdata()
			if err != nil {
				t.Fatal(err)
			}
			s2, err := ParseRRSIG(rd)
			if err != nil || s2.SignerName != s.SignerName || !bytes.Equal(s2.Signature, s.Signature) {
				t.Fatal("RRSIG round trip")
			}
		}
		if n, err := ParseNSEC(b); err == nil {
			rd, err := n.Rdata()
			if err != nil {
				t.Fatal(err)
			}
			if n2, err := ParseNSEC(rd); err != nil || n2.NextName != n.NextName || len(n2.Types) != len(n.Types) {
				t.Fatal("NSEC round trip")
			}
			d := Denial{Zone: ".", NSEC: []NSECRecord{{Owner: "a.", NSEC: n}}}
			_ = d.NXDomain("b.a.")
			_, _ = d.NoDS(n.NextName)
		}
		if n, err := ParseNSEC3(b); err == nil {
			if n2, err := ParseNSEC3(n.Rdata()); err != nil || n2.Iterations != n.Iterations || !bytes.Equal(n2.NextHashed, n.NextHashed) {
				t.Fatal("NSEC3 round trip")
			}
			if n.Iterations <= 10 {
				d := Denial{Zone: "example.", NSEC3: []NSEC3Record{{Owner: strings.Repeat("0", 32) + ".example.", NSEC3: n}}}
				_ = d.NXDomain("x.example.")
				_ = d.NoData("example.", 1)
			}
		}
		if bm, err := parseBitmap(b); err == nil {
			if got, err := parseBitmap(packBitmap(bm)); err != nil || len(got) != len(bm) {
				t.Fatal("bitmap round trip")
			}
		}
		if name, _, err := readName(b, 0); err == nil {
			if _, err := nameWire(name); err != nil {
				t.Fatalf("read name %q does not encode: %v", name, err)
			}
		}
	})
}

// FuzzParseAnchors checks the owner's anchor file parser.
func FuzzParseAnchors(f *testing.F) {
	f.Add(". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")
	f.Add("; x\n. DS 1 13 4 00\n")
	f.Fuzz(func(t *testing.T, s string) {
		ds, err := ParseAnchors(strings.NewReader(s))
		if err == nil && len(ds) == 0 {
			t.Fatal("no anchors without error")
		}
	})
}
