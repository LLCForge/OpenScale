// Package dnssec validates DNSSEC signatures (RFC 4033-4035, 5155, 6840)
// for the exit node's recursive resolver (#89, ADR-0102). It knows the
// record formats, the canonical form, signature and DS verification for
// the algorithms the standard library implements, and NSEC/NSEC3 denial of
// existence proofs. It does no I/O; the resolver fetches the records.
//
// Names are absolute presentation strings with the trailing dot, as
// dnsmessage.Name.String returns them ("www.example.com."); labels never
// contain dots (dnsmessage rejects them and so does this package).
package dnssec

import (
	"bytes"
	"errors"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Record types of DNSSEC.
const (
	TypeDS         dnsmessage.Type = 43
	TypeRRSIG      dnsmessage.Type = 46
	TypeNSEC       dnsmessage.Type = 47
	TypeDNSKEY     dnsmessage.Type = 48
	TypeNSEC3      dnsmessage.Type = 50
	TypeNSEC3PARAM dnsmessage.Type = 51
)

// Algorithm numbers (RFC 8624).
const (
	AlgRSASHA1         uint8 = 5
	AlgRSASHA1NSEC3    uint8 = 7
	AlgRSASHA256       uint8 = 8
	AlgRSASHA512       uint8 = 10
	AlgECDSAP256SHA256 uint8 = 13
	AlgECDSAP384SHA384 uint8 = 14
	AlgED25519         uint8 = 15
	AlgED448           uint8 = 16
)

// DS digest types.
const (
	DigestSHA1   uint8 = 1
	DigestSHA256 uint8 = 2
	DigestSHA384 uint8 = 4
)

// SupportedAlgorithm reports whether signatures of alg are verified. SHA-1
// algorithms (5, 7) are deliberately not: a zone signed only with them is
// treated as unsigned ("insecure"), never as validated (RFC 9905 direction,
// ADR-0102). Ed448 is not in the standard library.
func SupportedAlgorithm(alg uint8) bool {
	switch alg {
	case AlgRSASHA256, AlgRSASHA512, AlgECDSAP256SHA256, AlgECDSAP384SHA384, AlgED25519:
		return true
	}
	return false
}

// SupportedDigest reports whether DS records of digest type dt are used.
// SHA-1 DS records are ignored like SHA-1 algorithms.
func SupportedDigest(dt uint8) bool { return dt == DigestSHA256 || dt == DigestSHA384 }

// Errors.
var (
	ErrMalformed            = errors.New("dnssec: malformed record")
	ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")
	ErrBadSignature         = errors.New("dnssec: signature does not verify")
	ErrSignatureTime        = errors.New("dnssec: signature is outside its validity period")
	ErrKeyMismatch          = errors.New("dnssec: key does not match the signature")
	ErrRRset                = errors.New("dnssec: invalid RRset")
)

// maxNameWire is the longest name in wire form (RFC 1035 3.1).
const maxNameWire = 255

// CanonicalName lowercases ASCII letters and adds the trailing dot.
func CanonicalName(name string) string {
	if name == "" {
		return "."
	}
	b := []byte(name)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	if b[len(b)-1] != '.' {
		b = append(b, '.')
	}
	return string(b)
}

// labels splits an absolute name into its labels (none for the root).
func labels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// LabelCount is the RRSIG "labels" value of name: the number of labels
// without the root and without a leading wildcard (RFC 4034 3.1.3).
func LabelCount(name string) int {
	l := labels(name)
	if len(l) > 0 && l[0] == "*" {
		return len(l) - 1
	}
	return len(l)
}

// lastLabels returns the absolute name made of the last n labels.
func lastLabels(name string, n int) string {
	l := labels(name)
	if n <= 0 {
		return "."
	}
	if n >= len(l) {
		return CanonicalName(name)
	}
	return strings.Join(l[len(l)-n:], ".") + "."
}

// parent returns the name one label shorter ("." for a TLD and the root).
func parent(name string) string {
	l := labels(name)
	if len(l) <= 1 {
		return "."
	}
	return strings.Join(l[1:], ".") + "."
}

// IsSubdomain reports whether name equals zone or lies below it, without
// regard to case.
func IsSubdomain(name, zone string) bool {
	name, zone = CanonicalName(name), CanonicalName(zone)
	return zone == "." || name == zone || strings.HasSuffix(name, "."+zone)
}

// isProperSubdomain reports name strictly below zone.
func isProperSubdomain(name, zone string) bool {
	return IsSubdomain(name, zone) && CanonicalName(name) != CanonicalName(zone)
}

// nameWire is the uncompressed, lowercased wire form of an absolute name.
func nameWire(name string) ([]byte, error) {
	name = CanonicalName(name)
	out := make([]byte, 0, len(name)+1)
	for _, l := range labels(name) {
		if l == "" || len(l) > 63 {
			return nil, ErrMalformed
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	if len(out) > maxNameWire {
		return nil, ErrMalformed
	}
	return out, nil
}

// readName reads an uncompressed wire name at off and returns it in
// canonical presentation form. Compression pointers are refused: DNSSEC
// record data never uses them (RFC 4034 3.1.7, 4.1.1).
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	total := 0
	for {
		if off >= len(b) {
			return "", 0, ErrMalformed
		}
		n := int(b[off])
		off++
		total++
		if n == 0 {
			break
		}
		if n > 63 || off+n > len(b) {
			return "", 0, ErrMalformed
		}
		total += n
		if total > maxNameWire {
			return "", 0, ErrMalformed
		}
		for _, c := range b[off : off+n] {
			if c == '.' {
				return "", 0, ErrMalformed
			}
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			sb.WriteByte(c)
		}
		sb.WriteByte('.')
		off += n
	}
	if sb.Len() == 0 {
		return ".", off, nil
	}
	return sb.String(), off, nil
}

// lowerLabel returns the label with ASCII letters lowercased.
func lowerLabel(l string) []byte {
	b := []byte(l)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return b
}

// CompareNames orders names canonically (RFC 4034 6.1): label by label
// from the right, each label as lowercase bytes. It returns -1, 0 or 1.
func CompareNames(a, b string) int {
	la, lb := labels(a), labels(b)
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		if c := bytes.Compare(lowerLabel(la[len(la)-i]), lowerLabel(lb[len(lb)-i])); c != 0 {
			return c
		}
	}
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	}
	return 0
}

// commonAncestor is the longest name both a and b are equal to or below.
func commonAncestor(a, b string) string {
	la, lb := labels(CanonicalName(a)), labels(CanonicalName(b))
	n := 0
	for n < len(la) && n < len(lb) && la[len(la)-1-n] == lb[len(lb)-1-n] {
		n++
	}
	return lastLabels(a, n)
}
