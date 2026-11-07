package plugin

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"
)

// ABI version 1 (docs/eklenti-abi.md). A module exports:
//
//	memory                        its linear memory
//	osp_abi_version() -> i32      must return ABIVersion
//	osp_buffer() -> i32           offset of a BufferSize-byte exchange area
//	osp_dns_query(len i32) -> i32           (hook dns)
//	osp_http_location(len i32) -> i32       (hook http_location)
//
// The host writes the request at the buffer and passes its length; the
// hook writes its answer at the buffer and returns its length, or a
// negative number to report its own failure. The module imports nothing.
const (
	ABIVersion = 1
	BufferSize = 8192

	exportMemory  = "memory"
	exportVersion = "osp_abi_version"
	exportBuffer  = "osp_buffer"
	exportDNS     = "osp_dns_query"
	exportHTTP    = "osp_http_location"
)

// Request limits.
const (
	MaxNameLen    = 253
	MaxClientTags = 16
	MaxTagLen     = 63
	MaxURLLen     = 4096
)

// DNS verdicts, also the first output byte of osp_dns_query.
type Verdict uint8

const (
	VerdictPass    Verdict = 0 // no opinion
	VerdictAllow   Verdict = 1
	VerdictBlock   Verdict = 2
	VerdictRewrite Verdict = 3 // answer with Addr
)

func (v Verdict) String() string {
	switch v {
	case VerdictPass:
		return "pass"
	case VerdictAllow:
		return "allow"
	case VerdictBlock:
		return "block"
	case VerdictRewrite:
		return "rewrite"
	}
	return "unknown"
}

const (
	qtypeA    = 1
	qtypeAAAA = 28
)

// normalizeName lowercases a query name and drops one trailing dot. It
// refuses what is not a plain host name.
func normalizeName(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > MaxNameLen {
		return "", false
	}
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + 'a' - 'A'
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return "", false
		}
	}
	return string(b), true
}

func validTag(t string) bool {
	if len(t) == 0 || len(t) > MaxTagLen {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= ' ' || t[i] >= 0x7f {
			return false
		}
	}
	return true
}

// encodeDNS: [0]=1, [1:3]=qtype LE, [3:5]=name length LE, name,
// tag count (1 byte), each tag as length (1 byte) and bytes. The tag count
// is 0 unless the plugin declared client_tags.
func encodeDNS(name string, qtype uint16, tags []string) []byte {
	b := make([]byte, 0, 6+len(name)+len(tags)*(MaxTagLen+1))
	b = append(b, ABIVersion)
	b = binary.LittleEndian.AppendUint16(b, qtype)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = append(b, byte(len(tags)))
	for _, t := range tags {
		b = append(b, byte(len(t)))
		b = append(b, t...)
	}
	return b
}

var errBadOutput = errors.New("plugin: malformed output")

// decodeDNS: [0]=verdict; for rewrite [1]=4 or 6 and the address, which
// must fit the query type. Nothing may follow.
func decodeDNS(out []byte, qtype uint16) (Verdict, netip.Addr, error) {
	if len(out) < 1 {
		return 0, netip.Addr{}, errBadOutput
	}
	v := Verdict(out[0])
	switch v {
	case VerdictPass, VerdictAllow, VerdictBlock:
		if len(out) != 1 {
			return 0, netip.Addr{}, errBadOutput
		}
		return v, netip.Addr{}, nil
	case VerdictRewrite:
		if len(out) == 6 && out[1] == 4 && qtype == qtypeA {
			return v, netip.AddrFrom4([4]byte(out[2:6])), nil
		}
		if len(out) == 18 && out[1] == 6 && qtype == qtypeAAAA {
			a := netip.AddrFrom16([16]byte(out[2:18]))
			if a.Is4In6() {
				return 0, netip.Addr{}, errBadOutput
			}
			return v, a, nil
		}
	}
	return 0, netip.Addr{}, errBadOutput
}

// encodeHTTP: [0]=1, [1:3]=URL length LE, URL.
func encodeHTTP(u string) []byte {
	b := make([]byte, 0, 3+len(u))
	b = append(b, ABIVersion)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(u)))
	return append(b, u...)
}

// decodeHTTP: [0]=0 unchanged, or [0]=1, [1:3]=length LE, new URL.
func decodeHTTP(out []byte) (string, bool, error) {
	if len(out) == 1 && out[0] == 0 {
		return "", false, nil
	}
	if len(out) < 3 || out[0] != 1 {
		return "", false, errBadOutput
	}
	n := int(binary.LittleEndian.Uint16(out[1:3]))
	if len(out) != 3+n {
		return "", false, errBadOutput
	}
	return string(out[3:]), true, nil
}

// checkLocation accepts an absolute http or https URL without spaces or
// control characters.
func checkLocation(s string) (*url.URL, bool) {
	if len(s) == 0 || len(s) > MaxURLLen || !utf8.ValidString(s) {
		return nil, false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return nil, false
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
		return nil, false
	}
	return u, true
}

// sameTarget reports whether a plugin's new Location keeps the origin of
// the old one: same host and port and user info, same scheme or an
// upgrade from http to https. A plugin may clean a URL, never send the
// browser elsewhere.
func sameTarget(old, nu *url.URL) bool {
	if !strings.EqualFold(old.Host, nu.Host) || old.User.String() != nu.User.String() {
		return false
	}
	return old.Scheme == nu.Scheme || old.Scheme == "http" && nu.Scheme == "https" && old.Port() == ""
}
