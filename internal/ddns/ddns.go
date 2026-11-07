// Package ddns updates the owner's own authoritative DNS server with the
// home address (RFC 2136 dynamic update signed with TSIG, RFC 8945; #449)
// and checks that a dynamic DNS name still points at the address devices
// really reach (#448). See ADR-0160.
//
// Nothing here has a built-in server or name: the owner gives the
// server's address, the zone, the name and the key. The only packets sent
// go to that server; there is no third-party DDNS service.
package ddns

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// DNS constants used here.
const (
	typeA    = 1
	typeSOA  = 6
	typeAAAA = 28
	typeTSIG = 250
	classIN  = 1
	classANY = 255

	opUpdate = 5

	rcodeNoError  = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeNotImp   = 4
	rcodeRefused  = 5
	rcodeYXDomain = 6
	rcodeYXRRSet  = 7
	rcodeNXRRSet  = 8
	rcodeNotAuth  = 9
	rcodeNotZone  = 10

	tsigBadSig  = 16
	tsigBadKey  = 17
	tsigBadTime = 18

	// DefaultFudge is the allowed clock difference in seconds.
	DefaultFudge = 300
	maxMessage   = 65535
)

// Algorithms (TSIG algorithm names).
const (
	HMACSHA256 = "hmac-sha256."
	HMACSHA512 = "hmac-sha512."
)

var (
	// ErrBadName is returned for names that are not valid DNS names.
	ErrBadName = errors.New("ddns: geçersiz DNS adı")
	// ErrBadKey is returned for unusable TSIG keys.
	ErrBadKey = errors.New("ddns: TSIG anahtarı geçersiz")
	// ErrUnsigned is returned when the server's answer is not signed with
	// the key (it cannot be trusted).
	ErrUnsigned = errors.New("ddns: sunucunun yanıtı anahtarla imzalı değil")
	// ErrBadResponse is returned for malformed or forged answers.
	ErrBadResponse = errors.New("ddns: sunucunun yanıtı geçersiz veya imzası tutmuyor")
)

// Key is a TSIG key shared with the authoritative server.
type Key struct {
	// Name is the key's name as configured on the server.
	Name string
	// Algorithm is HMACSHA256 or HMACSHA512.
	Algorithm string
	Secret    []byte
}

// ParseKey builds a key from the server's key definition; secret is the
// base64 text the server's key file holds.
func ParseKey(name, algorithm, secret string) (Key, error) {
	name = canonical(name)
	if _, err := nameWire(name); err != nil {
		return Key{}, fmt.Errorf("%w: anahtar adı", ErrBadKey)
	}
	alg := canonical(algorithm)
	if alg == "." {
		alg = HMACSHA256
	}
	if alg != HMACSHA256 && alg != HMACSHA512 {
		return Key{}, fmt.Errorf("%w: algoritma hmac-sha256 veya hmac-sha512 olmalı", ErrBadKey)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) < 16 || len(raw) > 128 {
		return Key{}, fmt.Errorf("%w: gizli değer 16-128 baytlık base64 olmalı", ErrBadKey)
	}
	return Key{Name: name, Algorithm: alg, Secret: raw}, nil
}

func (k Key) hash() func() hash.Hash {
	if k.Algorithm == HMACSHA512 {
		return sha512.New
	}
	return sha256.New
}

// canonical lowercases a name and makes it absolute.
func canonical(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// ValidName reports whether n is a host name usable in an update.
func ValidName(n string) bool {
	_, err := nameWire(canonical(n))
	return err == nil && canonical(n) != "."
}

// nameWire encodes an absolute name without compression.
func nameWire(n string) ([]byte, error) {
	if n == "." {
		return []byte{0}, nil
	}
	if !strings.HasSuffix(n, ".") || len(n) > 254 {
		return nil, ErrBadName
	}
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, ErrBadName
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c >= 'A' && c <= 'Z'
			if !ok || (c == '-' && (i == 0 || i == len(label)-1)) {
				return nil, ErrBadName
			}
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// inZone reports whether name is zone or below it.
func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone) || zone == "."
}

func rcodeText(rc int) string {
	switch rc {
	case rcodeFormErr:
		return "sunucu iletiyi anlamadı (FORMERR)"
	case rcodeServFail:
		return "sunucu hatası (SERVFAIL)"
	case rcodeNXDomain:
		return "ad yok (NXDOMAIN)"
	case rcodeNotImp:
		return "sunucu dinamik güncellemeyi desteklemiyor (NOTIMP)"
	case rcodeRefused:
		return "sunucu güncellemeyi reddetti (REFUSED); anahtarın bu ada izni olmalı"
	case rcodeYXDomain, rcodeYXRRSet, rcodeNXRRSet:
		return fmt.Sprintf("ön koşul tutmadı (%d)", rc)
	case rcodeNotAuth:
		return "sunucu bu bölge için yetkili değil veya anahtar tanınmadı (NOTAUTH)"
	case rcodeNotZone:
		return "ad bölgenin içinde değil (NOTZONE)"
	case tsigBadSig:
		return "imza tutmadı (BADSIG); anahtar gizli değeri farklı"
	case tsigBadKey:
		return "sunucu anahtarı tanımıyor (BADKEY)"
	case tsigBadTime:
		return "saat farkı çok büyük (BADTIME); iki cihazın saatini eşitleyin"
	}
	return fmt.Sprintf("sunucu hata kodu %d", rc)
}

// --- TSIG ---

type tsigVars struct {
	time   uint64
	fudge  uint16
	err    uint16
	other  []byte
	mac    []byte
	origID uint16
}

// variables are the TSIG fields covered by the MAC (RFC 8945 4.3.3).
func (k Key) variables(v tsigVars) []byte {
	kn, _ := nameWire(k.Name)
	an, _ := nameWire(k.Algorithm)
	b := append([]byte{}, kn...)
	b = binary.BigEndian.AppendUint16(b, classANY)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, an...)
	b = append(b, byte(v.time>>40), byte(v.time>>32), byte(v.time>>24), byte(v.time>>16), byte(v.time>>8), byte(v.time))
	b = binary.BigEndian.AppendUint16(b, v.fudge)
	b = binary.BigEndian.AppendUint16(b, v.err)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v.other)))
	return append(b, v.other...)
}

// tsigRR encodes the TSIG record.
func (k Key) tsigRR(v tsigVars) []byte {
	kn, _ := nameWire(k.Name)
	an, _ := nameWire(k.Algorithm)
	rd := append([]byte{}, an...)
	rd = append(rd, byte(v.time>>40), byte(v.time>>32), byte(v.time>>24), byte(v.time>>16), byte(v.time>>8), byte(v.time))
	rd = binary.BigEndian.AppendUint16(rd, v.fudge)
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(v.mac)))
	rd = append(rd, v.mac...)
	rd = binary.BigEndian.AppendUint16(rd, v.origID)
	rd = binary.BigEndian.AppendUint16(rd, v.err)
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(v.other)))
	rd = append(rd, v.other...)
	b := append([]byte{}, kn...)
	b = binary.BigEndian.AppendUint16(b, typeTSIG)
	b = binary.BigEndian.AppendUint16(b, classANY)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...)
}

// sign appends a TSIG record to msg (whose ARCOUNT does not count it yet)
// and returns the signed message and its MAC. prior is the request MAC
// when signing a response, nil for a request.
func (k Key) sign(msg, prior []byte, v tsigVars) ([]byte, []byte) {
	m := hmac.New(k.hash(), k.Secret)
	if prior != nil {
		_ = binary.Write(m, binary.BigEndian, uint16(len(prior)))
		m.Write(prior)
	}
	m.Write(msg)
	m.Write(k.variables(v))
	v.mac = m.Sum(nil)
	v.origID = binary.BigEndian.Uint16(msg[0:2])
	out := append(append([]byte{}, msg...), k.tsigRR(v)...)
	binary.BigEndian.PutUint16(out[10:12], binary.BigEndian.Uint16(out[10:12])+1)
	return out, v.mac
}

// --- parsing ---

// skipName returns the offset after the (possibly compressed) name at off.
func skipName(msg []byte, off int) (int, error) {
	for range 128 {
		if off >= len(msg) {
			return 0, ErrBadResponse
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, ErrBadResponse
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, ErrBadResponse
		}
		off += 1 + l
	}
	return 0, ErrBadResponse
}

// readName reads an uncompressed name at off (TSIG names are never
// compressed, RFC 8945 4.2).
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	for range 128 {
		if off >= len(msg) {
			return "", 0, ErrBadResponse
		}
		l := int(msg[off])
		if l == 0 {
			return strings.ToLower(strings.Join(labels, ".")) + ".", off + 1, nil
		}
		if l > 63 || off+1+l > len(msg) {
			return "", 0, ErrBadResponse
		}
		labels = append(labels, string(msg[off+1:off+1+l]))
		off += 1 + l
	}
	return "", 0, ErrBadResponse
}

type header struct {
	id, flags           uint16
	qd, an, ns, ar      int
	opcode, rcode       int
	response, truncated bool
}

func parseHeader(msg []byte) (header, error) {
	if len(msg) < 12 {
		return header{}, ErrBadResponse
	}
	h := header{id: binary.BigEndian.Uint16(msg[0:2]), flags: binary.BigEndian.Uint16(msg[2:4]),
		qd: int(binary.BigEndian.Uint16(msg[4:6])), an: int(binary.BigEndian.Uint16(msg[6:8])),
		ns: int(binary.BigEndian.Uint16(msg[8:10])), ar: int(binary.BigEndian.Uint16(msg[10:12]))}
	h.response = h.flags&0x8000 != 0
	h.opcode = int(h.flags>>11) & 0xf
	h.truncated = h.flags&0x0200 != 0
	h.rcode = int(h.flags & 0xf)
	return h, nil
}

// rr is a parsed resource record.
type rr struct {
	start, end int
	name       int // offset of the owner name
	typ, class uint16
	ttl        uint32
	rdata      []byte
}

// records walks every record after the header; questions (zone section)
// have no TTL or data.
func records(msg []byte, h header) (questions int, out []rr, err error) {
	off := 12
	for range h.qd {
		if off, err = skipName(msg, off); err != nil {
			return 0, nil, err
		}
		off += 4
		if off > len(msg) {
			return 0, nil, ErrBadResponse
		}
	}
	for range h.an + h.ns + h.ar {
		r := rr{start: off, name: off}
		if off, err = skipName(msg, off); err != nil {
			return 0, nil, err
		}
		if off+10 > len(msg) {
			return 0, nil, ErrBadResponse
		}
		r.typ = binary.BigEndian.Uint16(msg[off:])
		r.class = binary.BigEndian.Uint16(msg[off+2:])
		r.ttl = binary.BigEndian.Uint32(msg[off+4:])
		n := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+n > len(msg) {
			return 0, nil, ErrBadResponse
		}
		r.rdata = msg[off : off+n]
		off += n
		r.end = off
		out = append(out, r)
	}
	if off != len(msg) {
		return 0, nil, ErrBadResponse
	}
	return h.qd, out, nil
}

// parseTSIG reads the TSIG record's data.
func parseTSIG(rd []byte) (alg string, v tsigVars, err error) {
	alg, off, err := readName(rd, 0)
	if err != nil || off+10 > len(rd) {
		return "", v, ErrBadResponse
	}
	v.time = uint64(rd[off])<<40 | uint64(rd[off+1])<<32 | uint64(rd[off+2])<<24 | uint64(rd[off+3])<<16 | uint64(rd[off+4])<<8 | uint64(rd[off+5])
	v.fudge = binary.BigEndian.Uint16(rd[off+6:])
	macLen := int(binary.BigEndian.Uint16(rd[off+8:]))
	off += 10
	if off+macLen+6 > len(rd) {
		return "", v, ErrBadResponse
	}
	v.mac = rd[off : off+macLen]
	off += macLen
	v.origID = binary.BigEndian.Uint16(rd[off:])
	v.err = binary.BigEndian.Uint16(rd[off+2:])
	otherLen := int(binary.BigEndian.Uint16(rd[off+4:]))
	off += 6
	if off+otherLen != len(rd) {
		return "", v, ErrBadResponse
	}
	v.other = rd[off:]
	return alg, v, nil
}

// signedPart finds the trailing TSIG of msg and returns the message as it
// was before signing (ARCOUNT minus one, original ID) and the TSIG.
func signedPart(msg []byte, k Key) ([]byte, tsigVars, bool, error) {
	h, err := parseHeader(msg)
	if err != nil {
		return nil, tsigVars{}, false, err
	}
	_, rrs, err := records(msg, h)
	if err != nil {
		return nil, tsigVars{}, false, err
	}
	if len(rrs) == 0 || h.ar == 0 || rrs[len(rrs)-1].typ != typeTSIG {
		return nil, tsigVars{}, false, nil
	}
	last := rrs[len(rrs)-1]
	name, _, err := readName(msg, last.name)
	if err != nil || name != k.Name || last.class != classANY {
		return nil, tsigVars{}, true, ErrBadResponse
	}
	alg, v, err := parseTSIG(last.rdata)
	if err != nil || alg != k.Algorithm {
		return nil, tsigVars{}, true, ErrBadResponse
	}
	pre := append([]byte{}, msg[:last.start]...)
	binary.BigEndian.PutUint16(pre[0:2], v.origID)
	binary.BigEndian.PutUint16(pre[10:12], uint16(h.ar-1))
	return pre, v, true, nil
}

// verify checks a signed message's MAC; prior is the request MAC when
// msg is a response.
func (k Key) verify(msg, prior []byte, now uint64) (tsigVars, error) {
	pre, v, found, err := signedPart(msg, k)
	if err != nil {
		return v, err
	}
	if !found {
		return v, ErrUnsigned
	}
	if v.err != 0 {
		return v, fmt.Errorf("ddns: %s", rcodeText(int(v.err)))
	}
	m := hmac.New(k.hash(), k.Secret)
	if prior != nil {
		_ = binary.Write(m, binary.BigEndian, uint16(len(prior)))
		m.Write(prior)
	}
	m.Write(pre)
	m.Write(k.variables(v))
	if !hmac.Equal(m.Sum(nil), v.mac) {
		return v, ErrBadResponse
	}
	diff := int64(now) - int64(v.time)
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(v.fudge) {
		return v, fmt.Errorf("ddns: %s", rcodeText(tsigBadTime))
	}
	return v, nil
}
