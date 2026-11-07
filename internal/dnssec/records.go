package dnssec

import (
	"encoding/binary"
	"slices"
)

// DNSKEY flag bits (RFC 4034 2.1.1, RFC 5011 2.1).
const (
	FlagZone   uint16 = 0x0100
	FlagRevoke uint16 = 0x0080
	FlagSEP    uint16 = 0x0001
)

// maxRecordData bounds the record data this package parses.
const maxRecordData = 65535

// DNSKEY is a zone's public key.
type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

// ParseDNSKEY parses DNSKEY record data.
func ParseDNSKEY(rdata []byte) (DNSKEY, error) {
	if len(rdata) < 5 || len(rdata) > maxRecordData {
		return DNSKEY{}, ErrMalformed
	}
	return DNSKEY{
		Flags:     binary.BigEndian.Uint16(rdata),
		Protocol:  rdata[2],
		Algorithm: rdata[3],
		PublicKey: slices.Clone(rdata[4:]),
	}, nil
}

// Rdata returns the record data.
func (k DNSKEY) Rdata() []byte {
	out := make([]byte, 4, 4+len(k.PublicKey))
	binary.BigEndian.PutUint16(out, k.Flags)
	out[2], out[3] = k.Protocol, k.Algorithm
	return append(out, k.PublicKey...)
}

// KeyTag computes the key tag (RFC 4034 appendix B; algorithm 1 is not
// supported and needs no special case).
func (k DNSKEY) KeyTag() uint16 {
	var ac uint32
	for i, b := range k.Rdata() {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// usable reports a key that may verify zone data: zone key, protocol 3,
// not revoked (RFC 4035 5.3.1, RFC 5011 2.1).
func (k DNSKEY) usable() bool {
	return k.Flags&FlagZone != 0 && k.Flags&FlagRevoke == 0 && k.Protocol == 3
}

// Usable is the exported form of usable.
func (k DNSKEY) Usable() bool { return k.usable() }

// DS is a delegation signer record.
type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// ParseDS parses DS record data.
func ParseDS(rdata []byte) (DS, error) {
	if len(rdata) < 5 || len(rdata) > maxRecordData {
		return DS{}, ErrMalformed
	}
	d := DS{
		KeyTag:     binary.BigEndian.Uint16(rdata),
		Algorithm:  rdata[2],
		DigestType: rdata[3],
		Digest:     slices.Clone(rdata[4:]),
	}
	switch d.DigestType {
	case DigestSHA1:
		if len(d.Digest) != 20 {
			return DS{}, ErrMalformed
		}
	case DigestSHA256:
		if len(d.Digest) != 32 {
			return DS{}, ErrMalformed
		}
	case DigestSHA384:
		if len(d.Digest) != 48 {
			return DS{}, ErrMalformed
		}
	}
	return d, nil
}

// Rdata returns the record data.
func (d DS) Rdata() []byte {
	out := make([]byte, 4, 4+len(d.Digest))
	binary.BigEndian.PutUint16(out, d.KeyTag)
	out[2], out[3] = d.Algorithm, d.DigestType
	return append(out, d.Digest...)
}

// Supported reports whether the DS can lead to a validated key.
func (d DS) Supported() bool { return SupportedAlgorithm(d.Algorithm) && SupportedDigest(d.DigestType) }

// RRSIG is a signature over one RRset.
type RRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

// ParseRRSIG parses RRSIG record data.
func ParseRRSIG(rdata []byte) (RRSIG, error) {
	if len(rdata) < 19 || len(rdata) > maxRecordData {
		return RRSIG{}, ErrMalformed
	}
	s := RRSIG{
		TypeCovered: binary.BigEndian.Uint16(rdata[0:]),
		Algorithm:   rdata[2],
		Labels:      rdata[3],
		OrigTTL:     binary.BigEndian.Uint32(rdata[4:]),
		Expiration:  binary.BigEndian.Uint32(rdata[8:]),
		Inception:   binary.BigEndian.Uint32(rdata[12:]),
		KeyTag:      binary.BigEndian.Uint16(rdata[16:]),
	}
	name, off, err := readName(rdata, 18)
	if err != nil {
		return RRSIG{}, err
	}
	if off >= len(rdata) {
		return RRSIG{}, ErrMalformed
	}
	s.SignerName = name
	s.Signature = slices.Clone(rdata[off:])
	return s, nil
}

// signedPrefix is the record data without the signature, the signer name
// in canonical form (RFC 4034 3.1.8.1).
func (s RRSIG) signedPrefix() ([]byte, error) {
	signer, err := nameWire(s.SignerName)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 18, 18+len(signer)+len(s.Signature))
	binary.BigEndian.PutUint16(out[0:], s.TypeCovered)
	out[2], out[3] = s.Algorithm, s.Labels
	binary.BigEndian.PutUint32(out[4:], s.OrigTTL)
	binary.BigEndian.PutUint32(out[8:], s.Expiration)
	binary.BigEndian.PutUint32(out[12:], s.Inception)
	binary.BigEndian.PutUint16(out[16:], s.KeyTag)
	return append(out, signer...), nil
}

// Rdata returns the record data.
func (s RRSIG) Rdata() ([]byte, error) {
	p, err := s.signedPrefix()
	if err != nil {
		return nil, err
	}
	return append(p, s.Signature...), nil
}

// TypeBitmap is the set of types of an NSEC or NSEC3 record.
type TypeBitmap []uint16

// Has reports whether t is in the set.
func (b TypeBitmap) Has(t uint16) bool {
	_, ok := slices.BinarySearch(b, t)
	return ok
}

// parseBitmap parses type bit maps (RFC 4034 4.1.2): windows in increasing
// order, each 1 to 32 bytes long.
func parseBitmap(b []byte) (TypeBitmap, error) {
	var out TypeBitmap
	last := -1
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, ErrMalformed
		}
		win, n := int(b[0]), int(b[1])
		if win <= last || n < 1 || n > 32 || len(b) < 2+n {
			return nil, ErrMalformed
		}
		last = win
		for i, octet := range b[2 : 2+n] {
			for bit := 0; bit < 8; bit++ {
				if octet&(0x80>>bit) != 0 {
					out = append(out, uint16(win<<8|i*8+bit))
				}
			}
		}
		b = b[2+n:]
	}
	return out, nil
}

// packBitmap is the inverse of parseBitmap.
func packBitmap(types []uint16) []byte {
	t := slices.Clone(types)
	slices.Sort(t)
	t = slices.Compact(t)
	var out []byte
	for i := 0; i < len(t); {
		win := t[i] >> 8
		var bits [32]byte
		n := 0
		for ; i < len(t) && t[i]>>8 == win; i++ {
			lo := t[i] & 0xFF
			bits[lo/8] |= 0x80 >> (lo % 8)
			n = int(lo/8) + 1
		}
		out = append(out, byte(win), byte(n))
		out = append(out, bits[:n]...)
	}
	return out
}

// NSEC proves which names and types exist in a zone.
type NSEC struct {
	NextName string
	Types    TypeBitmap
}

// ParseNSEC parses NSEC record data.
func ParseNSEC(rdata []byte) (NSEC, error) {
	if len(rdata) > maxRecordData {
		return NSEC{}, ErrMalformed
	}
	next, off, err := readName(rdata, 0)
	if err != nil {
		return NSEC{}, err
	}
	types, err := parseBitmap(rdata[off:])
	if err != nil {
		return NSEC{}, err
	}
	return NSEC{NextName: next, Types: types}, nil
}

// Rdata returns the record data.
func (n NSEC) Rdata() ([]byte, error) {
	w, err := nameWire(n.NextName)
	if err != nil {
		return nil, err
	}
	return append(w, packBitmap(n.Types)...), nil
}

// NSEC3 flags.
const NSEC3OptOut uint8 = 0x01

// NSEC3 is hashed denial of existence (RFC 5155).
type NSEC3 struct {
	HashAlgorithm uint8
	Flags         uint8
	Iterations    uint16
	Salt          []byte
	NextHashed    []byte
	Types         TypeBitmap
}

// ParseNSEC3 parses NSEC3 record data.
func ParseNSEC3(rdata []byte) (NSEC3, error) {
	if len(rdata) < 6 || len(rdata) > maxRecordData {
		return NSEC3{}, ErrMalformed
	}
	n := NSEC3{HashAlgorithm: rdata[0], Flags: rdata[1], Iterations: binary.BigEndian.Uint16(rdata[2:])}
	sl := int(rdata[4])
	off := 5
	if off+sl+1 > len(rdata) {
		return NSEC3{}, ErrMalformed
	}
	n.Salt = slices.Clone(rdata[off : off+sl])
	off += sl
	hl := int(rdata[off])
	off++
	if hl == 0 || off+hl > len(rdata) {
		return NSEC3{}, ErrMalformed
	}
	n.NextHashed = slices.Clone(rdata[off : off+hl])
	off += hl
	types, err := parseBitmap(rdata[off:])
	if err != nil {
		return NSEC3{}, err
	}
	n.Types = types
	return n, nil
}

// Rdata returns the record data.
func (n NSEC3) Rdata() []byte {
	out := []byte{n.HashAlgorithm, n.Flags, byte(n.Iterations >> 8), byte(n.Iterations), byte(len(n.Salt))}
	out = append(out, n.Salt...)
	out = append(out, byte(len(n.NextHashed)))
	out = append(out, n.NextHashed...)
	return append(out, packBitmap(n.Types)...)
}
