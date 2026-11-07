package dnssec

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// RR is one resource record with its data in canonical wire form.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Rdata []byte
}

// FromResource converts a parsed record to canonical form: names inside
// the data uncompressed and, for the types RFC 4034 6.2 lists (and
// dnsmessage parses), lowercased.
func FromResource(r dnsmessage.Resource) (RR, error) {
	rdata, err := packRdata(r)
	if err != nil {
		return RR{}, err
	}
	switch r.Header.Type {
	case dnsmessage.TypeNS, dnsmessage.TypeCNAME, dnsmessage.TypePTR:
		err = lowerWireName(rdata, 0)
	case dnsmessage.TypeMX:
		err = lowerWireName(rdata, 2)
	case dnsmessage.TypeSRV:
		err = lowerWireName(rdata, 6)
	case dnsmessage.TypeSOA:
		var off int
		if off, err = skipLowerName(rdata, 0); err == nil {
			err = lowerWireName(rdata, off)
		}
	}
	if err != nil {
		return RR{}, err
	}
	return RR{
		Name:  CanonicalName(r.Header.Name.String()),
		Type:  uint16(r.Header.Type),
		Class: uint16(r.Header.Class),
		TTL:   r.Header.TTL,
		Rdata: rdata,
	}, nil
}

// packRdata returns the uncompressed wire data of r: the record is built
// alone into a message without name compression and cut out again.
func packRdata(r dnsmessage.Resource) ([]byte, error) {
	if u, ok := r.Body.(*dnsmessage.UnknownResource); ok {
		return slices.Clone(u.Data), nil
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{})
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	h := r.Header
	var err error
	switch body := r.Body.(type) {
	case *dnsmessage.AResource:
		err = b.AResource(h, *body)
	case *dnsmessage.AAAAResource:
		err = b.AAAAResource(h, *body)
	case *dnsmessage.NSResource:
		err = b.NSResource(h, *body)
	case *dnsmessage.CNAMEResource:
		err = b.CNAMEResource(h, *body)
	case *dnsmessage.PTRResource:
		err = b.PTRResource(h, *body)
	case *dnsmessage.MXResource:
		err = b.MXResource(h, *body)
	case *dnsmessage.SOAResource:
		err = b.SOAResource(h, *body)
	case *dnsmessage.SRVResource:
		err = b.SRVResource(h, *body)
	case *dnsmessage.TXTResource:
		err = b.TXTResource(h, *body)
	case *dnsmessage.SVCBResource:
		err = b.SVCBResource(h, *body)
	case *dnsmessage.HTTPSResource:
		err = b.HTTPSResource(h, *body)
	default:
		return nil, ErrRRset
	}
	if err != nil {
		return nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	// Header (12 bytes), then the owner name, type, class, TTL, length.
	off, err := skipName(msg, 12)
	if err != nil {
		return nil, err
	}
	if off+10 > len(msg) {
		return nil, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if off+n != len(msg) {
		return nil, ErrMalformed
	}
	return slices.Clone(msg[off:]), nil
}

// skipName returns the offset after an uncompressed wire name.
func skipName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, ErrMalformed
		}
		n := int(b[off])
		if n&0xC0 != 0 {
			return 0, ErrMalformed
		}
		off++
		if n == 0 {
			return off, nil
		}
		off += n
	}
}

// skipLowerName lowercases the name at off and returns the offset after it.
func skipLowerName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, ErrMalformed
		}
		n := int(b[off])
		if n&0xC0 != 0 {
			return 0, ErrMalformed
		}
		off++
		if n == 0 {
			return off, nil
		}
		if off+n > len(b) {
			return 0, ErrMalformed
		}
		for i := off; i < off+n; i++ {
			if 'A' <= b[i] && b[i] <= 'Z' {
				b[i] += 'a' - 'A'
			}
		}
		off += n
	}
}

func lowerWireName(b []byte, off int) error {
	_, err := skipLowerName(b, off)
	return err
}

// signedData builds the data an RRSIG signs (RFC 4034 3.1.8.1, 6.2, 6.3):
// the RRSIG fields, then every record of the set with the owner in
// canonical form (wildcard owner when the signature says so), the
// original TTL, sorted by data, duplicates removed.
func signedData(sig RRSIG, rrset []RR) ([]byte, error) {
	if len(rrset) == 0 {
		return nil, ErrRRset
	}
	owner := CanonicalName(rrset[0].Name)
	for _, rr := range rrset {
		if CanonicalName(rr.Name) != owner || rr.Type != rrset[0].Type || rr.Class != rrset[0].Class {
			return nil, ErrRRset
		}
	}
	if rrset[0].Type != sig.TypeCovered {
		return nil, ErrRRset
	}
	n := LabelCount(owner)
	if int(sig.Labels) > n {
		return nil, ErrRRset
	}
	if int(sig.Labels) < n {
		owner = "*." + strings.TrimPrefix(lastLabels(owner, int(sig.Labels)), ".")
		if sig.Labels == 0 {
			owner = "*."
		}
	}
	ownerWire, err := nameWire(owner)
	if err != nil {
		return nil, err
	}
	prefix, err := sig.signedPrefix()
	if err != nil {
		return nil, err
	}
	datas := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		if len(rr.Rdata) > maxRecordData {
			return nil, ErrRRset
		}
		datas = append(datas, rr.Rdata)
	}
	slices.SortFunc(datas, bytes.Compare)
	datas = slices.CompactFunc(datas, bytes.Equal)
	out := prefix
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:], rrset[0].Type)
	binary.BigEndian.PutUint16(fixed[2:], rrset[0].Class)
	binary.BigEndian.PutUint32(fixed[4:], sig.OrigTTL)
	for _, d := range datas {
		out = append(out, ownerWire...)
		binary.BigEndian.PutUint16(fixed[8:], uint16(len(d)))
		out = append(out, fixed[:]...)
		out = append(out, d...)
	}
	return out, nil
}
