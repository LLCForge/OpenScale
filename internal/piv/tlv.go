package piv

import (
	"errors"
)

// BER-TLV as the PIV applet uses it: one- or two-byte tags (a first byte
// with low five bits all set announces a second byte) and definite lengths
// of up to three bytes (0x81 xx, 0x82 xx xx).

// TLV is one decoded element.
type TLV struct {
	Tag   uint16
	Value []byte
}

const maxTLVLength = 0xFFFF

// appendTLV appends the encoding of tag and value to dst.
func appendTLV(dst []byte, tag uint16, value []byte) []byte {
	if tag > 0xFF {
		dst = append(dst, byte(tag>>8), byte(tag))
	} else {
		dst = append(dst, byte(tag))
	}
	n := len(value)
	switch {
	case n < 0x80:
		dst = append(dst, byte(n))
	case n <= 0xFF:
		dst = append(dst, 0x81, byte(n))
	default:
		dst = append(dst, 0x82, byte(n>>8), byte(n))
	}
	return append(dst, value...)
}

// tlv encodes one element.
func tlv(tag uint16, value []byte) []byte { return appendTLV(nil, tag, value) }

var errTLV = errors.New("malformed TLV data")

// parseTLVs decodes a sequence of elements that must exactly fill data.
func parseTLVs(data []byte) ([]TLV, error) {
	var out []TLV
	for len(data) > 0 {
		if len(out) >= 64 {
			return nil, errTLV
		}
		tag := uint16(data[0])
		data = data[1:]
		if tag&0x1F == 0x1F {
			if len(data) == 0 || data[0]&0x80 != 0 {
				return nil, errTLV // three-byte tags are not used by PIV
			}
			tag = tag<<8 | uint16(data[0])
			data = data[1:]
		}
		if len(data) == 0 {
			return nil, errTLV
		}
		n := int(data[0])
		data = data[1:]
		switch {
		case n < 0x80:
		case n == 0x81:
			if len(data) < 1 {
				return nil, errTLV
			}
			n = int(data[0])
			data = data[1:]
		case n == 0x82:
			if len(data) < 2 {
				return nil, errTLV
			}
			n = int(data[0])<<8 | int(data[1])
			data = data[2:]
		default:
			return nil, errTLV
		}
		if n > maxTLVLength || n > len(data) {
			return nil, errTLV
		}
		out = append(out, TLV{Tag: tag, Value: data[:n:n]})
		data = data[n:]
	}
	return out, nil
}

// findTLV returns the value of the first element with tag.
func findTLV(list []TLV, tag uint16) ([]byte, bool) {
	for _, t := range list {
		if t.Tag == tag {
			return t.Value, true
		}
	}
	return nil, false
}

// unwrapTLV parses data as exactly one element with tag and returns its
// value.
func unwrapTLV(data []byte, tag uint16) ([]byte, error) {
	list, err := parseTLVs(data)
	if err != nil {
		return nil, err
	}
	if len(list) != 1 || list[0].Tag != tag {
		return nil, errTLV
	}
	return list[0].Value, nil
}
