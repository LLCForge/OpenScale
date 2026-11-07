package dbuswire

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

// encoder writes little-endian D-Bus data. base is the offset of buf[0]
// in the message, so alignment is computed against the message start.
type encoder struct {
	buf  []byte
	base int
}

func (e *encoder) pos() int { return e.base + len(e.buf) }

func (e *encoder) align(n int) {
	for e.pos()%n != 0 {
		e.buf = append(e.buf, 0)
	}
}

func (e *encoder) u8(v byte) { e.buf = append(e.buf, v) }

func (e *encoder) u16(v uint16) {
	e.align(2)
	e.buf = binary.LittleEndian.AppendUint16(e.buf, v)
}

func (e *encoder) u32(v uint32) {
	e.align(4)
	e.buf = binary.LittleEndian.AppendUint32(e.buf, v)
}

func (e *encoder) u64(v uint64) {
	e.align(8)
	e.buf = binary.LittleEndian.AppendUint64(e.buf, v)
}

func (e *encoder) str(s string) error {
	if !validString(s) {
		return fmt.Errorf("%w: dize UTF-8 değil veya NUL içeriyor", ErrValue)
	}
	e.u32(uint32(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0)
	return nil
}

func (e *encoder) sig(s Signature) error {
	if !ValidSignature(s) {
		return fmt.Errorf("%w: %q", ErrInvalidSignature, s)
	}
	e.buf = append(e.buf, byte(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0)
	return nil
}

// validString: valid UTF-8 without NUL (the specification's rule).
func validString(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false
		}
	}
	return true
}

func wrongType(sig string, v any) error {
	return fmt.Errorf("%w: %q için %T", ErrValue, sig, v)
}

// value encodes v as the single complete type sig.
func (e *encoder) value(sig string, v any, depth int) error {
	if depth > maxTotalDepth {
		return fmt.Errorf("%w: çok derin", ErrValue)
	}
	if len(e.buf) > MaxMessageSize {
		return ErrTooLarge
	}
	switch sig[0] {
	case 'y':
		b, ok := v.(byte)
		if !ok {
			return wrongType(sig, v)
		}
		e.u8(b)
	case 'b':
		b, ok := v.(bool)
		if !ok {
			return wrongType(sig, v)
		}
		var x uint32
		if b {
			x = 1
		}
		e.u32(x)
	case 'n':
		switch x := v.(type) {
		case int16:
			e.u16(uint16(x))
		case int:
			if !intIn(x, math.MinInt16, math.MaxInt16) {
				return wrongType(sig, v)
			}
			e.u16(uint16(int16(x)))
		default:
			return wrongType(sig, v)
		}
	case 'q':
		switch x := v.(type) {
		case uint16:
			e.u16(x)
		case int:
			if !intIn(x, 0, math.MaxUint16) {
				return wrongType(sig, v)
			}
			e.u16(uint16(x))
		default:
			return wrongType(sig, v)
		}
	case 'i':
		switch x := v.(type) {
		case int32:
			e.u32(uint32(x))
		case int:
			if !intIn(x, math.MinInt32, math.MaxInt32) {
				return wrongType(sig, v)
			}
			e.u32(uint32(int32(x)))
		default:
			return wrongType(sig, v)
		}
	case 'u':
		switch x := v.(type) {
		case uint32:
			e.u32(x)
		case int:
			if !intIn(x, 0, math.MaxUint32) {
				return wrongType(sig, v)
			}
			e.u32(uint32(x))
		default:
			return wrongType(sig, v)
		}
	case 'h':
		x, ok := v.(UnixFD)
		if !ok {
			return wrongType(sig, v)
		}
		e.u32(uint32(x))
	case 'x':
		switch x := v.(type) {
		case int64:
			e.u64(uint64(x))
		case int:
			e.u64(uint64(int64(x)))
		default:
			return wrongType(sig, v)
		}
	case 't':
		switch x := v.(type) {
		case uint64:
			e.u64(x)
		case int:
			if x < 0 {
				return wrongType(sig, v)
			}
			e.u64(uint64(x))
		default:
			return wrongType(sig, v)
		}
	case 'd':
		x, ok := v.(float64)
		if !ok {
			return wrongType(sig, v)
		}
		e.u64(math.Float64bits(x))
	case 's':
		x, ok := v.(string)
		if !ok {
			return wrongType(sig, v)
		}
		return e.str(x)
	case 'o':
		var p string
		switch x := v.(type) {
		case ObjectPath:
			p = string(x)
		case string:
			p = x
		default:
			return wrongType(sig, v)
		}
		if !ValidObjectPath(p) {
			return fmt.Errorf("%w: geçersiz nesne yolu %q", ErrValue, p)
		}
		return e.str(p)
	case 'g':
		switch x := v.(type) {
		case Signature:
			return e.sig(x)
		case string:
			return e.sig(Signature(x))
		}
		return wrongType(sig, v)
	case 'v':
		x, ok := v.(Variant)
		if !ok {
			return wrongType(sig, v)
		}
		if err := singleType(x.Sig); err != nil {
			return fmt.Errorf("%w: varyant: %v", ErrValue, err)
		}
		if err := e.sig(x.Sig); err != nil {
			return err
		}
		return e.value(string(x.Sig), x.Value, depth+1)
	case '(':
		var fields []any
		switch x := v.(type) {
		case Struct:
			fields = x
		case []any:
			fields = x
		default:
			return wrongType(sig, v)
		}
		parts, err := SplitSignature(Signature(sig[1 : len(sig)-1]))
		if err != nil {
			return err
		}
		if len(parts) != len(fields) {
			return fmt.Errorf("%w: yapı %q için %d alan", ErrValue, sig, len(fields))
		}
		e.align(8)
		for i, p := range parts {
			if err := e.value(p, fields[i], depth+1); err != nil {
				return err
			}
		}
	case 'a':
		return e.array(sig, v, depth)
	default:
		return fmt.Errorf("%w: %q", ErrInvalidSignature, sig)
	}
	return nil
}

// array encodes an array; elem is the element signature.
func (e *encoder) array(sig string, v any, depth int) error {
	elem := sig[1:]
	e.align(4)
	lenAt := len(e.buf)
	e.buf = append(e.buf, 0, 0, 0, 0)
	e.align(alignment(elem[0]))
	start := len(e.buf)
	each := func(n int, item func(i int) error) error {
		for i := 0; i < n; i++ {
			if err := item(i); err != nil {
				return err
			}
		}
		return nil
	}
	var err error
	if elem[0] == '{' {
		parts, perr := SplitSignature(Signature(elem[1 : len(elem)-1]))
		if perr != nil {
			return perr
		}
		kSig, vSig := parts[0], parts[1]
		entry := func(k, val any) error {
			e.align(8)
			if err := e.value(kSig, k, depth+1); err != nil {
				return err
			}
			return e.value(vSig, val, depth+1)
		}
		switch x := v.(type) {
		case []DictEntry:
			err = each(len(x), func(i int) error { return entry(x[i].Key, x[i].Value) })
		case map[string]Variant:
			if kSig != "s" || vSig != "v" {
				return wrongType(sig, v)
			}
			keys := sortedKeys(x)
			err = each(len(keys), func(i int) error { return entry(keys[i], x[keys[i]]) })
		case map[string]string:
			if kSig != "s" || vSig != "s" {
				return wrongType(sig, v)
			}
			keys := make(map[string]Variant, len(x))
			for k := range x {
				keys[k] = Variant{}
			}
			order := sortedKeys(keys)
			err = each(len(order), func(i int) error { return entry(order[i], x[order[i]]) })
		default:
			return wrongType(sig, v)
		}
	} else {
		switch x := v.(type) {
		case []any:
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		case []byte:
			if elem != "y" {
				return wrongType(sig, v)
			}
			e.buf = append(e.buf, x...)
		case []string:
			if elem != "s" && elem != "o" && elem != "g" {
				return wrongType(sig, v)
			}
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		case []ObjectPath:
			if elem != "o" {
				return wrongType(sig, v)
			}
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		case []int32:
			if elem != "i" {
				return wrongType(sig, v)
			}
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		case []uint32:
			if elem != "u" {
				return wrongType(sig, v)
			}
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		case []Variant:
			if elem != "v" {
				return wrongType(sig, v)
			}
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		case []Struct:
			if elem[0] != '(' {
				return wrongType(sig, v)
			}
			err = each(len(x), func(i int) error { return e.value(elem, x[i], depth+1) })
		default:
			return wrongType(sig, v)
		}
	}
	if err != nil {
		return err
	}
	n := len(e.buf) - start
	if n > MaxMessageSize {
		return ErrTooLarge
	}
	binary.LittleEndian.PutUint32(e.buf[lenAt:], uint32(n))
	return nil
}

// encodeBody encodes values as the body signature sig (offset 0, which
// is 8-aligned in the message).
func encodeBody(sig Signature, values []any) ([]byte, error) {
	parts, err := SplitSignature(sig)
	if err != nil {
		return nil, err
	}
	if len(parts) != len(values) {
		return nil, fmt.Errorf("%w: imza %q için %d değer", ErrValue, sig, len(values))
	}
	e := &encoder{}
	for i, p := range parts {
		if err := e.value(p, values[i], 0); err != nil {
			return nil, err
		}
	}
	if len(e.buf) > MaxMessageSize {
		return nil, ErrTooLarge
	}
	return e.buf, nil
}

// MarshalBody encodes values as a message body of signature sig, the
// way a reply or signal would carry them; it checks that values fit.
func MarshalBody(sig Signature, values ...any) ([]byte, error) { return encodeBody(sig, values) }
