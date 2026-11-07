package dbuswire

import (
	"encoding/binary"
	"math"
)

// decoder reads D-Bus data from b. base is the offset of b[0] in the
// message (alignment is relative to the message start). Every read is
// bounds checked; padding must be zero.
type decoder struct {
	b      []byte
	off    int
	base   int
	order  binary.ByteOrder
	values int
}

func (d *decoder) pos() int { return d.base + d.off }

func (d *decoder) align(n int) error {
	for d.pos()%n != 0 {
		if d.off >= len(d.b) {
			return malformed("hizalama verinin dışında")
		}
		if d.b[d.off] != 0 {
			return malformed("dolgu baytı sıfır değil")
		}
		d.off++
	}
	return nil
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(d.b)-d.off {
		return nil, malformed("veri kısa")
	}
	out := d.b[d.off : d.off+n]
	d.off += n
	return out, nil
}

func (d *decoder) u8() (byte, error) {
	b, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (d *decoder) u16() (uint16, error) {
	if err := d.align(2); err != nil {
		return 0, err
	}
	b, err := d.take(2)
	if err != nil {
		return 0, err
	}
	return d.order.Uint16(b), nil
}

func (d *decoder) u32() (uint32, error) {
	if err := d.align(4); err != nil {
		return 0, err
	}
	b, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return d.order.Uint32(b), nil
}

func (d *decoder) u64() (uint64, error) {
	if err := d.align(8); err != nil {
		return 0, err
	}
	b, err := d.take(8)
	if err != nil {
		return 0, err
	}
	return d.order.Uint64(b), nil
}

func (d *decoder) str() (string, error) {
	n, err := d.u32()
	if err != nil {
		return "", err
	}
	if n > uint32(len(d.b)) {
		return "", malformed("dize uzunluğu veriden büyük")
	}
	b, err := d.take(int(n) + 1)
	if err != nil {
		return "", err
	}
	if b[n] != 0 {
		return "", malformed("dize NUL ile bitmiyor")
	}
	s := string(b[:n])
	if !validString(s) {
		return "", malformed("dize UTF-8 değil veya NUL içeriyor")
	}
	return s, nil
}

func (d *decoder) signature() (Signature, error) {
	n, err := d.u8()
	if err != nil {
		return "", err
	}
	b, err := d.take(int(n) + 1)
	if err != nil {
		return "", err
	}
	if b[n] != 0 {
		return "", malformed("imza NUL ile bitmiyor")
	}
	s := Signature(b[:n])
	if !ValidSignature(s) {
		return "", malformed("geçersiz imza %q", s)
	}
	return s, nil
}

func (d *decoder) count() error {
	d.values++
	if d.values > maxValues {
		return malformed("çok fazla değer")
	}
	return nil
}

// value decodes the single complete type sig. arrays, structs and depth
// count the containers around it (variants add to depth only).
func (d *decoder) value(sig string, arrays, structs, depth int) (any, error) {
	if depth > maxTotalDepth || arrays > maxArrayDepth || structs > maxStructDepth {
		return nil, malformed("çok derin")
	}
	if err := d.count(); err != nil {
		return nil, err
	}
	switch sig[0] {
	case 'y':
		return d.u8()
	case 'b':
		v, err := d.u32()
		if err != nil {
			return nil, err
		}
		if v > 1 {
			return nil, malformed("mantıksal değer 0 veya 1 değil")
		}
		return v == 1, nil
	case 'n':
		v, err := d.u16()
		return int16(v), err
	case 'q':
		return d.u16()
	case 'i':
		v, err := d.u32()
		return int32(v), err
	case 'u':
		return d.u32()
	case 'h':
		v, err := d.u32()
		return UnixFD(v), err
	case 'x':
		v, err := d.u64()
		return int64(v), err
	case 't':
		return d.u64()
	case 'd':
		v, err := d.u64()
		return math.Float64frombits(v), err
	case 's':
		return d.str()
	case 'o':
		s, err := d.str()
		if err != nil {
			return nil, err
		}
		if !ValidObjectPath(s) {
			return nil, malformed("geçersiz nesne yolu")
		}
		return ObjectPath(s), nil
	case 'g':
		return d.signature()
	case 'v':
		s, err := d.signature()
		if err != nil {
			return nil, err
		}
		if err := singleType(s); err != nil {
			return nil, malformed("varyant imzası tek tür değil")
		}
		// The variant's own signature counts toward every limit.
		v, err := d.value(string(s), arrays, structs, depth+1)
		if err != nil {
			return nil, err
		}
		return Variant{Sig: s, Value: v}, nil
	case '(':
		if err := d.align(8); err != nil {
			return nil, err
		}
		inner := sig[1 : len(sig)-1]
		var out Struct
		for i := 0; i < len(inner); {
			end, err := nextType(inner, i, 0, 0)
			if err != nil {
				return nil, malformed("yapı imzası")
			}
			v, err := d.value(inner[i:end], arrays, structs+1, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			i = end
		}
		return out, nil
	case 'a':
		return d.array(sig[1:], arrays, structs, depth)
	}
	return nil, malformed("bilinmeyen tür %q", sig[0])
}

func (d *decoder) array(elem string, arrays, structs, depth int) (any, error) {
	n, err := d.u32()
	if err != nil {
		return nil, err
	}
	if n > MaxMessageSize {
		return nil, malformed("dizi çok uzun")
	}
	if err := d.align(alignment(elem[0])); err != nil {
		return nil, err
	}
	if int(n) > len(d.b)-d.off {
		return nil, malformed("dizi verinin dışında")
	}
	end := d.off + int(n)
	if elem == "y" {
		b, _ := d.take(int(n))
		d.values += len(b) / 64 // byte arrays are copied, not expanded
		return append([]byte(nil), b...), d.count()
	}
	if elem[0] == '{' {
		inner := elem[1 : len(elem)-1]
		kEnd, err := nextType(inner, 0, 0, 0)
		if err != nil {
			return nil, malformed("sözlük imzası")
		}
		kSig, vSig := inner[:kEnd], inner[kEnd:]
		var out []DictEntry
		for d.off < end {
			if err := d.align(8); err != nil {
				return nil, err
			}
			k, err := d.value(kSig, arrays+1, structs+1, depth+1)
			if err != nil {
				return nil, err
			}
			v, err := d.value(vSig, arrays+1, structs+1, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, DictEntry{Key: k, Value: v})
		}
		if d.off != end {
			return nil, malformed("dizi uzunluğu öğelerle uyuşmuyor")
		}
		if out == nil {
			out = []DictEntry{}
		}
		return out, nil
	}
	out := []any{}
	for d.off < end {
		v, err := d.value(elem, arrays+1, structs, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if d.off != end {
		return nil, malformed("dizi uzunluğu öğelerle uyuşmuyor")
	}
	return out, nil
}

// decodeBody decodes a message body. The body starts 8-aligned in the
// message, so offsets restart at 0.
func decodeBody(b []byte, order binary.ByteOrder, sig Signature) ([]any, error) {
	parts, err := SplitSignature(sig)
	if err != nil {
		return nil, malformed("gövde imzası")
	}
	d := &decoder{b: b, order: order}
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		v, err := d.value(p, 0, 0, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if d.off != len(b) {
		return nil, malformed("gövdenin sonunda fazla veri")
	}
	return out, nil
}
