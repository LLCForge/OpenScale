package panel

import (
	"encoding/binary"
	"errors"
	"math"
)

// A small CBOR decoder for WebAuthn (ADR-0199): attestation objects and
// COSE keys use definite-length, canonical CBOR. Indefinite lengths,
// floats and deep nesting are refused; every length is checked against
// the remaining input before anything is allocated.

var errCBOR = errors.New("cbor: geçersiz veri")

const cborMaxDepth = 8

// cborDecode returns one item and the rest of b. Maps are
// map[any]any whose keys are int64 or string; unsigned and negative
// integers are int64; byte strings []byte; text string; arrays []any.
func cborDecode(b []byte) (any, []byte, error) {
	return cborItem(b, 0)
}

func cborHead(b []byte) (major byte, arg uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, 0, nil, errCBOR
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	switch {
	case info < 24:
		return major, uint64(info), b, nil
	case info == 24:
		if len(b) < 1 {
			return 0, 0, nil, errCBOR
		}
		return major, uint64(b[0]), b[1:], nil
	case info == 25:
		if len(b) < 2 {
			return 0, 0, nil, errCBOR
		}
		return major, uint64(binary.BigEndian.Uint16(b)), b[2:], nil
	case info == 26:
		if len(b) < 4 {
			return 0, 0, nil, errCBOR
		}
		return major, uint64(binary.BigEndian.Uint32(b)), b[4:], nil
	case info == 27:
		if len(b) < 8 {
			return 0, 0, nil, errCBOR
		}
		return major, binary.BigEndian.Uint64(b), b[8:], nil
	}
	return 0, 0, nil, errCBOR // reserved or indefinite length
}

func cborItem(b []byte, depth int) (any, []byte, error) {
	if depth > cborMaxDepth {
		return nil, nil, errCBOR
	}
	major, arg, rest, err := cborHead(b)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return int64(arg), rest, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, nil, errCBOR
		}
		return -1 - int64(arg), rest, nil
	case 2, 3:
		if arg > uint64(len(rest)) {
			return nil, nil, errCBOR
		}
		v := rest[:arg]
		if major == 3 {
			return string(v), rest[arg:], nil
		}
		return append([]byte(nil), v...), rest[arg:], nil
	case 4:
		if arg > uint64(len(rest)) {
			return nil, nil, errCBOR
		}
		out := make([]any, 0, arg)
		for range arg {
			var v any
			if v, rest, err = cborItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, rest, nil
	case 5:
		if arg > uint64(len(rest))/2 {
			return nil, nil, errCBOR
		}
		out := make(map[any]any, arg)
		for range arg {
			var k, v any
			if k, rest, err = cborItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, errCBOR
			}
			if _, dup := out[k]; dup {
				return nil, nil, errCBOR
			}
			if v, rest, err = cborItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out[k] = v
		}
		return out, rest, nil
	case 6:
		// A tag: the tagged item is returned as is.
		return cborItem(rest, depth+1)
	case 7:
		switch arg {
		case 20:
			return false, rest, nil
		case 21:
			return true, rest, nil
		case 22, 23:
			return nil, rest, nil
		}
	}
	return nil, nil, errCBOR
}
