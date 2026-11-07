package dbuswire

import (
	"errors"
	"fmt"
	"sort"
)

// Limits of what is accepted from the bus.
const (
	// MaxMessageSize bounds a whole message (header and body).
	MaxMessageSize = 1 << 20
	// maxSignature is the specification's limit.
	maxSignature = 255
	// maxArrayDepth and maxStructDepth are the specification's limits;
	// maxTotalDepth also counts variants.
	maxArrayDepth  = 32
	maxStructDepth = 32
	maxTotalDepth  = 64
	// maxValues bounds the values one message decodes to, so a small
	// message cannot expand into a large allocation.
	maxValues = 1 << 18
	// maxFDs bounds the file descriptors one message may carry.
	maxFDs = 16
)

// ObjectPath is a D-Bus object path ("o").
type ObjectPath string

// Signature is a D-Bus type signature ("g"); as a message body signature
// it lists zero or more complete types.
type Signature string

// UnixFD is a file descriptor index ("h") into the message's Files.
type UnixFD uint32

// Variant is a value with its own signature ("v"). Sig is one complete
// type.
type Variant struct {
	Sig   Signature
	Value any
}

// Struct is a D-Bus structure ("(...)").
type Struct []any

// DictEntry is one entry of a dictionary ("a{...}").
type DictEntry struct {
	Key   any
	Value any
}

// MakeVariant wraps a value whose signature follows from its Go type. It
// covers the basic types, []string, []byte, []ObjectPath, []int32,
// []uint32, Variant itself and map[string]Variant; other values need
// NewVariant.
func MakeVariant(v any) Variant {
	sig, ok := goSignature(v)
	if !ok {
		// Encoding reports the error; a variant can never be invalid
		// silently.
		return Variant{Sig: "", Value: v}
	}
	return Variant{Sig: sig, Value: v}
}

// NewVariant wraps a value with an explicit signature.
func NewVariant(sig Signature, v any) Variant { return Variant{Sig: sig, Value: v} }

func goSignature(v any) (Signature, bool) {
	switch v.(type) {
	case byte:
		return "y", true
	case bool:
		return "b", true
	case int16:
		return "n", true
	case uint16:
		return "q", true
	case int32:
		return "i", true
	case uint32:
		return "u", true
	case int64:
		return "x", true
	case uint64:
		return "t", true
	case float64:
		return "d", true
	case string:
		return "s", true
	case ObjectPath:
		return "o", true
	case Signature:
		return "g", true
	case Variant:
		return "v", true
	case []string:
		return "as", true
	case []byte:
		return "ay", true
	case []ObjectPath:
		return "ao", true
	case []int32:
		return "ai", true
	case []uint32:
		return "au", true
	case map[string]Variant:
		return "a{sv}", true
	}
	return "", false
}

// Errors of the wire format.
var (
	// ErrInvalidSignature: a signature breaks the grammar or a limit.
	ErrInvalidSignature = errors.New("dbus: geçersiz imza")
	// ErrMalformed: a message breaks the wire format.
	ErrMalformed = errors.New("dbus: bozuk ileti")
	// ErrTooLarge: a message is larger than MaxMessageSize.
	ErrTooLarge = errors.New("dbus: ileti çok büyük")
	// ErrValue: a Go value does not fit its signature.
	ErrValue = errors.New("dbus: değer imzaya uymuyor")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// isBasic reports whether c is a basic type code (a valid dict key).
func isBasic(c byte) bool {
	switch c {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h':
		return true
	}
	return false
}

// nextType returns the end of the complete type that starts at sig[i].
// depth counts containers around it.
func nextType(sig string, i, arrays, structs int) (int, error) {
	if i >= len(sig) {
		return 0, fmt.Errorf("%w: eksik tür", ErrInvalidSignature)
	}
	if arrays+structs > maxTotalDepth {
		return 0, fmt.Errorf("%w: çok derin", ErrInvalidSignature)
	}
	c := sig[i]
	switch {
	case isBasic(c), c == 'v':
		return i + 1, nil
	case c == 'a':
		if arrays+1 > maxArrayDepth {
			return 0, fmt.Errorf("%w: çok derin dizi", ErrInvalidSignature)
		}
		if i+1 < len(sig) && sig[i+1] == '{' {
			// a{KV}: K basic, V one complete type.
			j := i + 2
			if j >= len(sig) || !isBasic(sig[j]) {
				return 0, fmt.Errorf("%w: sözlük anahtarı temel tür değil", ErrInvalidSignature)
			}
			end, err := nextType(sig, j+1, arrays+1, structs+1)
			if err != nil {
				return 0, err
			}
			if end >= len(sig) || sig[end] != '}' {
				return 0, fmt.Errorf("%w: sözlük girdisi kapanmadı", ErrInvalidSignature)
			}
			return end + 1, nil
		}
		return nextType(sig, i+1, arrays+1, structs)
	case c == '(':
		if structs+1 > maxStructDepth {
			return 0, fmt.Errorf("%w: çok derin yapı", ErrInvalidSignature)
		}
		j := i + 1
		if j < len(sig) && sig[j] == ')' {
			return 0, fmt.Errorf("%w: boş yapı", ErrInvalidSignature)
		}
		for j < len(sig) && sig[j] != ')' {
			end, err := nextType(sig, j, arrays, structs+1)
			if err != nil {
				return 0, err
			}
			j = end
		}
		if j >= len(sig) {
			return 0, fmt.Errorf("%w: yapı kapanmadı", ErrInvalidSignature)
		}
		return j + 1, nil
	}
	return 0, fmt.Errorf("%w: bilinmeyen tür %q", ErrInvalidSignature, c)
}

// SplitSignature splits a signature into its complete types.
func SplitSignature(sig Signature) ([]string, error) {
	s := string(sig)
	if len(s) > maxSignature {
		return nil, fmt.Errorf("%w: çok uzun", ErrInvalidSignature)
	}
	var out []string
	for i := 0; i < len(s); {
		end, err := nextType(s, i, 0, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, s[i:end])
		i = end
	}
	return out, nil
}

// ValidSignature reports whether sig is a valid signature.
func ValidSignature(sig Signature) bool {
	_, err := SplitSignature(sig)
	return err == nil
}

// singleType checks that sig is exactly one complete type.
func singleType(sig Signature) error {
	parts, err := SplitSignature(sig)
	if err != nil {
		return err
	}
	if len(parts) != 1 {
		return fmt.Errorf("%w: tek tür bekleniyordu: %q", ErrInvalidSignature, sig)
	}
	return nil
}

// alignment returns the alignment of the type that starts with c.
func alignment(c byte) int {
	switch c {
	case 'y', 'g', 'v':
		return 1
	case 'n', 'q':
		return 2
	case 'b', 'i', 'u', 's', 'o', 'a', 'h':
		return 4
	case 'x', 't', 'd', '(', '{':
		return 8
	}
	return 1
}

// sortedKeys returns the keys of m in order, so encoding is stable.
func sortedKeys(m map[string]Variant) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// intIn reports whether an int fits [lo, hi].
func intIn(v int, lo, hi int64) bool { return int64(v) >= lo && int64(v) <= hi }
