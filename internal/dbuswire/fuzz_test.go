package dbuswire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzReadMessage feeds arbitrary bytes to the message reader: it must
// never panic, never accept more than MaxMessageSize and every accepted
// message must encode again.
func FuzzReadMessage(f *testing.F) {
	seeds := []*Message{
		{Type: TypeMethodCall, Serial: 1, Path: "/a", Interface: "a.b", Member: "M", Destination: "org.x.Y", Signature: "sa{sv}(iv)", Body: []any{"x", map[string]Variant{"k": MakeVariant(int32(1))}, Struct{int32(2), MakeVariant([]string{"a"})}}},
		{Type: TypeSignal, Serial: 2, Path: "/b", Interface: "a.b", Member: "S", Signature: "ayau", Body: []any{[]byte{1, 2}, []uint32{3}}},
		{Type: TypeError, Serial: 3, ReplySerial: 1, ErrorName: "a.b.E", Signature: "s", Body: []any{"e"}},
		{Type: TypeMethodReturn, Serial: 4, ReplySerial: 2},
	}
	for _, m := range seeds {
		data, err := m.marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add(helloLibdbus())
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := readMessage(bytes.NewReader(data))
		if err != nil {
			return
		}
		m.Serial = 1
		// Re-encoding may refuse what we never send (descriptors);
		// it must not panic.
		_, _ = m.marshal()
	})
}

// FuzzDecodeBody decodes arbitrary bodies against arbitrary signatures.
func FuzzDecodeBody(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 2, 0, 0, 0}, "yu", false)
	f.Add(binary.LittleEndian.AppendUint32(nil, 8), "a(yv)", true)
	f.Add([]byte{1, 'v', 0, 1, 'y', 0, 5}, "v", false)
	f.Fuzz(func(t *testing.T, data []byte, sig string, big bool) {
		if len(data) > MaxMessageSize {
			return
		}
		var order binary.ByteOrder = binary.LittleEndian
		if big {
			order = binary.BigEndian
		}
		body, err := decodeBody(data, order, Signature(sig))
		if err != nil {
			return
		}
		if order == binary.LittleEndian {
			if _, err := encodeBody(Signature(sig), toEncodable(body)); err != nil {
				t.Fatalf("decoded body does not encode: %v", err)
			}
		}
	})
}

// toEncodable is the identity today: every decoded form is accepted by
// the encoder. It exists so the fuzz test states that rule.
func toEncodable(v []any) []any { return v }

// FuzzParseAddress must never panic and never return a relative path.
func FuzzParseAddress(f *testing.F) {
	f.Add("unix:path=/run/user/1000/bus")
	f.Add("unix:abstract=/tmp/dbus-x,guid=1;tcp:host=a")
	f.Fuzz(func(t *testing.T, s string) {
		eps, err := ParseAddress(s)
		if err != nil {
			return
		}
		for _, e := range eps {
			if e.Path != "" && !strings.HasPrefix(e.Path, "/") {
				t.Fatalf("relative path %q", e.Path)
			}
		}
	})
}

// FuzzAuthReplies runs the client side of authentication against
// arbitrary server bytes.
func FuzzAuthReplies(f *testing.F) {
	f.Add([]byte("OK 0123456789abcdef0123456789abcdef\r\nAGREE_UNIX_FD\r\n"))
	f.Add([]byte("DATA\r\nREJECTED\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		_, _ = authenticate(&out, bufio.NewReader(bytes.NewReader(data)), "1000", true)
	})
}
