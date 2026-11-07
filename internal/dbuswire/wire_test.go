package dbuswire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, m *Message) *Message {
	t.Helper()
	data, err := m.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := readMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

func TestRoundTripTypes(t *testing.T) {
	body := []any{
		byte(7), true, int16(-3), uint16(65000), int32(-70000), uint32(4000000000),
		int64(-1 << 40), uint64(1 << 63), 3.5, "merhaba ğüşiöç", ObjectPath("/a/b_c"), Signature("a{sv}"),
		NewVariant("(is)", Struct{int32(1), "x"}),
		[]string{"a", "", "c"},
		[]byte{1, 2, 3},
		map[string]Variant{"b": MakeVariant(uint32(2)), "a": MakeVariant("bir")},
		Struct{int32(5), []any{Struct{"k", MakeVariant(false)}}},
		[]DictEntry{{Key: int32(1), Value: []string{"x"}}},
	}
	sig := Signature("ybnqiuxtdsogvasaya{sv}(ia(sv))a{ias}")
	m := &Message{Type: TypeMethodCall, Serial: 9, Path: "/x", Member: "M", Signature: sig, Body: body}
	got := roundTrip(t, m)
	if got.Signature != sig || got.Serial != 9 || got.Path != "/x" || got.Member != "M" {
		t.Fatalf("header: %+v", got)
	}
	want := []any{
		byte(7), true, int16(-3), uint16(65000), int32(-70000), uint32(4000000000),
		int64(-1 << 40), uint64(1 << 63), 3.5, "merhaba ğüşiöç", ObjectPath("/a/b_c"), Signature("a{sv}"),
		Variant{Sig: "(is)", Value: Struct{int32(1), "x"}},
		[]any{"a", "", "c"},
		[]byte{1, 2, 3},
		[]DictEntry{{Key: "a", Value: Variant{Sig: "s", Value: "bir"}}, {Key: "b", Value: Variant{Sig: "u", Value: uint32(2)}}},
		Struct{int32(5), []any{Struct{"k", Variant{Sig: "b", Value: false}}}},
		[]DictEntry{{Key: int32(1), Value: []any{"x"}}},
	}
	if !reflect.DeepEqual(got.Body, want) {
		t.Fatalf("body:\n got %#v\nwant %#v", got.Body, want)
	}
}

// helloLibdbus is the Hello call as libdbus writes it (fields in the
// order path, destination, interface, member).
func helloLibdbus() []byte {
	var b []byte
	b = append(b, 'l', 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0)
	fields := []byte{}
	str := func(code byte, typ byte, s string) {
		for len(fields)%8 != 0 {
			fields = append(fields, 0)
		}
		fields = append(fields, code, 1, typ, 0)
		fields = binary.LittleEndian.AppendUint32(fields, uint32(len(s)))
		fields = append(fields, s...)
		fields = append(fields, 0)
	}
	str(1, 'o', "/org/freedesktop/DBus")
	str(6, 's', "org.freedesktop.DBus")
	str(2, 's', "org.freedesktop.DBus")
	str(3, 's', "Hello")
	b = binary.LittleEndian.AppendUint32(b, uint32(len(fields)))
	b = append(b, fields...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestParseForeignFieldOrder(t *testing.T) {
	m, err := readMessage(bytes.NewReader(helloLibdbus()))
	if err != nil {
		t.Fatal(err)
	}
	if m.Member != "Hello" || m.Destination != BusName || m.Interface != BusInterface || m.Path != BusPath || m.Serial != 1 {
		t.Fatalf("%+v", m)
	}
}

func TestBigEndian(t *testing.T) {
	// Signal "/a" i.f.S with body u = 0x01020304, big endian.
	var fields []byte
	add := func(code, typ byte, s string) {
		for len(fields)%8 != 0 {
			fields = append(fields, 0)
		}
		fields = append(fields, code, 1, typ, 0)
		if typ == 'g' {
			fields = append(fields, byte(len(s)))
		} else {
			fields = binary.BigEndian.AppendUint32(fields, uint32(len(s)))
		}
		fields = append(fields, s...)
		fields = append(fields, 0)
	}
	add(1, 'o', "/a")
	add(2, 's', "i.f")
	add(3, 's', "S")
	add(8, 'g', "u")
	b := []byte{'B', 4, 0, 1}
	b = binary.BigEndian.AppendUint32(b, 4)
	b = binary.BigEndian.AppendUint32(b, 5)
	b = binary.BigEndian.AppendUint32(b, uint32(len(fields)))
	b = append(b, fields...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint32(b, 0x01020304)
	m, err := readMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != TypeSignal || m.Body[0] != uint32(0x01020304) {
		t.Fatalf("%+v", m)
	}
}

func TestSignatures(t *testing.T) {
	good := []Signature{"", "s", "a{sv}", "(ii)", "aa{s(ai)}", "a(ia{sv})", "v", "h", Signature(strings.Repeat("a", 32) + "y")}
	for _, s := range good {
		if !ValidSignature(s) {
			t.Errorf("%q geçerli olmalı", s)
		}
	}
	bad := []Signature{"a", "()", "(i", "i)", "a{vs}", "{sv}", "a{s}", "a{sss}", "z", Signature(strings.Repeat("a", 33) + "y"),
		Signature(strings.Repeat("(", 33) + "y" + strings.Repeat(")", 33)), Signature(strings.Repeat("y", 256))}
	for _, s := range bad {
		if ValidSignature(s) {
			t.Errorf("%q geçersiz olmalı", s)
		}
	}
}

func TestNames(t *testing.T) {
	for _, p := range []string{"/", "/a", "/a/b_1"} {
		if !ValidObjectPath(p) {
			t.Errorf("%q", p)
		}
	}
	for _, p := range []string{"", "a", "/a/", "//", "/a//b", "/a-b", "/ğ"} {
		if ValidObjectPath(p) {
			t.Errorf("%q", p)
		}
	}
	if !ValidBusName(":1.42") || !ValidBusName("org.kde.StatusNotifierItem-12-1") || ValidBusName("org") || ValidBusName("1org.x") || ValidBusName("org..x") {
		t.Fatal("bus names")
	}
	if !ValidInterfaceName("org.freedesktop.DBus") || ValidInterfaceName("org.free-desktop") || ValidInterfaceName("x") {
		t.Fatal("interface names")
	}
}

func marshalOK(t *testing.T, m *Message) []byte {
	t.Helper()
	data, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRejectsMalformed(t *testing.T) {
	base := marshalOK(t, &Message{Type: TypeMethodReturn, Serial: 2, ReplySerial: 1, Signature: "bs", Body: []any{true, "x"}})
	bodyAt := len(base) - 4 - 4 - 2 // b (4) + string length (4) + "x\0"
	mutate := func(f func(b []byte) []byte) error {
		b := append([]byte(nil), base...)
		_, err := readMessage(bytes.NewReader(f(b)))
		return err
	}
	cases := map[string]func(b []byte) []byte{
		"byte order": func(b []byte) []byte { b[0] = 'x'; return b },
		"version":    func(b []byte) []byte { b[3] = 2; return b },
		"bool 2":     func(b []byte) []byte { b[bodyAt] = 2; return b },
		"no NUL":     func(b []byte) []byte { b[len(b)-1] = 'y'; return b },
		"bad utf8":   func(b []byte) []byte { b[len(b)-2] = 0xff; return b },
		"zero serial": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[8:], 0)
			return b
		},
		"huge body": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[4:], MaxMessageSize+1)
			return b
		},
		"huge fields": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[12:], 0xffffffff)
			return b
		},
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"string too long": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[bodyAt+4:], 1000)
			return b
		},
	}
	for name, f := range cases {
		if err := mutate(f); err == nil {
			t.Errorf("%s: kabul edildi", name)
		}
	}
}

func TestNestedVariantLimit(t *testing.T) {
	// 70 variants inside each other: "v" "v" ... "y".
	var v any = byte(1)
	sig := Signature("y")
	for i := 0; i < 70; i++ {
		v = Variant{Sig: sig, Value: v}
		sig = "v"
	}
	var b []byte
	for i := 0; i < 70; i++ {
		b = append(b, 1, 'v', 0)
	}
	b = b[:len(b)-2]
	b = append(b, 'y', 0, 1)
	if _, err := decodeBody(b, binary.LittleEndian, "v"); err == nil {
		t.Fatal("derin varyant kabul edildi")
	}
	if _, err := encodeBody("v", []any{v}); err == nil {
		t.Fatal("derin varyant kodlandı")
	}
}

func TestArrayLengthBeyondData(t *testing.T) {
	b := binary.LittleEndian.AppendUint32(nil, 1<<19)
	b = append(b, 1, 2, 3, 4)
	if _, err := decodeBody(b, binary.LittleEndian, "ai"); err == nil {
		t.Fatal("kısa dizi kabul edildi")
	}
}

func TestNonZeroPadding(t *testing.T) {
	// "yu": byte, three padding bytes, uint32.
	b := []byte{1, 0, 9, 0, 4, 0, 0, 0}
	if _, err := decodeBody(b, binary.LittleEndian, "yu"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("dolgu: %v", err)
	}
	b[2] = 0
	if _, err := decodeBody(b, binary.LittleEndian, "yu"); err != nil {
		t.Fatal(err)
	}
}

func TestValueLimit(t *testing.T) {
	// An array of empty strings: 5 bytes each in 1 MiB is ~200k values;
	// "ab" is 4 bytes each and goes past maxValues.
	n := maxValues + 10
	b := binary.LittleEndian.AppendUint32(nil, uint32(4*n))
	b = append(b, make([]byte, 4*n)...)
	if _, err := decodeBody(b, binary.LittleEndian, "ab"); err == nil {
		t.Fatal("değer sınırı aşıldı")
	}
}

func TestEncodeRejects(t *testing.T) {
	cases := []struct {
		sig  Signature
		vals []any
	}{
		{"s", []any{"a\x00b"}},
		{"s", []any{"\xff"}},
		{"o", []any{"yol"}},
		{"i", []any{"x"}},
		{"u", []any{-1}},
		{"(ii)", []any{Struct{int32(1)}}},
		{"v", []any{Variant{Sig: "ii", Value: 1}}},
		{"ss", []any{"a"}},
	}
	for _, c := range cases {
		if _, err := encodeBody(c.sig, c.vals); err == nil {
			t.Errorf("%q %v kodlandı", c.sig, c.vals)
		}
	}
	if _, err := (&Message{Type: TypeMethodCall, Serial: 1, Path: "/a"}).marshal(); err == nil {
		t.Error("üyesiz çağrı kodlandı")
	}
}

func TestParseAddress(t *testing.T) {
	eps, err := ParseAddress("tcp:host=x,port=1;unix:abstract=/tmp/dbus-abc,guid=00;unix:path=/run/user/1000/b%75s")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[0].Abstract != "/tmp/dbus-abc" || eps[1].Path != "/run/user/1000/bus" {
		t.Fatalf("%+v", eps)
	}
	for _, bad := range []string{"tcp:host=x", "unix:path=rel", "unix:path=/a,path=/b", "unix:path=%zz", "unix:path=/a,abstract=b", ""} {
		if _, err := ParseAddress(bad); err == nil {
			t.Errorf("%q kabul edildi", bad)
		}
	}
	env := map[string]string{"XDG_RUNTIME_DIR": "/run/user/7"}
	eps, err = sessionEndpoints(func(k string) string { return env[k] })
	if err != nil || eps[0].Path != "/run/user/7/bus" {
		t.Fatalf("%v %v", eps, err)
	}
	if _, err := sessionEndpoints(func(string) string { return "" }); !errors.Is(err, ErrNoBus) {
		t.Fatal(err)
	}
}
