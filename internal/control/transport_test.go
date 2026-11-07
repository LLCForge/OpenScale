package control

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func wgMsg(typ byte, n int) []byte {
	b := make([]byte, n)
	b[0] = typ
	return b
}

func TestValidWireGuardMessage(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		want bool
	}{
		{wgMsg(1, 148), true},
		{wgMsg(1, 149), false},
		{wgMsg(2, 92), true},
		{wgMsg(3, 64), true},
		{wgMsg(4, 32), true},
		{wgMsg(4, 1452), true},
		{wgMsg(4, 31), false},
		{wgMsg(4, TCPMaxFrame+1), false},
		{wgMsg(5, 148), false},
		{append([]byte{1, 1, 0, 0}, make([]byte, 144)...), false},
		{nil, false},
	} {
		if got := ValidWireGuardMessage(tc.b); got != tc.want {
			t.Errorf("ValidWireGuardMessage(type %v len %d) = %v", tc.b, len(tc.b), got)
		}
	}
	if !IsWireGuardInitiation(wgMsg(1, 148)) || IsWireGuardInitiation(wgMsg(4, 148)) {
		t.Fatal("IsWireGuardInitiation")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var stream []byte
	msgs := [][]byte{wgMsg(1, 148), wgMsg(4, 32), wgMsg(4, 2000)}
	for _, m := range msgs {
		var err error
		if stream, err = AppendFrame(stream, m); err != nil {
			t.Fatal(err)
		}
	}
	r := bytes.NewReader(stream)
	buf := make([]byte, TCPMaxFrame)
	for _, m := range msgs {
		got, err := ReadFrame(r, buf)
		if err != nil || !bytes.Equal(got, m) {
			t.Fatalf("ReadFrame = %d bytes, %v", len(got), err)
		}
	}
	if _, err := ReadFrame(r, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: %v", err)
	}
	if _, err := AppendFrame(nil, nil); err == nil {
		t.Fatal("empty frame accepted")
	}
	if _, err := AppendFrame(nil, make([]byte, TCPMaxFrame+1)); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestReadFrameRejects(t *testing.T) {
	buf := make([]byte, TCPMaxFrame)
	for name, stream := range map[string][]byte{
		"zero length": {0, 0},
		"too long":    {0x10, 0x01},
		"not wg":      append([]byte{0, 4}, 9, 0, 0, 0),
		"truncated":   append([]byte{0, 148}, wgMsg(1, 100)...),
	} {
		if _, err := ReadFrame(bytes.NewReader(stream), buf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ReadMagic(bytes.NewReader([]byte("GET / HT"))); err == nil {
		t.Fatal("foreign preamble accepted")
	}
	if err := ReadMagic(bytes.NewReader([]byte(TCPMagic))); err != nil {
		t.Fatal(err)
	}
	echo := append([]byte(UDPEchoRequest), make([]byte, UDPEchoNonce)...)
	if !IsUDPEcho(echo, UDPEchoRequest) || IsUDPEcho(echo, UDPEchoReply) || IsUDPEcho(echo[:10], UDPEchoRequest) {
		t.Fatal("IsUDPEcho")
	}
	if ValidWireGuardMessage(echo) {
		t.Fatal("an echo looks like a WireGuard message")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 148})
	s, _ := AppendFrame(nil, wgMsg(4, 64))
	f.Add(s)
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := make([]byte, TCPMaxFrame)
		r := bytes.NewReader(data)
		for i := 0; i < 64; i++ {
			msg, err := ReadFrame(r, buf)
			if err != nil {
				return
			}
			if len(msg) == 0 || len(msg) > TCPMaxFrame || !ValidWireGuardMessage(msg) {
				t.Fatalf("invalid frame passed: %d bytes", len(msg))
			}
		}
	})
}
