package control

import (
	"bytes"
	"testing"
)

// Fuzz tests for network-facing control parsers not covered elsewhere
// (#654, ADR-0209): clone alerts relayed by the coordinator, the
// "who am I" reply from any UDP peer and the TCP stream preamble.

func FuzzDecodeCloneAlert(f *testing.F) {
	f.Add([]byte(`{"device":"d1","name":"laptop","flips":3,"endpoints":["1.2.3.4:41641"],"first":"2026-10-30T00:00:00Z","last":"2026-10-30T00:01:00Z"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := DecodeCloneAlert(data)
		if err != nil {
			return
		}
		if len(a.Endpoints) > 1<<16 {
			t.Fatalf("unbounded endpoints: %d", len(a.Endpoints))
		}
	})
}

func FuzzParseWhoAmIReply(f *testing.F) {
	var nonce [WhoAmINonce]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	f.Add([]byte(WhoAmIReply), nonce[:])
	f.Add(append([]byte(WhoAmIReply), bytes.Repeat([]byte{1}, 64)...), nonce[:])
	f.Fuzz(func(t *testing.T, b []byte, n []byte) {
		var nn [WhoAmINonce]byte
		copy(nn[:], n)
		ap, ok := ParseWhoAmIReply(b, nn)
		if ok && !ap.IsValid() {
			t.Fatal("accepted reply with invalid address")
		}
	})
}

func FuzzReadMagic(f *testing.F) {
	f.Add([]byte(TCPMagic))
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		err := ReadMagic(bytes.NewReader(b))
		if err == nil && !bytes.HasPrefix(b, []byte(TCPMagic)) {
			t.Fatal("wrong preamble accepted")
		}
	})
}
