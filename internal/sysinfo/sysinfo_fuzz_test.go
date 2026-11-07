package sysinfo

import "testing"

// FuzzDecode covers the system report every member device sends to admin
// devices (#654, ADR-0209).
func FuzzDecode(f *testing.F) {
	in := Info{Version: "1", OS: "linux", Posture: "d=y;f=n", PostureExt: "sb=y;tp=n;sl=u", Listen: []uint16{22, 80}}
	if b, err := in.Encode(); err == nil {
		f.Add(b)
	}
	f.Add([]byte(`{"ps":"d=x","pe":"sb=?","lp":[0,70000]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Decode(b)
		if err != nil {
			return
		}
		if got.Detail != nil {
			t.Fatal("decoded report carries the detail inventory")
		}
		if _, err := got.Encode(); err != nil && len(b) <= MaxEncoded/2 {
			t.Fatalf("decoded report does not re-encode: %v", err)
		}
	})
}

// FuzzDecodeDetail covers the chunked detailed inventory.
func FuzzDecodeDetail(f *testing.F) {
	f.Add([]byte(`{}`), "")
	f.Fuzz(func(t *testing.T, b []byte, id string) {
		_, _ = DecodeDetail(b, id)
	})
}
