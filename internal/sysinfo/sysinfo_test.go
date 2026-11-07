package sysinfo

import (
	"strings"
	"testing"
	"time"
)

func TestCollectAndRoundTrip(t *testing.T) {
	in := Collect(time.Now())
	in.PublicIP = "203.0.113.7"
	if in.Cores < 1 || in.OS == "" {
		t.Fatalf("unexpected info %+v", in)
	}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil || out.PublicIP != in.PublicIP || out.MemTotal != in.MemTotal {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	t.Logf("%d bytes: %s", len(data), data)
}

func TestSanitizeLimitsText(t *testing.T) {
	in := Info{OSName: strings.Repeat("ğ", 100) + "\n\x00x", CPU: "a\tb"}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Decode(data)
	if len(out.OSName) > maxText || strings.ContainsAny(out.OSName, "\n\x00") || out.CPU != "a b" {
		t.Fatalf("not sanitized: %q %q", out.OSName, out.CPU)
	}
}

func TestExtraFields(t *testing.T) {
	SetExtra(func(in *Info) {
		in.SSHHostKey = "SHA256:abcDEF0123+/xyz"
		in.WakeMAC = "AA-BB-CC-DD-EE-01"
	})
	defer SetExtra(nil)
	in := Collect(time.Unix(1, 0))
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SSHHostKey != "SHA256:abcDEF0123+/xyz" || got.WakeMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("extra fields: %+v", got)
	}
	bad, err := Decode([]byte(`{"hk":"SHA256:<script>","wm":"ff:ff:ff:ff:ff:ff"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bad.SSHHostKey != "" || bad.WakeMAC != "" {
		t.Fatalf("malformed extra fields kept: %+v", bad)
	}
}
