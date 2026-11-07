package sysinfo

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The Tor exit reports its kind; the panel names it from "xk".
func TestUpstreamKindRoundTrip(t *testing.T) {
	SetUpstream(func() (UpstreamState, bool) {
		return UpstreamState{Label: "Tor", Mode: UpstreamBlocked, Kind: UpstreamKindTor}, true
	})
	defer SetUpstream(nil)
	data, err := Collect(time.Unix(1_790_000_100, 0)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"xk":"tor"`) || strings.Contains(string(data), `"xh"`) {
		t.Fatalf("encoded form: %s", data)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamKind != UpstreamKindTor || got.UpstreamMode != UpstreamBlocked || got.UpstreamLabel != "Tor" {
		t.Fatalf("decoded: %+v", got)
	}
}

// A report without the kind encodes exactly as before the field existed.
func TestUpstreamKindAbsentUnchanged(t *testing.T) {
	in := Info{OS: "linux", UpstreamLabel: "Mullvad · İsveç", UpstreamMode: UpstreamTunnel, UpstreamHandshake: 1_790_000_000}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"xk"`) {
		t.Fatalf("empty kind encoded: %s", data)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamKind != "" || got.UpstreamMode != UpstreamTunnel {
		t.Fatalf("decoded: %+v", got)
	}
}

func TestUpstreamKindSanitize(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"xm":"tunnel","xk":"warp"}`, UpstreamKindWARP},
		{`{"xm":"tunnel","xk":"mullvad"}`, UpstreamKindMullvad},
		{`{"xm":"tunnel","xk":"wireguard"}`, UpstreamKindWireGuard},
		{`{"xm":"tunnel","xk":"i2p"}`, ""},
		{`{"xm":"tunnel","xk":"TOR"}`, ""},
		{`{"xm":"bogus","xk":"tor"}`, ""},
	} {
		got, err := Decode([]byte(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		if got.UpstreamKind != tc.want {
			t.Errorf("%s: kind %q, want %q", tc.in, got.UpstreamKind, tc.want)
		}
	}
}
