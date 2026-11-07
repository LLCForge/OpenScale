package osnet

import (
	"strings"
	"testing"
)

func TestParseWSLConfig(t *testing.T) {
	cases := []struct {
		in   string
		mode string
		dns  string
	}{
		{"", WSLModeNAT, "nil"},
		{"[wsl2]\nnetworkingMode=mirrored\ndnsTunneling=true\n", WSLModeMirrored, "true"},
		{"[WSL2]\n  NetworkingMode = \"Mirrored\" # yorum\n", WSLModeMirrored, "nil"},
		{"[experimental]\nnetworkingMode=mirrored\n", WSLModeNAT, "nil"},
		{"[wsl2]\nnetworkingMode=uydurma\ndnsTunneling=belki\n", "", "nil"},
		{"[wsl2]\ndnsTunneling=false\n", WSLModeNAT, "false"},
	}
	for _, c := range cases {
		mode, dns := ParseWSLConfig([]byte(c.in))
		got := "nil"
		if dns != nil {
			got = map[bool]string{true: "true", false: "false"}[*dns]
		}
		if mode != c.mode || got != c.dns {
			t.Errorf("%q: mode=%q dns=%s, want %q %s", c.in, mode, got, c.mode, c.dns)
		}
	}
}

func TestParseWSLKernel(t *testing.T) {
	for in, want := range map[string]int{
		"5.15.153.1-microsoft-standard-WSL2": 2,
		"4.4.0-19041-Microsoft":              1,
		"6.8.0-45-generic":                   0,
	} {
		inside, v := ParseWSLKernel(in)
		if v != want || inside != (want != 0) {
			t.Errorf("%q: inside=%v v=%d", in, inside, v)
		}
	}
}

func TestWSLNotes(t *testing.T) {
	if n := WSLNotes(WSLInfo{}); n != nil {
		t.Fatalf("no WSL, notes %v", n)
	}
	nat := strings.Join(WSLNotes(WSLInfo{Installed: true, ConfigRead: true, Mode: WSLModeNAT}), "\n")
	if !strings.Contains(nat, "mtu 1280") || !strings.Contains(nat, "networkingMode=mirrored") {
		t.Fatalf("NAT notes: %s", nat)
	}
	f := false
	mir := strings.Join(WSLNotes(WSLInfo{Installed: true, ConfigRead: true, Mode: WSLModeMirrored, DNSTunneling: &f}), "\n")
	if !strings.Contains(mir, "dnsTunneling=true") {
		t.Fatalf("mirrored notes: %s", mir)
	}
	svc := strings.Join(WSLNotes(WSLInfo{Installed: true}), "\n")
	if !strings.Contains(svc, "openscale platform wsl") {
		t.Fatalf("service notes: %s", svc)
	}
	in := strings.Join(WSLNotes(WSLInfo{Inside: true, Version: 2}), "\n")
	if !strings.Contains(in, "systemd=true") {
		t.Fatalf("inside notes: %s", in)
	}
}
