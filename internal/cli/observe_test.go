package cli

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
)

func TestParseSize(t *testing.T) {
	cases := map[string]int64{"16M": 16 << 20, "512k": 512 << 10, "4096": 4096, "1G": 1 << 30}
	for in, want := range cases {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%s = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "abc", "0", "99999999999G"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWriteBundleZipKeepsNamesInside(t *testing.T) {
	rep := panel.BundleReply{CreatedAt: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), Files: []panel.BundleFile{
		{Name: "README.txt", Content: "merhaba"},
		{Name: "system/ip-route-v4.txt", Content: "default via 192.168.*.*"},
		{Name: "../kacis.txt", Content: "x"},
		{Name: "/etc/passwd", Content: "x"},
		{Name: `C:\Windows\x.txt`, Content: "x"},
	}}
	var buf bytes.Buffer
	if err := writeBundleZip(&buf, rep); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "openscale-teshis/README.txt,openscale-teshis/system/ip-route-v4.txt" {
		t.Fatalf("names = %v", names)
	}
}

func TestWriteDenied(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	writeDenied(&buf, panel.DeniedReply{Entries: []panel.DeniedEntry{
		{Direction: "in", Peer: "laptop", Proto: "tcp", Port: 22, Reason: panel.DenyDisabledRule, Rule: 2, Why: "Kural 2 buna izin verirdi ama devre dışı", Count: 3, Last: now.Add(-time.Minute)},
		{Direction: "out", Remote: "203.0.*.*", Proto: "udp", Port: 53, Reason: panel.DenyUnknownPeer, Why: "bilinmeyen", Count: 1, Last: now},
	}, Totals: map[string]uint64{"rules": 3}}, now)
	out := buf.String()
	for _, want := range []string{"laptop → bu cihaz", "tcp/22", "devre dışı kural", "bu cihaz → 203.0.*.*", "rules=3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q missing:\n%s", want, out)
		}
	}
}
