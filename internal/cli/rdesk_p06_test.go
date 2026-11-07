package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
)

func TestRDPFileHardened(t *testing.T) {
	c := rdpFileContent("nas.openscale.internal", nil)
	for _, want := range []string{
		"full address:s:nas.openscale.internal\r\n", "enablecredsspsupport:i:1\r\n", "redirectclipboard:i:0\r\n",
		"redirectprinters:i:0\r\n", "drivestoredirect:s:\r\n", "redirectdrives:i:0\r\n", "redirectsmartcards:i:0\r\n",
		"usbdevicestoredirect:s:\r\n", "audiocapturemode:i:0\r\n", "redirectcomports:i:0\r\n",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q", want)
		}
	}
	allow, err := parseRDPAllow("Clipboard, drives")
	if err != nil {
		t.Fatal(err)
	}
	c = rdpFileContent("nas.openscale.internal:3390", allow)
	if !strings.Contains(c, "redirectclipboard:i:1\r\n") || !strings.Contains(c, "drivestoredirect:s:*\r\n") || strings.Contains(c, "redirectdrives:i:0") || !strings.Contains(c, "redirectprinters:i:0\r\n") {
		t.Fatalf("allowed redirections:\n%s", c)
	}
	if _, err := parseRDPAllow("clipboard,disk"); err == nil {
		t.Fatal("unknown redirection accepted")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "nas.rdp")
	if err := writeRDPFile(p, c, true); err != nil {
		t.Fatal(err)
	}
	if err := writeRDPFile(p, c, true); err == nil {
		t.Fatal("existing file overwritten")
	}
	if err := writeRDPFile(p, "x", false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(p); string(data) != "x" {
		t.Fatal("cache file not replaced")
	}
	if err := writeRDPFile(filepath.Join(dir, "nas.txt"), c, true); err == nil {
		t.Fatal("wrong extension accepted")
	}
	if got := rdpFileCommand("windows", p); got[0] != "mstsc.exe" || got[1] != p {
		t.Fatalf("command %v", got)
	}
	h := newHarness(t)
	h.run(exitUsage, "connect", "100.80.0.4", "--rdp", "--rdp-allow", "disk", "--print")
}

func TestRDeskStatsLine(t *testing.T) {
	line := formatRDeskStats(rdesk.Stats{FPS: 12.5, RTT: 34 * time.Millisecond, BytesPerSec: 2048, Width: 1920, Height: 1080, Scale: 2}, "aktarıcı")
	for _, want := range []string{"12.5 kare/sn", "gecikme 34 ms", "1920×1080", "1/2", "yol: aktarıcı"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing in %q", want, line)
		}
	}
	if !strings.Contains(formatRDeskStats(rdesk.Stats{}, ""), "gecikme bilinmiyor") {
		t.Fatal("unknown latency")
	}
}

func TestRDeskHelpTargets(t *testing.T) {
	dev := func(name, ip string) trust.Device {
		d := trust.Device{Name: name, IPv4: netip.MustParseAddr(ip)}
		d.WireGuardKey[0] = 1
		return d
	}
	doc := &trust.Document{
		Devices: []trust.Device{dev("anne", "100.80.0.2"), dev("ben", "100.80.0.3"), dev("kardes", "100.80.0.4"), dev("izleyici", "100.80.0.5")},
		Rules: []trust.Rule{
			{From: []string{"ben"}, To: []string{"anne"}, Service: trust.ServiceRemoteDesktop, AllowControl: true},
			{From: []string{"izleyici"}, To: []string{"anne"}, Service: trust.ServiceRemoteDesktop},
		},
	}
	got := helpTargets(doc, "anne", "", time.Now())
	if len(got) != 1 || got[0].Name != "ben" {
		t.Fatalf("targets %+v", got)
	}
	if len(helpTargets(doc, "anne", "kardes", time.Now())) != 0 {
		t.Fatal("device without control rule targeted")
	}
	text := helpRequestText("anne", "yazıcı çalışmıyor")
	if !strings.Contains(text, "anne") || !strings.Contains(text, "yazıcı") || !strings.Contains(text, "onay") {
		t.Fatalf("text %q", text)
	}
	h := newHarness(t)
	h.run(exitUsage, "rdesk-stats")
	h.run(exitUsage, "rdesk-stats", "laptop", "--duration", "0s")
	h.run(exitUsage, "rdesk-files", "laptop", "--get", "a/b")
	h.run(exitUsage, "rdesk-files", "laptop", "--path", "a", "--get", "a/b", "--out", filepath.Join(t.TempDir(), "x"))
	h.run(exitUsage, "rdesk-help", "--note", strings.Repeat("a", 501))
}
