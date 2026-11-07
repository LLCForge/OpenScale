package cli

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/upstream"
)

// Tor exit commands (ADR-0142, Tor appendix).
func TestTorCommands(t *testing.T) {
	h := newHarness(t)
	state := filepath.Join(t.TempDir(), "device")
	sd := []string{"--state-dir", state}

	h.run(exitUsage, append([]string{"exit-node", "upstream", "tor", "enable", "--trans-port", "0"}, sd...)...)
	h.run(exitUsage, append([]string{"exit-node", "upstream", "tor", "enable", "--trans-port", "5353"}, sd...)...)
	out := h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "enable"}, sd...)...)
	mustContain(t, out, "Tor çıkışı seçildi (TransPort 9040, DNSPort 127.0.0.1:5353)", "UDP (QUIC", "DÜŞÜRÜLÜR", "tor torrc")

	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "status"}, sd...)...)
	mustContain(t, out, "Üst çıkış:       Tor", "rapor yok veya eski")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "status"}, sd...)...)
	mustContain(t, out, "Tor (tür: tor)")

	// A report from the running exit.
	st, err := upstream.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	now := h.env.Now()
	if err := st.WriteStatus(upstream.Status{Kind: upstream.KindTor, Mode: upstream.ModeBlocked, Label: "Tor", Updated: now.Unix(),
		Error: "Tor TransPort 9040 dinlemiyor", Tor: &upstream.TorStatus{TransPort: 9040, DNSPort: 5353, Listen: "100.80.0.1", DNSUp: true}}); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "status"}, sd...)...)
	mustContain(t, out, "Tor dinlemiyor: üyelerin internet trafiği kesiliyor (sızıntı yok)", "TransPort:       dinlemiyor (100.80.0.1:9040)", "DNSPort:         dinliyor (127.0.0.1:5353)")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "status", "--json"}, sd...)...)
	var js struct {
		Enabled bool                `json:"enabled"`
		Mode    string              `json:"mode"`
		Status  *upstream.TorStatus `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &js); err != nil || !js.Enabled || js.Mode != upstream.ModeBlocked || js.Status == nil || !js.Status.DNSUp {
		t.Fatalf("tor status json %q: %v", out, err)
	}

	// torrc lines; the address comes from the running exit's report.
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "torrc"}, sd...)...)
	mustContain(t, out, "TransPort 100.80.0.1:9040\n", "DNSPort 127.0.0.1:5353\n", "AutomapHostsOnResolve 1\n",
		"AutomapHostsSuffixes .onion\n", "VirtualAddrNetworkIPv4 198.18.0.0/15\n", "After=openscale-wait-online.service")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "torrc", "--listen", "100.80.0.9", "--trans-port", "9041"}, sd...)...)
	mustContain(t, out, "TransPort 100.80.0.9:9041\n")
	h.run(exitUsage, append([]string{"exit-node", "upstream", "tor", "torrc", "--listen", "127.0.0.1"}, sd...)...)
	h.run(exitError, "exit-node", "upstream", "tor", "torrc", "--state-dir", filepath.Join(t.TempDir(), "bos"))

	// "use" of a WireGuard profile replaces Tor.
	conf, _ := upstreamTestConf(t)
	src := filepath.Join(t.TempDir(), "se.conf")
	if err := os.WriteFile(src, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, append([]string{"exit-node", "upstream", "import", src, "--provider", "mullvad"}, sd...)...)
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "use", "se"}, sd...)...)
	mustContain(t, out, "Tor çıkışı kapatıldı")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "status"}, sd...)...)
	mustContain(t, out, "Tor çıkışı: kapalı")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "enable", "--trans-port", "9050", "--dns-port", "9053"}, sd...)...)
	mustContain(t, out, `"se" artık kullanılmıyor`)
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "disable"}, sd...)...)
	mustContain(t, out, "Tor çıkışı kapatıldı")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "tor", "disable"}, sd...)...)
	mustContain(t, out, "zaten kapalı")
}

// A WARP file names its server: the name is resolved once at import and
// stored as an address, with a warning.
func TestUpstreamImportWARP(t *testing.T) {
	h := newHarness(t)
	state := filepath.Join(t.TempDir(), "device")
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	p, _ := ecdh.X25519().GenerateKey(rand.Reader)
	conf := "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(k.Bytes()) +
		"\nAddress = 172.16.0.2/32\nAddress = 2001:db8:110::2/128\nDNS = 192.0.2.53\nMTU = 1280\n[Peer]\nPublicKey = " +
		base64.StdEncoding.EncodeToString(p.PublicKey().Bytes()) + "\nAllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\nEndpoint = engage.example.net:2408\n"
	src := filepath.Join(t.TempDir(), "wgcf-profile.conf")
	if err := os.WriteFile(src, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	old := lookupEndpoint
	defer func() { lookupEndpoint = old }()
	var asked []string
	lookupEndpoint = func(_ context.Context, host string) ([]netip.Addr, error) {
		asked = append(asked, host)
		if host != "engage.example.net" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("198.51.100.7")}, nil
	}
	out := h.run(exitOK, "exit-node", "upstream", "import", src, "--name", "warp", "--provider", "warp", "--label", "Cloudflare WARP", "--state-dir", state)
	mustContain(t, out, "Endpoint bir addı (engage.example.net)", "198.51.100.7 olarak çözüldü", "198.51.100.7:2408", "MTU:             1280")
	if len(asked) != 1 {
		t.Fatalf("lookups %v", asked)
	}
	h.run(exitUsage, "exit-node", "upstream", "import", src, "--name", "w2", "--provider", "nordvpn", "--state-dir", state)
	if len(asked) != 1 {
		t.Fatal("a refused import resolved the name")
	}
	h.run(exitOK, "exit-node", "upstream", "use", "warp", "--state-dir", state)
	out = h.run(exitOK, "exit-node", "upstream", "status", "--state-dir", state)
	mustContain(t, out, "Tür:             warp")
	data, err := os.ReadFile(filepath.Join(state, upstream.DirName, "warp.conf"))
	if err != nil || strings.Contains(string(data), "engage") {
		t.Fatalf("stored profile kept the name: %v\n%s", err, data)
	}
}
