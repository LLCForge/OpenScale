package cli

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/upstream"
)

func upstreamTestConf(t *testing.T) (conf, priv string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv = base64.StdEncoding.EncodeToString(k.Bytes())
	return "[Interface]\n# Device: Neat Otter\nPrivateKey = " + priv +
		"\nAddress = 10.68.12.34/32,fc00:bbbb:bbbb:bb01::5:c21/128\nDNS = 10.64.0.1\n\n[Peer]\nPublicKey = " +
		base64.StdEncoding.EncodeToString(p.PublicKey().Bytes()) +
		"\nAllowedIPs = 0.0.0.0/0,::0/0\nEndpoint = 198.51.100.20:51820\n", priv
}

// Upstream exit commands (ADR-0142).
func TestUpstreamCommands(t *testing.T) {
	h := newHarness(t)
	state := filepath.Join(t.TempDir(), "device")
	conf, priv := upstreamTestConf(t)
	src := filepath.Join(t.TempDir(), "se-got-wg-001.conf")
	if err := os.WriteFile(src, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	sd := []string{"--state-dir", state}

	out := h.run(exitOK, append([]string{"exit-node", "upstream", "import", src, "--label", "Mullvad · İsveç"}, sd...)...)
	mustContain(t, out, "Üst çıkış profili içe aktarıldı: se-got-wg-001", "198.51.100.20:51820", "DNS (tünel içi):  10.64.0.1")
	if strings.Contains(out, priv) {
		t.Fatal("import printed the private key")
	}
	h.run(exitError, append([]string{"exit-node", "upstream", "import", src}, sd...)...)
	h.run(exitOK, append([]string{"exit-node", "upstream", "import", src, "--name", "se-got-wg-001", "--replace", "--label", "Mullvad · İsveç"}, sd...)...)

	bad := filepath.Join(t.TempDir(), "bad.conf")
	if err := os.WriteFile(bad, []byte(conf+"PostUp = iptables -F\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitError, append([]string{"exit-node", "upstream", "import", bad, "--name", "bad"}, sd...)...)
	mustContain(t, out, "desteklenmeyen alan")

	out = h.run(exitOK, append([]string{"exit-node", "upstream", "list"}, sd...)...)
	mustContain(t, out, "se-got-wg-001", "Mullvad · İsveç")

	h.run(exitUsage, append([]string{"exit-node", "upstream", "use", "se-got-wg-001", "--on-down", "leak"}, sd...)...)
	h.run(exitError, append([]string{"exit-node", "upstream", "use", "yok"}, sd...)...)
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "use", "se-got-wg-001"}, sd...)...)
	mustContain(t, out, "Etkin üst çıkış: se-got-wg-001 (Mullvad · İsveç)", "trafiği kesilir")
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "use", "se-got-wg-001", "--on-down", "direct"}, sd...)...)
	mustContain(t, out, "UYARI: --on-down direct")

	out = h.run(exitOK, append([]string{"exit-node", "upstream", "list", "--json"}, sd...)...)
	var list []upstreamProfileJSON
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != 1 || !list[0].Active || list[0].PublicKey == "" {
		t.Fatalf("list json %q: %v", out, err)
	}
	if strings.Contains(out, priv) {
		t.Fatal("list printed the private key")
	}

	// No running tunnel yet: status says so.
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "status"}, sd...)...)
	mustContain(t, out, "Seçili profil:   se-got-wg-001", "rapor yok veya eski")

	// A report from the running tunnel.
	st, err := upstream.OpenStore(state)
	if err != nil {
		t.Fatal(err)
	}
	now := h.env.Now()
	if err := st.WriteStatus(upstream.Status{Active: "se-got-wg-001", Interface: "os-up0", Endpoint: "198.51.100.20:51820", Connected: true,
		LastHandshake: now.Unix() - 42, RxBytes: 2048, TxBytes: 1024, Mode: upstream.ModeTunnel, Updated: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "status"}, sd...)...)
	mustContain(t, out, "bağlı: üyelerin internet trafiği üst tünelden çıkıyor", "Son el sıkışma:  42s önce", "2.0 KiB", "görünen çıkış IP'si buradan ölçülmez")

	h.run(exitError, append([]string{"exit-node", "upstream", "rm", "se-got-wg-001"}, sd...)...)
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "off"}, sd...)...)
	mustContain(t, out, "Üst çıkış kapatıldı")
	h.run(exitOK, append([]string{"exit-node", "upstream", "rm", "se-got-wg-001"}, sd...)...)
	out = h.run(exitOK, append([]string{"exit-node", "upstream", "list"}, sd...)...)
	mustContain(t, out, "Üst çıkış profili yok")
}
