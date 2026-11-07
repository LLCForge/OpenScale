package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

// Rule language commands (ADR-0120).
func TestP09RuleLanguageCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	// Port names, bidirectional, ICMP types and a one-time window.
	out := h.run(exitOK, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--ports", "rdp", "--bidirectional"}, dir...)...)
	mustContain(t, out, "+ kural laptop -> masaustu tcp/3389 [çift yönlü]")
	out = h.run(exitOK, append([]string{"rule", "add", "--from", "masaustu", "--to", "laptop", "--proto", "icmp", "--icmp-types", "echo", "--for", "30m"}, dir...)...)
	mustContain(t, out, "icmp türleri: echo", "bitiş 2026-10-29T12:30:00Z", "kendi saatine")
	h.run(exitUsage, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--ports", "gopher"}, dir...)...)
	h.run(exitUsage, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--ports", "22", "--for", "1s"}, dir...)...)

	// Simulator.
	out = h.run(exitOK, "policy", "check", "--dir", h.netDir, "--from", "masaustu", "--to", "laptop", "--port", "rdp")
	mustContain(t, out, "İZİN", "kural 1")
	out = h.run(exitOK, "policy", "check", "--dir", h.netDir, "--from", "masaustu", "--to", "laptop", "--port", "22")
	mustContain(t, out, "RET", "varsayılan reddet")
	h.run(exitError, "policy", "check", "--dir", h.netDir, "--from", "yok", "--to", "laptop", "--port", "22")

	// Named address.
	out = h.run(exitOK, append([]string{"host", "set", "--name", "hepsi", "--prefix", "100.80.0.0/16"}, dir...)...)
	mustContain(t, out, "+ adres host:hepsi = 100.80.0.0/16")
	h.run(exitError, append([]string{"host", "set", "--name", "lan", "--prefix", "192.168.1.0/24"}, dir...)...)

	// Export, edit as data, import with a failing and then a passing test.
	file := filepath.Join(t.TempDir(), "politika.jsonc")
	h.run(exitOK, "policy", "export", "--dir", h.netDir, "--out", file)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(data), "// OpenScale politika dosyası", "tcp/3389(rdp)")
	p, err := trust.ParsePolicyText(data)
	if err != nil {
		t.Fatal(err)
	}
	p.Tests = []trust.PolicyTest{{From: "masaustu", To: "laptop", Protocol: trust.ProtocolTCP, Port: 3389, Expect: trust.RuleDeny}}
	write := func() {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, append([]byte("# düzenlendi\n"), b...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	out = h.run(exitError, append([]string{"policy", "import", "--file", file}, dir...)...)
	mustContain(t, out, "kural testi başarısız")
	h.run(exitError, "policy", "test", "--dir", h.netDir, "--file", file)
	p.Tests[0].Expect = trust.RuleAllow
	write()
	out = h.run(exitOK, append([]string{"policy", "import", "--file", file}, dir...)...)
	mustContain(t, out, "+ kural testi masaustu -> laptop tcp/3389 beklenen: izin", "1 test geçti", "imzalandı")
	out = h.run(exitOK, "policy", "test", "--dir", h.netDir)
	mustContain(t, out, "GEÇTİ")

	// A broad rule added through the file needs explicit confirmation.
	p.Rules = append(p.Rules, trust.Rule{From: []string{"*"}, To: []string{"*"}, Protocol: trust.ProtocolAny, Ports: []string{}})
	write()
	h.run(exitUsage, append([]string{"policy", "import", "--file", file}, dir...)...)
	h.run(exitOK, append([]string{"policy", "import", "--file", file, "--confirm", wideRuleWord}, dir...)...)
	out = h.run(exitOK, "policy", "lint", "--dir", h.netDir)
	mustContain(t, out, "[broad]", "[clock]")

	// Revoking a device named by a test still works and drops the test.
	h.run(exitOK, append([]string{"device", "revoke", "--name", "laptop", "--confirm", "laptop"}, dir...)...)
	out = h.run(exitOK, "policy", "test", "--dir", h.netDir)
	mustContain(t, out, "kural testi yok")
}
