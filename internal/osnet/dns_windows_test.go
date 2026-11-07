//go:build windows

package osnet

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// fakeDNSRunner records commands instead of running them, so no test
// touches the host's NRPT.
func fakeDNSRunner(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	prev := runDNSCommand
	runDNSCommand = func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { runDNSCommand = prev })
	return &calls
}

func TestConfigureNetworkDNSRunsOneScript(t *testing.T) {
	calls := fakeDNSRunner(t)
	n := NetworkDNS{
		Split:   []SplitDomain{{Domain: "ev.lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")}}},
		Overlay: testOverlay,
	}
	if err := ConfigureNetworkDNS(context.Background(), testMagic, n); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d commands, want 1", len(*calls))
	}
	cmd := (*calls)[0]
	if cmd[len(cmd)-2] != "-Command" {
		t.Fatalf("command = %q", cmd)
	}
	// The recorder skips run, so check what run would do with this name: an
	// absolute path here left MagicDNS unconfigured on every Windows device.
	if p, err := lookTool(cmd[0]); err != nil {
		t.Fatalf("real runner refuses %q: %v", cmd[0], err)
	} else if !strings.HasSuffix(strings.ToLower(p), `\powershell.exe`) {
		t.Fatalf("tool path = %q", p)
	}
	want, _ := nrptScript(testMagic, n)
	if cmd[len(cmd)-1] != want {
		t.Fatalf("script = %q", cmd[len(cmd)-1])
	}
}

func TestConfigureNetworkDNSRefusesBeforeRunning(t *testing.T) {
	calls := fakeDNSRunner(t)
	n := NetworkDNS{Nameservers: []netip.Addr{netip.MustParseAddr("9.9.9.9")}, Overlay: testOverlay}
	if err := ConfigureNetworkDNS(context.Background(), testMagic, n); err == nil {
		t.Fatal("public resolver accepted")
	}
	if len(*calls) != 0 {
		t.Fatalf("ran %q for a refused setting", *calls)
	}
}

func TestRemoveDNSRemovesOnlyOpenScaleRules(t *testing.T) {
	calls := fakeDNSRunner(t)
	if err := RemoveDNS(context.Background(), testMagic); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d commands", len(*calls))
	}
	script := (*calls)[0][len((*calls)[0])-1]
	if !strings.Contains(script, "$_.Comment -eq 'OpenScale'") || strings.Contains(script, "Add-DnsClientNrptRule") {
		t.Fatalf("script = %q", script)
	}
}
