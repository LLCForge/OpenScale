//go:build windows

package osnet

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func fakeNRPT(t *testing.T, local, gpo []nrptRule) {
	t.Helper()
	prev := readNRPT
	readNRPT = func(key string) ([]nrptRule, error) {
		if key == nrptGPOKey {
			return gpo, nil
		}
		return local, nil
	}
	t.Cleanup(func() { readNRPT = prev })
}

func TestVerifyNRPT(t *testing.T) {
	n := NetworkDNS{Split: []SplitDomain{{Domain: "ev.lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")}}}, Overlay: testOverlay}
	fakeNRPT(t, []nrptRule{
		{namespaces: []string{".openscale.internal"}, servers: []string{"100.80.255.254"}},
		{namespaces: []string{".ev.lan"}, servers: []string{"100.80.0.5"}},
	}, nil)
	if err := VerifyNetworkDNS(context.Background(), testMagic, n); err != nil {
		t.Fatalf("intact rules: %v", err)
	}
	fakeNRPT(t, []nrptRule{{namespaces: []string{".openscale.internal"}, servers: []string{"100.80.255.254"}}}, nil)
	if err := VerifyNetworkDNS(context.Background(), testMagic, n); !errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("missing split rule: %v", err)
	}
	fakeNRPT(t, nil, []nrptRule{{namespaces: []string{".corp.example"}, servers: []string{"10.0.0.1"}}})
	if err := VerifyNetworkDNS(context.Background(), testMagic, NetworkDNS{Overlay: testOverlay}); !errors.Is(err, ErrDNSOverwritten) {
		t.Fatalf("missing MagicDNS rule: %v", err)
	}
	if st := SystemDNSStatus("OpenScale"); !st.GroupPolicyNRPT || st.Backend != BackendNRPT {
		t.Fatalf("status %+v", st)
	}
}

func TestConfigureDNSHardensAdapter(t *testing.T) {
	calls := fakeDNSRunner(t)
	if err := ConfigureDNS(context.Background(), testMagic); err != nil {
		t.Fatal(err)
	}
	script := (*calls)[0][len((*calls)[0])-1]
	for _, part := range []string{"-RegisterThisConnectionsAddress $false", "SetTcpipNetbios", "Add-DnsClientNrptRule -Namespace '.openscale.internal'"} {
		if !strings.Contains(script, part) {
			t.Errorf("script lacks %q", part)
		}
	}
}
