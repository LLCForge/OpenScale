//go:build windows

package osnet

import (
	"context"
	"strings"
	"testing"
)

func TestNRPTGroupPolicyStatusAndWarning(t *testing.T) {
	fakeNRPT(t, []nrptRule{{namespaces: []string{".openscale.internal"}, servers: []string{"100.80.255.254"}}},
		[]nrptRule{{namespaces: []string{"."}, servers: []string{"10.0.0.1"}}, {namespaces: []string{".corp.example"}, servers: []string{"10.0.0.1"}}})
	st := SystemDNSStatus("OpenScale")
	if !st.GroupPolicyNRPT || len(st.GroupPolicyRules) != 2 || st.GroupPolicyRules[0].Namespaces[0] != "." {
		t.Fatalf("status %+v", st)
	}
	msg := NRPTGroupPolicyWarning(testMagic)
	if !strings.Contains(msg, "başka DNS") || !strings.Contains(msg, ".openscale.internal") {
		t.Fatalf("warning %q", msg)
	}
	// The local rules are still written exactly as before: the policy is
	// reported, never worked around.
	calls := fakeDNSRunner(t)
	if err := ConfigureNetworkDNS(context.Background(), testMagic, NetworkDNS{Overlay: testOverlay}); err != nil {
		t.Fatal(err)
	}
	want, err := nrptScript(testMagic, NetworkDNS{Overlay: testOverlay})
	if err != nil {
		t.Fatal(err)
	}
	if got := (*calls)[0]; got[0] != "powershell" || got[len(got)-1] != want {
		t.Fatalf("script changed: %q", got)
	}

	fakeNRPT(t, nil, nil)
	if msg := NRPTGroupPolicyWarning(testMagic); msg != "" {
		t.Fatalf("no policy warned: %q", msg)
	}
}
