package osnet

import "testing"

// Captured from Ubuntu 24.04 with Tailscale 1.x (iptables -S ts-input).
const tsInput = `-N ts-input
-A ts-input -s 100.101.102.103/32 -i lo -j ACCEPT
-A ts-input -i tailscale0 -j ACCEPT
-A ts-input -p udp -m udp --dport 41641 -j ACCEPT
-A ts-input -s 100.115.92.0/23 ! -i tailscale0 -j RETURN
-A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
`

func TestTailscaleDropsTunnel(t *testing.T) {
	if !tailscaleDropsTunnel(tsInput, "OpenScale") {
		t.Fatal("Tailscale's CGNAT drop not found")
	}
	fixed := "-N ts-input\n-A ts-input -i OpenScale -j ACCEPT\n" + tsInput[len("-N ts-input\n"):]
	if tailscaleDropsTunnel(fixed, "OpenScale") {
		t.Fatal("an exception for the tunnel before the drop still reported")
	}
	if tailscaleDropsTunnel("", "OpenScale") || tailscaleDropsTunnel("iptables: No chain/target/match by that name.", "OpenScale") {
		t.Fatal("no Tailscale chain reported as a conflict")
	}
	// Another interface's exception does not help the tunnel.
	other := "-A ts-input -i docker0 -j ACCEPT\n" + tsInput
	if !tailscaleDropsTunnel(other, "OpenScale") {
		t.Fatal("exception for another interface hid the conflict")
	}
}
