package osnet

import "testing"

func TestNetworkFingerprint(t *testing.T) {
	salt := []byte("0123456789abcdef")
	home := []CurrentNetwork{{Kind: NetworkWiFi, Name: "Ev"}}
	fp := NetworkFingerprint(home, salt)
	if len(fp) != NetworkFingerprintLen {
		t.Fatalf("len %d", len(fp))
	}
	if NetworkFingerprint(home, salt) != fp {
		t.Fatal("not stable")
	}
	if NetworkFingerprint([]CurrentNetwork{{Kind: NetworkWiFi, Name: "Otel"}}, salt) == fp {
		t.Fatal("different networks share a fingerprint")
	}
	if NetworkFingerprint(home, []byte("another-salt----")) == fp {
		t.Fatal("salt ignored")
	}
	two := []CurrentNetwork{{Kind: NetworkWiFi, Name: "B"}, {Kind: NetworkWiFi, Name: "A"}}
	rev := []CurrentNetwork{{Kind: NetworkWiFi, Name: "A"}, {Kind: NetworkWiFi, Name: "B"}}
	if NetworkFingerprint(two, salt) != NetworkFingerprint(rev, salt) {
		t.Fatal("order matters")
	}
	for name, nets := range map[string][]CurrentNetwork{
		"none":    nil,
		"wired":   {{Kind: NetworkWired, Name: "Ethernet"}},
		"mixed":   {{Kind: NetworkWiFi, Name: "Ev"}, {Kind: NetworkWired, Name: "Ethernet"}},
		"unnamed": {{Kind: NetworkWiFi, Name: ""}},
	} {
		if got := NetworkFingerprint(nets, salt); got != "" {
			t.Errorf("%s: %q, want none", name, got)
		}
	}
	if NetworkFingerprint(home, nil) != "" {
		t.Fatal("empty salt")
	}
}
