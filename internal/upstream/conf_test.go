package upstream

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// testKeys returns a private key and its public key in base64.
func testKeys(t testing.TB) (priv, pub string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// mullvadStyle is a configuration in the shape the provider's generator
// writes (addresses from documentation ranges).
func mullvadStyle(priv, peer, endpoint string) string {
	return "[Interface]\n" +
		"# Device: Neat Otter\n" +
		"PrivateKey = " + priv + "\n" +
		"Address = 10.68.12.34/32,fc00:bbbb:bbbb:bb01::5:c21/128\n" +
		"DNS = 10.64.0.1\n\n" +
		"[Peer]\n" +
		"PublicKey = " + peer + "\n" +
		"AllowedIPs = 0.0.0.0/0,::0/0\n" +
		"Endpoint = " + endpoint + "\n"
}

func TestParseProviderFile(t *testing.T) {
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	c, err := Parse([]byte("\xef\xbb\xbf" + strings.ReplaceAll(mullvadStyle(priv, peer, "198.51.100.20:51820"), "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Address4 != netip.MustParseAddr("10.68.12.34") || c.Address6 != netip.MustParseAddr("fc00:bbbb:bbbb:bb01::5:c21") {
		t.Fatalf("addresses %v %v", c.Address4, c.Address6)
	}
	if len(c.DNS) != 1 || c.DNS[0] != netip.MustParseAddr("10.64.0.1") || !c.IPv6 {
		t.Fatalf("dns %v ipv6 %v", c.DNS, c.IPv6)
	}
	if c.Endpoint != netip.MustParseAddrPort("198.51.100.20:51820") {
		t.Fatalf("endpoint %v", c.Endpoint)
	}
	if base64.StdEncoding.EncodeToString(c.PeerKey[:]) != peer {
		t.Fatal("peer key")
	}
	srv, src, ok := c.ResolverFor()
	if !ok || srv != c.DNS[0] || src != c.Address4 {
		t.Fatalf("resolver %v from %v", srv, src)
	}

	// Canonical form parses to the same configuration and drops comments.
	out := c.Marshal()
	if bytes.Contains(out, []byte("Neat Otter")) {
		t.Fatal("comment kept")
	}
	again, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if again.PrivateKey != c.PrivateKey || again.PeerKey != c.PeerKey || again.Endpoint != c.Endpoint ||
		again.Address4 != c.Address4 || again.Address6 != c.Address6 || again.IPv6 != c.IPv6 || len(again.DNS) != 1 {
		t.Fatalf("round trip changed the configuration:\n%s", out)
	}
	c.Wipe()
	if c.PrivateKey != ([32]byte{}) {
		t.Fatal("Wipe left the key")
	}
}

func TestParseIPv4Only(t *testing.T) {
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	conf := "[Interface]\nPrivateKey=" + priv + "\nAddress=10.2.0.2/32, fd00::2/128\nDNS=10.2.0.1\n[Peer]\nPublicKey=" + peer + "\nAllowedIPs=0.0.0.0/0\nEndpoint=[2001:db8::7]:51820\n"
	c, err := Parse([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if c.IPv6 || c.Address6.IsValid() {
		t.Fatal("IPv6 address kept without ::/0")
	}
	if c.Endpoint.Addr() != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("endpoint %v", c.Endpoint)
	}
}

func TestParseRejects(t *testing.T) {
	priv, pub := testKeys(t)
	_, peer := testKeys(t)
	base := mullvadStyle(priv, peer, "198.51.100.20:51820")
	cases := map[string]string{
		"PostUp":            strings.Replace(base, "DNS = 10.64.0.1", "DNS = 10.64.0.1\nPostUp = curl evil", 1),
		"PresharedKey":      base + "PresharedKey = " + priv + "\n",
		"MTU out of range":  strings.Replace(base, "DNS = 10.64.0.1", "DNS = 10.64.0.1\nMTU = 9000", 1),
		"Table":             strings.Replace(base, "DNS = 10.64.0.1", "DNS = 10.64.0.1\nTable = off", 1),
		"PersistentKA":      base + "PersistentKeepalive = 25\n",
		"two peers":         base + "[Peer]\nPublicKey = " + peer + "\n",
		"hostname endpoint": mullvadStyle(priv, peer, "se-got-wg-001.example:51820"),
		"port 0":            mullvadStyle(priv, peer, "198.51.100.20:0"),
		"split allowed":     strings.Replace(base, "0.0.0.0/0,::0/0", "0.0.0.0/1,128.0.0.0/1", 1),
		"v6 only allowed":   strings.Replace(base, "0.0.0.0/0,::0/0", "::/0", 1),
		"no dns":            strings.Replace(base, "DNS = 10.64.0.1\n", "", 1),
		"dns search domain": strings.Replace(base, "DNS = 10.64.0.1", "DNS = 10.64.0.1, corp.example", 1),
		"loopback dns":      strings.Replace(base, "DNS = 10.64.0.1", "DNS = 127.0.0.53", 1),
		"no address":        strings.Replace(base, "Address = 10.68.12.34/32,fc00:bbbb:bbbb:bb01::5:c21/128\n", "", 1),
		"v6 address only":   strings.Replace(base, "10.68.12.34/32,", "", 1),
		"two v4 addresses":  strings.Replace(base, "10.68.12.34/32", "10.68.12.34/32,10.68.12.35/32", 1),
		"bad key":           strings.Replace(base, priv, "bm90IGEga2V5", 1),
		"zero key":          strings.Replace(base, priv, base64.StdEncoding.EncodeToString(make([]byte, 32)), 1),
		"own key as peer":   mullvadStyle(priv, pub, "198.51.100.20:51820"),
		"duplicate key":     strings.Replace(base, "DNS = 10.64.0.1", "DNS = 10.64.0.1\nPrivateKey = "+priv, 1),
		"unknown section":   base + "[Extra]\n",
		"outside section":   "PrivateKey = " + priv + "\n" + base,
		"no equals":         base + "Endpoint\n",
		"control char":      strings.Replace(base, "DNS = 10.64.0.1", "DNS = 10.64.0.1\x00", 1),
		"empty":             "",
		"no peer":           "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n",
		"not utf8":          base + "# \xff\xfe\n",
		"too large":         base + strings.Repeat("#\n", MaxConfSize),
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(conf))
			if err == nil {
				t.Fatal("accepted")
			}
			var ce *ConfError
			if !errors.As(err, &ce) {
				t.Fatalf("error type %T", err)
			}
			if strings.Contains(err.Error(), priv) {
				t.Fatal("error message quotes the private key")
			}
		})
	}
}

func TestNameFromFile(t *testing.T) {
	cases := map[string]string{
		"se-got-wg-001.conf":                "se-got-wg-001",
		"/home/u/Downloads/Mullvad SE.conf": "mullvad-se",
		"___.conf":                          "",
		strings.Repeat("a", 40) + ".conf":   strings.Repeat("a", 32),
	}
	for in, want := range cases {
		if got := NameFromFile(in); got != want {
			t.Errorf("NameFromFile(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzParse: no input panics, and every accepted file survives the
// canonical round trip unchanged.
func FuzzParse(f *testing.F) {
	priv, _ := testKeys(f)
	_, peer := testKeys(f)
	f.Add([]byte(mullvadStyle(priv, peer, "198.51.100.20:51820")))
	f.Add([]byte("[Interface]\nPrivateKey=" + priv + "\nAddress=10.2.0.2\nDNS=10.2.0.1\n[Peer]\nPublicKey=" + peer + "\nAllowedIPs=0.0.0.0/0\nEndpoint=[2001:db8::7]:51820\n"))
	f.Add([]byte("[Interface]\n[Peer]\n= \n#\n[peer"))
	f.Add([]byte(warpStyle(priv, peer, "engage.example.net:2408")))
	f.Add([]byte(warpStyle(priv, peer, "198.51.100.7:2408")))
	// Names resolve to a fixed address, so the WARP path is fuzzed too.
	resolve := func(string) (netip.Addr, error) { return netip.MustParseAddr("198.51.100.7"), nil }
	f.Fuzz(func(t *testing.T, data []byte) {
		if w, err := ParseWith(data, resolve); err == nil {
			again, err := Parse(w.Marshal())
			if err != nil || !bytes.Equal(again.Marshal(), w.Marshal()) {
				t.Fatalf("resolved canonical form not stable: %v", err)
			}
		}
		c, err := Parse(data)
		if err != nil {
			return
		}
		again, err := Parse(c.Marshal())
		if err != nil {
			t.Fatalf("canonical form rejected: %v", err)
		}
		if !bytes.Equal(again.Marshal(), c.Marshal()) {
			t.Fatal("canonical form not stable")
		}
	})
}
