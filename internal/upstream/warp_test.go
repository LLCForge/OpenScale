package upstream

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// warpStyle is a configuration in the shape Cloudflare WARP generators
// write: MTU, an IPv6 address and two AllowedIPs lines, and a named
// endpoint (documentation names and ranges only).
func warpStyle(priv, peer, endpoint string) string {
	return "[Interface]\n" +
		"PrivateKey = " + priv + "\n" +
		"Address = 172.16.0.2/32\n" +
		"Address = 2001:db8:110::2/128\n" +
		"DNS = 192.0.2.53\n" +
		"MTU = 1280\n" +
		"[Peer]\n" +
		"PublicKey = " + peer + "\n" +
		"AllowedIPs = 0.0.0.0/0\n" +
		"AllowedIPs = ::/0\n" +
		"Endpoint = " + endpoint + "\n"
}

func fixedResolver(a string, calls *int) Resolver {
	return func(host string) (netip.Addr, error) {
		*calls++
		if host != "engage.example.net" {
			return netip.Addr{}, errors.New("unexpected host " + host)
		}
		return netip.ParseAddr(a)
	}
}

func TestParseWARP(t *testing.T) {
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	conf := warpStyle(priv, peer, "engage.example.net:2408")

	// Without a resolver a name is refused, as before.
	if _, err := Parse([]byte(conf)); err == nil || !strings.Contains(err.Error(), "IP:port") {
		t.Fatalf("name accepted without a resolver: %v", err)
	}
	calls := 0
	c, err := ParseWith([]byte(conf), fixedResolver("198.51.100.7", &calls))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || c.Endpoint != netip.MustParseAddrPort("198.51.100.7:2408") || c.EndpointHost != "engage.example.net" {
		t.Fatalf("endpoint %v host %q calls %d", c.Endpoint, c.EndpointHost, calls)
	}
	if c.MTU != 1280 || !c.IPv6 || c.Address6 != netip.MustParseAddr("2001:db8:110::2") {
		t.Fatalf("mtu %d ipv6 %v %v", c.MTU, c.IPv6, c.Address6)
	}
	// The canonical file keeps the address and the MTU, never the name.
	out := string(c.Marshal())
	if strings.Contains(out, "engage") || !strings.Contains(out, "Endpoint = 198.51.100.7:2408") || !strings.Contains(out, "MTU = 1280") {
		t.Fatalf("canonical form:\n%s", out)
	}
	again, err := Parse([]byte(out))
	if err != nil || again.MTU != 1280 || again.Endpoint != c.Endpoint {
		t.Fatalf("round trip: %v %+v", err, again)
	}
	// An IPv4 answer and an IPv4-mapped answer are the same address.
	calls = 0
	c, err = ParseWith([]byte(conf), fixedResolver("::ffff:198.51.100.7", &calls))
	if err != nil || c.Endpoint.Addr() != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("mapped answer: %v %v", err, c)
	}
}

func TestParseWARPRejects(t *testing.T) {
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	base := warpStyle(priv, peer, "engage.example.net:2408")
	cases := map[string]struct {
		conf   string
		answer string
		// queried: whether the resolver may be asked at all.
		queried bool
	}{
		"mtu low":         {strings.Replace(base, "MTU = 1280", "MTU = 1279", 1), "198.51.100.7", false},
		"mtu high":        {strings.Replace(base, "MTU = 1280", "MTU = 1421", 1), "198.51.100.7", false},
		"mtu text":        {strings.Replace(base, "MTU = 1280", "MTU = auto", 1), "198.51.100.7", false},
		"mtu plus":        {strings.Replace(base, "MTU = 1280", "MTU = +1300", 1), "198.51.100.7", false},
		"mtu twice":       {strings.Replace(base, "MTU = 1280", "MTU = 1280\nMTU = 1300", 1), "198.51.100.7", false},
		"reserved":        {strings.Replace(base, "MTU = 1280", "MTU = 1280\nReserved = 1, 2, 3", 1), "198.51.100.7", false},
		"peer mtu":        {base + "MTU = 1280\n", "198.51.100.7", false},
		"single label":    {warpStyle(priv, peer, "engage:2408"), "198.51.100.7", false},
		"numeric label":   {warpStyle(priv, peer, "198.51.100.300:2408"), "198.51.100.7", false},
		"underscore":      {warpStyle(priv, peer, "en_gage.example.net:2408"), "198.51.100.7", false},
		"no port":         {warpStyle(priv, peer, "engage.example.net"), "198.51.100.7", false},
		"port 0":          {warpStyle(priv, peer, "engage.example.net:0"), "198.51.100.7", false},
		"bad file first":  {strings.Replace(base, "DNS = 192.0.2.53\n", "", 1), "198.51.100.7", false},
		"loopback answer": {base, "127.0.0.1", true},
		"zero answer":     {base, "0.0.0.0", true},
		"multicast":       {base, "224.0.0.1", true},
		"lookup fails":    {base, "", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			resolve := func(string) (netip.Addr, error) {
				calls++
				if tc.answer == "" {
					return netip.Addr{}, errors.New("no such host")
				}
				return netip.ParseAddr(tc.answer)
			}
			_, err := ParseWith([]byte(tc.conf), resolve)
			if err == nil {
				t.Fatal("accepted")
			}
			var ce *ConfError
			if !errors.As(err, &ce) {
				t.Fatalf("error type %T", err)
			}
			if !tc.queried && calls != 0 {
				t.Fatalf("a refused file sent %d DNS queries", calls)
			}
			if strings.Contains(err.Error(), priv) {
				t.Fatal("error message quotes the private key")
			}
		})
	}
}

func TestStoreImportWARPAndKinds(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	calls := 0
	cfg, err := st.ImportWith("warp", "Cloudflare WARP", []byte(warpStyle(priv, peer, "engage.example.net:2408")),
		ImportOptions{Resolve: fixedResolver("198.51.100.7", &calls), Provider: ProviderWARP})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Wipe()
	if _, err := st.ImportWith("x", "", []byte(mullvadStyle(priv, peer, "198.51.100.20:51820")), ImportOptions{Provider: "nordvpn"}); err == nil {
		t.Fatal("unknown provider kind accepted")
	}
	// The stored profile needs no resolver any more.
	loaded, err := st.Load("warp")
	if err != nil || loaded.Endpoint != netip.MustParseAddrPort("198.51.100.7:2408") || loaded.MTU != 1280 {
		t.Fatalf("load: %v %+v", err, loaded)
	}
	loaded.Wipe()

	if err := st.Use("warp"); err != nil {
		t.Fatal(err)
	}
	s, _ := st.Settings()
	if s.Kind() != ProviderWARP || s.Provider("other") != ProviderWireGuard {
		t.Fatalf("kind %q", s.Kind())
	}
	// Tor replaces the active profile, and "use" replaces Tor.
	prev, err := st.EnableTor(0, 0)
	if err != nil || prev != "warp" {
		t.Fatalf("enable tor: %q %v", prev, err)
	}
	s, _ = st.Settings()
	if s.Active != "" || !s.TorEnabled() || s.Kind() != KindTor {
		t.Fatalf("settings %+v", s)
	}
	if trans, dns := s.Tor.Ports(); trans != DefaultTorTransPort || dns != DefaultTorDNSPort {
		t.Fatalf("ports %d %d", trans, dns)
	}
	if _, err := st.EnableTor(9050, 9050); err == nil {
		t.Fatal("same port for TransPort and DNSPort accepted")
	}
	if err := st.Use("warp"); err != nil {
		t.Fatal(err)
	}
	if s, _ = st.Settings(); s.TorEnabled() || s.Active != "warp" {
		t.Fatalf("use did not replace tor: %+v", s)
	}
	// A hand-edited file with both is refused.
	if err := st.UpdateSettings(func(s *Settings) error {
		s.Tor = &TorSettings{Enabled: true}
		return nil
	}); err == nil {
		t.Fatal("tor and a profile active together")
	}
	if err := st.Remove("warp"); err == nil {
		t.Fatal("active profile removed")
	}
	if was, err := st.DisableTor(); err != nil || was {
		t.Fatalf("disable tor: %v %v", was, err)
	}
}

// TestManagerProviderMTU: the tunnel uses the file's MTU (WARP: 1280)
// unless the owner chose one with "use --mtu".
func TestManagerProviderMTU(t *testing.T) {
	priv, _ := testKeys(t)
	_, peer := testKeys(t)
	h := newHarness(t, warpStyle(priv, peer, "127.0.0.1:9"))
	if err := h.store.Use("se-got"); err != nil {
		t.Fatal(err)
	}
	h.m.SetRole(true)
	applied, _, _ := h.router.snapshot()
	if len(applied) != 2 || applied[1].MTU != 1280 {
		t.Fatalf("routes %+v", applied)
	}
	if err := h.store.UpdateSettings(func(s *Settings) error { s.MTU = 1400; return nil }); err != nil {
		t.Fatal(err)
	}
	h.m.Tick()
	applied, _, _ = h.router.snapshot()
	if last := applied[len(applied)-1]; last.MTU != 1400 {
		t.Fatalf("owner MTU ignored: %+v", last)
	}
	if s := h.m.Status(); s.Kind != ProviderWireGuard {
		t.Fatalf("kind %q", s.Kind)
	}
}
