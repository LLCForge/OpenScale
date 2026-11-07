package trust

import (
	"net/netip"
	"testing"
)

func TestDNSSettingsValidation(t *testing.T) {
	_, doc := policyDoc(t)
	vps, _ := doc.DeviceByName("vps")
	nas, _ := doc.DeviceByName("masaustu")
	good := &DNSSettings{
		Nameservers: []netip.Addr{vps.IPv4, vps.IPv6},
		Split: []SplitDNS{
			{Domain: "ev.lan", Nameservers: []netip.Addr{nas.IPv4}},
			{Domain: "lan2", Nameservers: []netip.Addr{nas.IPv6, vps.IPv4}},
		},
	}
	if err := doc.SetDNS(good); err != nil {
		t.Fatalf("valid dns rejected: %v", err)
	}
	// SetDNS copies its input.
	good.Nameservers[0] = netip.MustParseAddr("8.8.8.8")
	if doc.DNS.Nameservers[0] != vps.IPv4 {
		t.Fatal("SetDNS must copy the settings")
	}

	unused := netip.MustParseAddr("100.80.0.200")
	bad := map[string]*DNSSettings{
		"empty":            {},
		"public resolver":  {Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
		"unused overlay":   {Nameservers: []netip.Addr{unused}},
		"magicdns ipv4":    {Nameservers: []netip.Addr{doc.DNSResolverIPv4()}},
		"magicdns ipv6":    {Nameservers: []netip.Addr{doc.DNSResolverIPv6()}},
		"zero address":     {Nameservers: []netip.Addr{{}}},
		"duplicate":        {Nameservers: []netip.Addr{vps.IPv4, vps.IPv4}},
		"too many":         {Nameservers: []netip.Addr{vps.IPv4, vps.IPv6, nas.IPv4, nas.IPv6, unused}},
		"magic domain":     {Split: []SplitDNS{{Domain: DefaultDNSDomain, Nameservers: []netip.Addr{vps.IPv4}}}},
		"below magic":      {Split: []SplitDNS{{Domain: "x." + DefaultDNSDomain, Nameservers: []netip.Addr{vps.IPv4}}}},
		"above magic":      {Split: []SplitDNS{{Domain: "internal", Nameservers: []netip.Addr{vps.IPv4}}}},
		"uppercase":        {Split: []SplitDNS{{Domain: "Ev.lan", Nameservers: []netip.Addr{vps.IPv4}}}},
		"trailing dot":     {Split: []SplitDNS{{Domain: "ev.lan.", Nameservers: []netip.Addr{vps.IPv4}}}},
		"no resolver":      {Split: []SplitDNS{{Domain: "ev.lan"}}},
		"duplicate domain": {Split: []SplitDNS{{Domain: "ev.lan", Nameservers: []netip.Addr{vps.IPv4}}, {Domain: "ev.lan", Nameservers: []netip.Addr{nas.IPv4}}}},
		"public split":     {Split: []SplitDNS{{Domain: "ev.lan", Nameservers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}}},
	}
	for name, s := range bad {
		if err := doc.SetDNS(s); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
	if len(doc.DNS.Split) != 2 {
		t.Fatal("rejected settings must keep the previous ones")
	}
	if err := doc.SetDNS(nil); err != nil || doc.DNS != nil {
		t.Fatalf("removing dns: %v", err)
	}
}

func TestDNSCustomDomainIsReserved(t *testing.T) {
	f := newFixture(t)
	f.doc.DNSDomain = "ag.ev"
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	_, req := newRequest(t, "a")
	d, err := doc.AddDevice(req, "a", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"ag.ev", "x.ag.ev", "ev", DefaultDNSDomain} {
		if err := doc.SetDNS(&DNSSettings{Split: []SplitDNS{{Domain: domain, Nameservers: []netip.Addr{d.IPv4}}}}); err == nil {
			t.Errorf("domain %s overlaps MagicDNS and must be rejected", domain)
		}
	}
}

func TestRevokeRemovesDNSResolvers(t *testing.T) {
	_, doc := policyDoc(t)
	vps, _ := doc.DeviceByName("vps")
	nas, _ := doc.DeviceByName("masaustu")
	if err := doc.SetDNS(&DNSSettings{
		Nameservers: []netip.Addr{vps.IPv4},
		Split: []SplitDNS{
			{Domain: "ev.lan", Nameservers: []netip.Addr{vps.IPv6}},
			{Domain: "is.lan", Nameservers: []netip.Addr{vps.IPv4, nas.IPv4}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.RevokeDevice("vps", testNow); err != nil {
		t.Fatalf("revoke with dns references: %v", err)
	}
	if doc.DNS == nil || len(doc.DNS.Nameservers) != 0 || len(doc.DNS.Split) != 1 || doc.DNS.Split[0].Domain != "is.lan" {
		t.Fatalf("dns not cleaned: %+v", doc.DNS)
	}
	if _, err := doc.RevokeDevice("masaustu", testNow); err != nil {
		t.Fatal(err)
	}
	if doc.DNS != nil {
		t.Fatalf("empty dns section must be removed: %+v", doc.DNS)
	}
}

func TestDNSResolverIPv6(t *testing.T) {
	f := newFixture(t)
	f.doc.IPv6Prefix = netip.MustParsePrefix("fd00:1:2::/120")
	doc, _ := f.doc.Next(testNow, DefaultValidity)
	if got := doc.DNSResolverIPv6().String(); got != "fd00:1:2::fe" {
		t.Fatalf("resolver %s", got)
	}
	f2 := newFixture(t)
	if r := f2.doc.DNSResolverIPv6(); !isHostAddr(f2.doc.IPv6Prefix, r) {
		t.Fatalf("resolver %s is not a host address of %s", r, f2.doc.IPv6Prefix)
	}
	// The allocator skips the IPv6 resolver: with ::1-::fd taken, the next
	// free address is ::ff, not the resolver ::fe.
	synthetic := *doc
	synthetic.Devices = nil
	for a := netip.MustParseAddr("fd00:1:2::1"); a != doc.DNSResolverIPv6(); a = a.Next() {
		synthetic.Devices = append(synthetic.Devices, Device{IPv6: a})
	}
	if a, err := synthetic.freeAddr(synthetic.IPv6Prefix); err != nil || a.String() != "fd00:1:2::ff" {
		t.Fatalf("freeAddr = %v %v; the resolver must be skipped", a, err)
	}
	// A device placed on the resolver address is rejected.
	_, req := newRequest(t, "a")
	if _, err := doc.AddDevice(req, "a", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	doc.Devices[0].IPv6 = doc.DNSResolverIPv6()
	if err := doc.Validate(); err == nil {
		t.Fatal("device on the IPv6 resolver address must be rejected")
	}
}
