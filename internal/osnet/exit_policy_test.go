package osnet

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseExitPorts(t *testing.T) {
	got, err := ParseExitPorts(" 25, udp/1900 ,tcp/465,25,TCP/587")
	if err != nil {
		t.Fatal(err)
	}
	want := []ExitPort{{"tcp", 25}, {"tcp", 465}, {"tcp", 587}, {"udp", 1900}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	for _, s := range []string{"", "none", "NONE"} {
		if p, err := ParseExitPorts(s); err != nil || p != nil {
			t.Fatalf("%q: %v %v", s, p, err)
		}
	}
	for _, s := range []string{"0", "65536", "icmp/1", "tcp/", "x", "-1"} {
		if _, err := ParseExitPorts(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	var many []string
	for i := 1; i <= MaxExitBlockedPorts+1; i++ {
		many = append(many, strconv.Itoa(1000+i))
	}
	if _, err := ParseExitPorts(strings.Join(many, ",")); err == nil {
		t.Fatal("too many ports accepted")
	}
}

func TestParseDoHList(t *testing.T) {
	in := "# Cloudflare\n1.1.1.1\n1.0.0.1 # second\n\n2606:4700:4700::1111\n8.8.8.0/24\n1.1.1.1\n::ffff:9.9.9.9\n"
	got, err := ParseDoHList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("1.0.0.1/32"),
		netip.MustParsePrefix("2606:4700:4700::1111/128"), netip.MustParsePrefix("8.8.8.0/24"),
		netip.MustParsePrefix("9.9.9.9/32"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"0.0.0.0/0", "8.0.0.0/8", "10.0.0.1", "192.168.1.0/24", "fe80::1", "2000::/16", "dns.google", "1.1.1.1%eth0", "127.0.0.1"} {
		if _, err := ParseDoHList(strings.NewReader(bad + "\n")); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseDoHList(strings.NewReader(strings.Repeat("a", maxDoHLine+1))); err == nil {
		t.Fatal("long line accepted")
	}
}

var testPolicyNAT = ExitNAT{
	Interface: "OpenScale",
	IPv4:      netip.MustParsePrefix("100.80.0.0/16"),
	IPv6:      netip.MustParsePrefix("fd7a:1:2::/48"),
}

func FuzzParseDoHList(f *testing.F) {
	f.Add("1.1.1.1\n# x\n2606:4700::/32\n")
	f.Add("::ffff:1.2.3.4/120\n")
	f.Fuzz(func(t *testing.T, s string) {
		list, err := ParseDoHList(strings.NewReader(s))
		if err != nil {
			return
		}
		c := testPolicyNAT
		c.BlockDoH = list
		if err := c.validatePolicy(); err != nil {
			t.Fatalf("parsed list fails validation: %v (%v)", err, list)
		}
	})
}

func FuzzParseExitPorts(f *testing.F) {
	f.Add("25,udp/1900")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseExitPorts(s)
		if err != nil {
			return
		}
		c := testPolicyNAT
		c.BlockPorts = p
		if err := c.validatePolicy(); err != nil {
			t.Fatalf("parsed ports fail validation: %v (%v)", err, p)
		}
	})
}

func TestValidatePolicySources(t *testing.T) {
	ok := testPolicyNAT
	ok.Sources = []ExitSource{
		{Source: netip.MustParseAddr("203.0.113.5")},
		{Source: netip.MustParseAddr("2001:db8::5")},
		{Member: netip.MustParseAddr("100.80.0.7"), Source: netip.MustParseAddr("203.0.113.6")},
	}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string][]ExitSource{
		"two defaults":    {{Source: netip.MustParseAddr("203.0.113.5")}, {Source: netip.MustParseAddr("203.0.113.6")}},
		"family mismatch": {{Member: netip.MustParseAddr("100.80.0.7"), Source: netip.MustParseAddr("2001:db8::5")}},
		"not a member":    {{Member: netip.MustParseAddr("100.81.0.7"), Source: netip.MustParseAddr("203.0.113.6")}},
		"loopback":        {{Source: netip.MustParseAddr("127.0.0.1")}},
		"duplicate": {
			{Member: netip.MustParseAddr("100.80.0.7"), Source: netip.MustParseAddr("203.0.113.6")},
			{Member: netip.MustParseAddr("100.80.0.7"), Source: netip.MustParseAddr("203.0.113.7")},
		},
	} {
		c := testPolicyNAT
		c.Sources = src
		if err := c.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
