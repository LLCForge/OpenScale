package trust

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestMagicDNSRecordsValidation(t *testing.T) {
	_, doc := policyDoc(t)
	nas, _ := doc.DeviceByName("masaustu")
	good := &MagicDNSSettings{
		Search: []string{DefaultDNSDomain},
		Records: []DNSRecord{
			{Name: "nas", Type: RecordA, Value: "192.168.1.10"},
			{Name: "pano", Type: RecordCNAME, Value: "masaustu." + DefaultDNSDomain},
			{Name: "dis", Type: RecordCNAME, Value: "example.com"},
			{Name: "_rdp._tcp.masaustu", Type: RecordSRV, Value: "masaustu." + DefaultDNSDomain, Priority: 10, Weight: 5, Port: 3389},
			{Name: "*.lab", Type: RecordA, Value: nas.IPv4.String()},
			{Name: "bilgi", Type: RecordTXT, Value: "v=1 ev agi"},
		},
		DeviceSubdomains: true,
	}
	if err := doc.SetMagicDNS(good); err != nil {
		t.Fatalf("valid magic_dns rejected: %v", err)
	}
	good.Records[0].Value = "8.8.8.8"
	if doc.MagicDNS.Records[0].Value != "192.168.1.10" {
		t.Fatal("SetMagicDNS must copy its input")
	}

	rec := func(r ...DNSRecord) *MagicDNSSettings { return &MagicDNSSettings{Records: r} }
	bad := map[string]*MagicDNSSettings{
		"empty":              {},
		"device name":        rec(DNSRecord{Name: "laptop", Type: RecordA, Value: "192.168.1.2"}),
		"coordinator":        rec(DNSRecord{Name: CoordinatorName, Type: RecordA, Value: "192.168.1.2"}),
		"uppercase":          rec(DNSRecord{Name: "NAS", Type: RecordA, Value: "192.168.1.2"}),
		"non canonical":      rec(DNSRecord{Name: "nas", Type: RecordAAAA, Value: "FD00::1"}),
		"v6 in A":            rec(DNSRecord{Name: "nas", Type: RecordA, Value: "fd00::1"}),
		"unused overlay":     rec(DNSRecord{Name: "nas", Type: RecordA, Value: "100.80.0.200"}),
		"multicast":          rec(DNSRecord{Name: "nas", Type: RecordA, Value: "224.0.0.1"}),
		"unknown type":       rec(DNSRecord{Name: "nas", Type: "MX", Value: "x.example"}),
		"missing target":     rec(DNSRecord{Name: "nas", Type: RecordCNAME, Value: "yok." + DefaultDNSDomain}),
		"self cname":         rec(DNSRecord{Name: "nas", Type: RecordCNAME, Value: "nas." + DefaultDNSDomain}),
		"cname and a":        rec(DNSRecord{Name: "nas", Type: RecordCNAME, Value: "example.com"}, DNSRecord{Name: "nas", Type: RecordA, Value: "192.168.1.2"}),
		"cname loop":         rec(DNSRecord{Name: "a", Type: RecordCNAME, Value: "b." + DefaultDNSDomain}, DNSRecord{Name: "b", Type: RecordCNAME, Value: "a." + DefaultDNSDomain}),
		"srv without port":   rec(DNSRecord{Name: "_x._tcp", Type: RecordSRV, Value: "laptop." + DefaultDNSDomain}),
		"port on A":          rec(DNSRecord{Name: "nas", Type: RecordA, Value: "192.168.1.2", Port: 80}),
		"bare wildcard":      rec(DNSRecord{Name: "*", Type: RecordA, Value: "192.168.1.2"}),
		"wildcard cname":     rec(DNSRecord{Name: "*.lab", Type: RecordCNAME, Value: "example.com"}),
		"txt control":        rec(DNSRecord{Name: "t", Type: RecordTXT, Value: "a\nb"}),
		"duplicate":          rec(DNSRecord{Name: "nas", Type: RecordA, Value: "192.168.1.2"}, DNSRecord{Name: "nas", Type: RecordA, Value: "192.168.1.2"}),
		"public search":      {Search: []string{"example.com"}},
		"duplicate search":   {Search: []string{DefaultDNSDomain, DefaultDNSDomain}},
		"trailing dot value": rec(DNSRecord{Name: "nas", Type: RecordCNAME, Value: "example.com."}),
	}
	for name, s := range bad {
		if err := doc.SetMagicDNS(s); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
	if len(doc.MagicDNS.Records) != 6 {
		t.Fatal("rejected settings must keep the previous ones")
	}
	if err := doc.SetMagicDNS(nil); err != nil || doc.MagicDNS != nil {
		t.Fatalf("removing magic_dns: %v", err)
	}
}

func TestMagicDNSSearchFollowsSplitDomains(t *testing.T) {
	_, doc := policyDoc(t)
	vps, _ := doc.DeviceByName("vps")
	if err := doc.SetMagicDNS(&MagicDNSSettings{Search: []string{"ev.lan"}}); err == nil {
		t.Fatal("search domain without a split entry accepted")
	}
	if err := doc.SetDNS(&DNSSettings{Split: []SplitDNS{{Domain: "ev.lan", Nameservers: []netip.Addr{vps.IPv4}}}}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetMagicDNS(&MagicDNSSettings{Search: []string{DefaultDNSDomain, "ev.lan"}}); err != nil {
		t.Fatal(err)
	}
	// Removing the split domain also removes it from the search list.
	if err := doc.SetDNS(nil); err != nil {
		t.Fatalf("removing dns: %v", err)
	}
	if got := doc.MagicDNS.Search; len(got) != 1 || got[0] != DefaultDNSDomain {
		t.Fatalf("search = %v", got)
	}
	// Revoking the split resolver's device too.
	if err := doc.SetDNS(&DNSSettings{Split: []SplitDNS{{Domain: "ev.lan", Nameservers: []netip.Addr{vps.IPv4}}}}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetMagicDNS(&MagicDNSSettings{Search: []string{"ev.lan"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.RevokeDevice("vps", testNow); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if doc.MagicDNS != nil {
		t.Fatalf("empty magic_dns left behind: %+v", doc.MagicDNS)
	}
}

func TestDeviceAliases(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceAliases("masaustu", []string{"nas", "pano"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"laptop"}, {"coordinator"}, {"Nas"}, {"a.b"}, {"x", "x"}} {
		if err := doc.SetDeviceAliases("vps", bad); err == nil {
			t.Errorf("alias %v accepted", bad)
		}
	}
	if err := doc.SetDeviceAliases("vps", []string{"nas"}); err == nil {
		t.Fatal("alias of another device accepted")
	}
	if err := doc.RenameDevice("laptop", "nas"); err == nil {
		t.Fatal("rename onto an alias accepted")
	}
	if err := doc.SetMagicDNS(&MagicDNSSettings{Records: []DNSRecord{{Name: "nas", Type: RecordA, Value: "192.168.1.5"}}}); err == nil {
		t.Fatal("record with an alias name accepted")
	}
	if err := doc.SetDeviceAliases("yok", []string{"x"}); err == nil {
		t.Fatal("unknown device accepted")
	}
}

func TestZoneFollowsRenameAndRevoke(t *testing.T) {
	_, doc := policyDoc(t)
	nas, _ := doc.DeviceByName("masaustu")
	if err := doc.SetDeviceAliases("masaustu", []string{"nas"}); err != nil {
		t.Fatal(err)
	}
	s := &MagicDNSSettings{Records: []DNSRecord{
		{Name: "_rdp._tcp.masaustu", Type: RecordSRV, Value: "masaustu." + DefaultDNSDomain, Port: 3389},
		{Name: "pano", Type: RecordCNAME, Value: "nas." + DefaultDNSDomain},
		{Name: "eski", Type: RecordCNAME, Value: "pano." + DefaultDNSDomain},
		{Name: "dosya", Type: RecordA, Value: nas.IPv4.String()},
		{Name: "dis", Type: RecordA, Value: "192.168.1.9"},
	}}
	if err := doc.SetMagicDNS(s); err != nil {
		t.Fatal(err)
	}
	if err := doc.RenameDevice("masaustu", "calisma"); err != nil {
		t.Fatal(err)
	}
	r := doc.MagicDNS.Records[0]
	if r.Name != "_rdp._tcp.calisma" || r.Value != "calisma."+DefaultDNSDomain {
		t.Fatalf("rename not followed: %+v", r)
	}
	if _, err := doc.RevokeDevice("calisma", testNow.Add(time.Second)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Only the record that does not depend on the device stays.
	if got := doc.MagicDNS.Records; len(got) != 1 || got[0].Name != "dis" {
		t.Fatalf("records after revoke = %+v", got)
	}
}

func TestZoneFieldsOmittedWhenEmpty(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"magic_dns", "aliases"} {
		if strings.Contains(string(data), field) {
			t.Fatalf("%s present in a document without it", field)
		}
	}
}
