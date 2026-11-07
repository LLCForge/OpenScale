package trust

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDNSProfileEncodingUnchangedWithout(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "dns_profiles") {
		t.Fatal("a document without profiles must not encode the field")
	}
	if err := doc.SetDNSProfile(DNSProfile{Name: "cocuk", Members: []string{"telefon"}, SafeSearch: true}); err != nil {
		t.Fatal(err)
	}
	if err := doc.RemoveDNSProfile("cocuk"); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(data) {
		t.Fatal("removing the last profile must restore the previous encoding")
	}
}

func TestDNSProfileFor(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceTags("telefon", []string{"cocuk"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetGroup("sunucular", []string{"vps"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []DNSProfile{
		{Name: "siki", Members: []string{"tag:cocuk"}, SafeSearch: true},
		{Name: "acik", Members: []string{"group:sunucular", "laptop"}, NoBlocklist: true},
	} {
		if err := doc.SetDNSProfile(p); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]string{"telefon": "siki", "vps": "acik", "laptop": "acik", "masaustu": ""}
	for dev, want := range cases {
		p, ok := doc.DNSProfileFor(dev)
		if (want == "") == ok || p.Name != want {
			t.Fatalf("%s: got %q %v, want %q", dev, p.Name, ok, want)
		}
	}
	// Replacing keeps the order; the first match wins.
	if err := doc.SetDNSProfile(DNSProfile{Name: "siki", Members: []string{"laptop"}}); err != nil {
		t.Fatal(err)
	}
	if p, _ := doc.DNSProfileFor("laptop"); p.Name != "siki" {
		t.Fatalf("first profile must win, got %q", p.Name)
	}
}

func TestDNSProfileValidate(t *testing.T) {
	bad := []DNSProfile{
		{Name: "Cocuk", Members: []string{"laptop"}},
		{Name: "x", Members: nil},
		{Name: "x", Members: []string{"yok"}},
		{Name: "x", Members: []string{"*"}},
		{Name: "x", Members: []string{"10.0.0.0/8"}},
		{Name: "x", Members: []string{"group:yok"}},
		{Name: "x", Members: []string{"laptop", "laptop"}},
		{Name: "x", Members: []string{"tag:Buyuk"}},
	}
	for _, p := range bad {
		_, doc := policyDoc(t)
		if err := doc.SetDNSProfile(p); err == nil {
			t.Fatalf("%+v must be refused", p)
		}
		if doc.DNSProfiles != nil {
			t.Fatal("a refused profile must leave the document unchanged")
		}
	}
	_, doc := policyDoc(t)
	doc.DNSProfiles = []DNSProfile{}
	if err := doc.Validate(); err == nil {
		t.Fatal("an empty but present list must be refused")
	}
	doc.DNSProfiles = nil
	for i := 0; i < MaxDNSProfiles; i++ {
		doc.DNSProfiles = append(doc.DNSProfiles, DNSProfile{Name: "p" + strings.Repeat("a", i+1), Members: []string{"laptop"}})
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	doc.DNSProfiles = append(doc.DNSProfiles, DNSProfile{Name: "fazla", Members: []string{"laptop"}})
	if err := doc.Validate(); err == nil {
		t.Fatal("too many profiles must be refused")
	}
	doc.DNSProfiles = []DNSProfile{{Name: "a", Members: []string{"laptop"}}, {Name: "a", Members: []string{"vps"}}}
	if err := doc.Validate(); err == nil {
		t.Fatal("duplicate names must be refused")
	}
}

func TestDNSProfileRevokeAndRename(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDNSProfile(DNSProfile{Name: "tek", Members: []string{"telefon"}}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetDNSProfile(DNSProfile{Name: "iki", Members: []string{"telefon", "vps"}}); err != nil {
		t.Fatal(err)
	}
	if err := doc.RenameDevice("vps", "sunucu"); err != nil {
		t.Fatal(err)
	}
	if p, ok := doc.DNSProfileFor("sunucu"); !ok || p.Name != "iki" {
		t.Fatal("rename must follow into profiles")
	}
	if _, err := doc.RevokeDevice("telefon", testNow); err != nil {
		t.Fatal(err)
	}
	if len(doc.DNSProfiles) != 1 || doc.DNSProfiles[0].Name != "iki" || len(doc.DNSProfiles[0].Members) != 1 {
		t.Fatalf("revocation must drop the device and empty profiles: %+v", doc.DNSProfiles)
	}
	if _, err := doc.RevokeDevice("sunucu", testNow); err != nil {
		t.Fatal(err)
	}
	if doc.DNSProfiles != nil {
		t.Fatal("the last empty profile must remove the field")
	}
}
