package plugin

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParseManifest(t *testing.T) {
	ok := []string{
		`{"abi":1,"name":"ornek-engel","version":"1.0.0","hooks":["dns"],"data":["dns_name"],"on_error":"pass"}`,
		`{"abi":1,"name":"a","version":"0.1+b","hooks":["dns","http_location"],"data":["http_location","client_tags","dns_name"],"on_error":"block"}`,
		`{"abi":1,"name":"bos","version":"1","hooks":[],"data":[],"on_error":"allow"}`,
		`{"abi":1,"name":"bos2","version":"1","on_error":"pass","description":"Açıklama: ğüşiöç"}`,
	}
	for _, s := range ok {
		if _, err := ParseManifest([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{
		``,
		`[]`,
		`{"abi":2,"name":"a","version":"1","on_error":"pass"}`,
		`{"abi":1,"name":"A","version":"1","on_error":"pass"}`,
		`{"abi":1,"name":"-a","version":"1","on_error":"pass"}`,
		`{"abi":1,"name":"` + strings.Repeat("a", 33) + `","version":"1","on_error":"pass"}`,
		`{"abi":1,"name":"a","version":"","on_error":"pass"}`,
		`{"abi":1,"name":"a","version":"1 0","on_error":"pass"}`,
		`{"abi":1,"name":"a","version":"1","on_error":"fail"}`,
		`{"abi":1,"name":"a","version":"1"}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","extra":1}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass"} {}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","hooks":["dns"]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","data":["dns_name"]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","data":["client_tags"]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","hooks":["http_location"],"data":["http_location","client_tags"]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","hooks":["dns","dns"],"data":["dns_name"]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","hooks":["exec"],"data":[]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","data":["files"]}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","description":"a\nb"}`,
		`{"abi":1,"name":"a","version":"1","on_error":"pass","description":"` + strings.Repeat("x", 281) + `"}`,
		"{\"abi\":1,\"name\":\"a\",\"version\":\"1\",\"on_error\":\"pass\",\"description\":\"\xff\"}",
	}
	for _, s := range bad {
		if _, err := ParseManifest([]byte(s)); err == nil {
			t.Errorf("accepted: %q", s)
		}
	}
	if _, err := ParseManifest([]byte(`{"abi":1,"name":"a","version":"1","on_error":"pass","description":"` + strings.Repeat("x", MaxManifestSize) + `"}`)); err == nil {
		t.Error("oversized manifest accepted")
	}
}

func TestDataLabels(t *testing.T) {
	m, err := ParseManifest([]byte(`{"abi":1,"name":"a","version":"1","hooks":["dns","http_location"],"data":["http_location","client_tags","dns_name"],"on_error":"pass"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DNS sorgu adı ve kayıt türü", "istemci etiketleri", "HTTP Location"}
	if got := m.DataLabels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("labels %v", got)
	}
	if got := (Manifest{}).DataLabels(); !reflect.DeepEqual(got, []string{NothingLabel}) {
		t.Fatalf("labels %v", got)
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"abi":1,"name":"ornek-engel","version":"1.0.0","hooks":["dns"],"data":["dns_name"],"on_error":"pass"}`))
	f.Add([]byte(`{"abi":1,"name":"a","version":"1","hooks":["http_location"],"data":["http_location"],"on_error":"block","description":"x"}`))
	f.Add([]byte(`{"abi":1}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseManifest(b)
		if err != nil {
			return
		}
		if err := m.Validate(); err != nil {
			t.Fatalf("parsed manifest does not validate: %v", err)
		}
		again, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		m2, err := ParseManifest(again)
		if err != nil {
			t.Fatalf("round trip: %v", err)
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("round trip changed %+v to %+v", m, m2)
		}
		if len(m.DataLabels()) == 0 {
			t.Fatal("no data label")
		}
	})
}
