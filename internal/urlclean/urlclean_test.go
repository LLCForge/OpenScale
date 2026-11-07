package urlclean

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCleanURL(t *testing.T) {
	r := DefaultRules()
	cases := []struct{ in, out string }{
		{"http://shop.example/p?id=7&utm_source=x&UTM_Medium=y&fbclid=abc#top", "http://shop.example/p?id=7#top"},
		{"https://shop.example/?gclid=1", "https://shop.example/"},
		{"/rel?a=1&mc_eid=2&b=%20c", "/rel?a=1&b=%20c"},
		{"http://shop.example/p?id=7", "http://shop.example/p?id=7"},
		{"http://shop.example/p#frag?utm_source=x", "http://shop.example/p#frag?utm_source=x"},
		{"http://shop.example/p?utm%5Fsource=x&k", "http://shop.example/p?k"},
		{"http://shop.example/p?&&utm_id=1&", "http://shop.example/p?&&"},
	}
	for _, c := range cases {
		got, _ := r.CleanURL(c.in)
		if got != c.out {
			t.Errorf("%s: %s, want %s", c.in, got, c.out)
		}
	}
}

func TestCleanRedirectOnlyPlainHTTP(t *testing.T) {
	r := DefaultRules()
	loc := "https://dest.example/a?x=1&utm_campaign=c"
	if got, ok := r.CleanRedirect("http", http.StatusFound, loc); !ok || got != "https://dest.example/a?x=1" {
		t.Fatal(got, ok)
	}
	if got, ok := r.CleanRedirect("https", http.StatusFound, loc); ok || got != loc {
		t.Fatal("https touched")
	}
	if _, ok := r.CleanRedirect("http", http.StatusOK, loc); ok {
		t.Fatal("non redirect touched")
	}
	if got, ok := r.CleanReferer("http", "http://from.example/?fbclid=1"); !ok || got != "http://from.example/" {
		t.Fatal(got, ok)
	}
	if _, ok := r.CleanReferer("HTTPS", "http://from.example/?fbclid=1"); ok {
		t.Fatal("https referer touched")
	}
}

func TestParseRules(t *testing.T) {
	r, err := ParseRules(strings.NewReader("# extra\nref\ncamp_*\n!si\n!utm_*\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Tracking("REF") || !r.Tracking("camp_x") || r.Tracking("si") || r.Tracking("utm_source") || !r.Tracking("fbclid") {
		t.Fatal("rules not applied")
	}
	for _, bad := range []string{"a b\n", "x=y\n", strings.Repeat("a", 200) + "\n"} {
		if _, err := ParseRules(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func FuzzCleanURL(f *testing.F) {
	f.Add("http://a.example/?utm_source=1&b=2#f")
	f.Add("?fbclid")
	f.Add("http://a.example/%zz?gclid=1")
	r := DefaultRules()
	f.Fuzz(func(t *testing.T, in string) {
		out, n := r.CleanURL(in)
		if n == 0 {
			if out != in {
				t.Fatal("changed without removal")
			}
			return
		}
		if len(out) >= len(in) {
			t.Fatal("removal did not shorten")
		}
		u, err := url.Parse(out)
		if err != nil {
			t.Fatalf("result does not parse: %v", err)
		}
		for _, p := range strings.Split(u.RawQuery, "&") {
			name, _, _ := strings.Cut(p, "=")
			if name != "" && r.Tracking(name) {
				t.Fatalf("tracking parameter left: %q in %q", name, out)
			}
		}
		if again, m := r.CleanURL(out); m != 0 || again != out {
			t.Fatal("not idempotent")
		}
	})
}
