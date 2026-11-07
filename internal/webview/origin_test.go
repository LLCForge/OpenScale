package webview

import "testing"

func mustOrigin(t *testing.T, s string) origin {
	t.Helper()
	o, err := parseOrigin(s)
	if err != nil {
		t.Fatalf("parseOrigin(%q): %v", s, err)
	}
	return o
}

func TestParseOrigin(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // "" = error
	}{
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"http://[::1]:9", "http://[::1]:9"},
		{"http://127.0.0.1", ""},
		{"http://127.0.0.1:", ""},
		{"http://127.0.0.1:0", ""},
		{"http://127.0.0.1:65536", ""},
		{"http://127.0.0.1:08080", ""},
		{"https://127.0.0.1:8080", ""},
		{"http://localhost:8080", ""},
		{"http://127.0.0.2:8080", ""},
		{"http://10.0.0.1:8080", ""},
		{"http://[::ffff:127.0.0.1]:8080", ""},
		{"http://[fe80::1%25eth0]:8080", ""},
		{"http://127.0.0.1:8080/panel", ""},
		{"http://127.0.0.1:8080?x=1", ""},
		{"http://127.0.0.1:8080#x", ""},
		{"http://u:p@127.0.0.1:8080", ""},
		{"http://127.0.0.1:8080\\", ""},
		{"HTTP://127.0.0.1:8080 ", ""},
		{"", ""},
	} {
		o, err := parseOrigin(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("parseOrigin(%q) = %v, hata bekleniyordu", tc.in, o)
			}
			continue
		}
		if err != nil || o.String() != tc.want {
			t.Errorf("parseOrigin(%q) = %v, %v; %s bekleniyordu", tc.in, o, err, tc.want)
		}
	}
}

func TestOriginCheck(t *testing.T) {
	o := mustOrigin(t, "http://127.0.0.1:8080")
	for _, tc := range []struct {
		url  string
		want action
	}{
		{"http://127.0.0.1:8080/", actionAllow},
		{"http://127.0.0.1:8080", actionAllow},
		{"http://127.0.0.1:8080/devices?id=1#top", actionAllow},
		{"HTTP://127.0.0.1:8080/x", actionAllow}, // the scheme is case-insensitive
		{"about:blank", actionAllow},
		{"http://127.0.0.1:8081/", actionBlock},
		{"http://127.0.0.1/", actionBlock},
		{"http://127.0.0.1:80/", actionBlock},
		{"http://localhost:8080/", actionBlock},
		{"http://LOCALHOST:8080/", actionBlock},
		{"http://127.1:8080/", actionBlock},
		{"http://2130706433:8080/", actionBlock},
		{"http://[::1]:8080/", actionBlock},
		{"http://[::ffff:127.0.0.1]:8080/", actionBlock},
		{"https://127.0.0.1:8080/", actionBlock},
		{"ws://127.0.0.1:8080/", actionBlock},
		{"javascript:alert(1)", actionBlock},
		{"JavaScript:alert(1)", actionBlock},
		{"data:text/html,<b>x</b>", actionBlock},
		{"file:///C:/Windows/win.ini", actionBlock},
		{"blob:http://127.0.0.1:8080/abc", actionBlock},
		{"about:srcdoc", actionBlock},
		{"about:blank#x", actionBlock},
		{"http://127.0.0.1:8080@example.com/", actionBlock},
		{"http://user@127.0.0.1:8080/", actionBlock},
		{"http://127.0.0.1:8080.example.com/", actionBlock},
		{"http://127.0.0.1:08080/", actionBlock},
		{"http://127.0.0.1:8080\\@example.com/", actionBlock},
		{"http://127.0.0.1:8080/\r\nX: y", actionBlock},
		{"http://%31%32%37.0.0.1:8080/", actionBlock},
		{"http://127.0.0.1%2e:8080/", actionBlock},
		{"http://127.0.0.1.:8080/", actionBlock},
		{"http://127.0.0.1:8080:80/", actionBlock},
		{"http://127.0.0.1:+8080/", actionBlock},
		{"http://127.0.0.1:8080%2f@example.com/", actionBlock},
		{"http://127.0.0.2:8080/", actionBlock},
		{"http://0.0.0.0:8080/", actionBlock},
		{"http://[::1%25lo]:8080/", actionBlock},
		{"http:127.0.0.1:8080/", actionBlock},
		{"//127.0.0.1:8080/", actionBlock},
		{"", actionBlock},
	} {
		if got := o.check(tc.url); got != tc.want {
			t.Errorf("check(%q) = %v, %v bekleniyordu", tc.url, got, tc.want)
		}
	}

	v6 := mustOrigin(t, "http://[::1]:9000")
	if v6.check("http://[::1]:9000/x") != actionAllow || v6.check("http://127.0.0.1:9000/") != actionBlock {
		t.Error("IPv6 kaynağı yanlış değerlendirildi")
	}
}

func TestOriginNavigate(t *testing.T) {
	o := mustOrigin(t, "http://127.0.0.1:8080")
	for _, tc := range []struct {
		url  string
		user bool
		want action
	}{
		{"http://127.0.0.1:8080/x", false, actionAllow},
		{"http://127.0.0.1:8080/x", true, actionAllow},
		{"https://example.com/docs", true, actionExternal},
		{"https://example.com/docs", false, actionBlock},
		{"http://example.com/", true, actionBlock},
		{"https://127.0.0.1:8443/", true, actionBlock},
		{"https://localhost/", true, actionBlock},
		{"https://a.localhost/", true, actionBlock},
		{"https://[::1]/", true, actionBlock},
		{"https://169.254.1.1/", true, actionBlock},
		{"https://user:pw@example.com/", true, actionBlock},
		{"https://example.com/a b", true, actionBlock},
		{"https://example.com/\"x", true, actionBlock},
		{"https://-x.example.com/", true, actionBlock},
		{"javascript:alert(1)", true, actionBlock},
		{"mailto:a@example.com", true, actionBlock},
		{"ms-settings:network", true, actionBlock},
		{"file:///etc/passwd", true, actionBlock},
	} {
		if got := o.navigate(tc.url, tc.user); got != tc.want {
			t.Errorf("navigate(%q, %v) = %v, %v bekleniyordu", tc.url, tc.user, got, tc.want)
		}
	}
}

func TestOriginSubresource(t *testing.T) {
	o := mustOrigin(t, "http://127.0.0.1:8080")
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:8080/_next/app.js", true},
		{"data:image/png;base64,AAAA", true},
		{"DATA:image/png;base64,AAAA", true},
		{"blob:http://127.0.0.1:8080/0f8e", true},
		{"blob:http://127.0.0.1:9999/0f8e", false},
		{"blob:null/0f8e", false},
		{"about:blank", false},
		{"http://127.0.0.1:8081/x.png", false},
		{"https://example.com/x.js", false},
		{"ws://127.0.0.1:8080/", false},
		{"file:///C:/x", false},
	} {
		if got := o.subresource(tc.url); got != tc.want {
			t.Errorf("subresource(%q) = %v, %v bekleniyordu", tc.url, got, tc.want)
		}
	}
}

func TestExternalURL(t *testing.T) {
	if got := externalURL("https://example.com/a?b=c#d"); got != "https://example.com/a?b=c#d" {
		t.Errorf("externalURL = %q", got)
	}
	// Spellings a browser resolves to this computer although netip does
	// not parse them, and IDNA tricks that map to "localhost".
	for _, raw := range []string{
		"https://localhost./",
		"https://LocalHost./x",
		"https://a.localhost./",
		"https://127.1/",
		"https://127.0.1/",
		"https://2130706433/",
		"https://0x7f000001/",
		"https://0x7F.0.0.1/",
		"https://0177.0.0.1/",
		"https://0/",
		"https://127.0.0.1./",
		"https://ｌｏｃａｌｈｏｓｔ/",
		"https://%6c%6f%63alhost/",
		"https://example..com/",
		"https://example.com./",
		"https://ex_ample.com/",
		"https://[::ffff:127.0.0.1]/",
		"https://[::]/",
	} {
		if got := externalURL(raw); got != "" {
			t.Errorf("externalURL(%q) = %q, reddedilmeliydi", raw, got)
		}
	}
	for _, raw := range []string{
		"https://docs.example.com/a",
		"https://xn--fsq.example/",
		"https://8.8.8.8/",
		"https://[2001:db8::1]/",
		"https://a-b.example.co.uk:8443/x",
	} {
		if externalURL(raw) == "" {
			t.Errorf("externalURL(%q) reddedildi, kabul edilmeliydi", raw)
		}
	}
	long := "https://example.com/" + string(make([]byte, maxExternalURLBytes))
	if externalURL(long) != "" {
		t.Error("çok uzun adres kabul edildi")
	}
}

func TestBrowserArguments(t *testing.T) {
	got := browserArguments(mustOrigin(t, "http://127.0.0.1:8080"))
	want := "--proxy-server=http://127.0.0.1:8080 --proxy-bypass-list=<-loopback>;127.0.0.1:8080"
	if got != want {
		t.Errorf("browserArguments = %q, %q bekleniyordu", got, want)
	}
	got6 := browserArguments(mustOrigin(t, "http://[::1]:9"))
	if got6 != "--proxy-server=http://[::1]:9 --proxy-bypass-list=<-loopback>;[::1]:9" {
		t.Errorf("IPv6 browserArguments = %q", got6)
	}
}
