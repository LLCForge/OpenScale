package webview

import "testing"

func TestForwardPathAndAccept(t *testing.T) {
	for _, bad := range []string{"auth/ticket", "/a?b", "/a#b", "/a/../b", "/a b", `/a\b`} {
		if _, err := (Options{URL: "http://127.0.0.1:4000/", ForwardPath: bad}).normalize(); err == nil {
			t.Fatalf("ForwardPath %q accepted", bad)
		}
	}
	cfg, err := Options{URL: "http://127.0.0.1:4000/", ForwardPath: "/auth/ticket"}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]bool{
		"http://127.0.0.1:4000/auth/ticket?t=abc":   true,
		"http://127.0.0.1:4000/auth/ticket":         true,
		"http://127.0.0.1:4000/devices/":            false,
		"http://127.0.0.1:4001/auth/ticket?t=abc":   false,
		"https://example.com/auth/ticket?t=abc":     false,
		"http://127.0.0.1:4000/auth/ticket#x":       false,
		"http://u:p@127.0.0.1:4000/auth/ticket?t=a": false,
		"javascript:alert(1)":                       false,
	} {
		if got := cfg.acceptForward(u); got != want {
			t.Errorf("acceptForward(%q) = %v, want %v", u, got, want)
		}
	}
	none, err := Options{URL: "http://127.0.0.1:4000/"}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if none.acceptForward("http://127.0.0.1:4000/auth/ticket?t=abc") {
		t.Fatal("a window without ForwardPath accepted a forward")
	}
}
