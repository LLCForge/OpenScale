package service

import "testing"

func TestSplitStaticEndpoints(t *testing.T) {
	eps, names, err := SplitStaticEndpoints([]string{"203.0.113.5:51820", " ev.example.net:41641", "[2001:db8::1]:51820"})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || len(names) != 1 || names[0] != "ev.example.net:41641" {
		t.Fatalf("eps %v names %v", eps, names)
	}
	for _, bad := range []string{"ev.example.net", "ev.example.net:0", "localhost:51820", "ev:51820", "127.0.0.1:51820", "a_b.example.net:1", "[::1]:5"} {
		if _, _, err := SplitStaticEndpoints([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, 0, 20)
	for range 20 {
		many = append(many, "ev.example.net:1")
	}
	if _, _, err := SplitStaticEndpoints(many); err == nil {
		t.Error("too many accepted")
	}
	// A list with only IP entries parses as before.
	old, err := ParseStaticEndpoints([]string{"203.0.113.5:51820"})
	eps, names, err2 := SplitStaticEndpoints([]string{"203.0.113.5:51820"})
	if err != nil || err2 != nil || len(names) != 0 || len(eps) != 1 || eps[0] != old[0] {
		t.Fatalf("regression: %v %v %v %v", old, eps, err, err2)
	}
}
