//go:build windows

package rdesk

import (
	"context"
	"errors"
	"testing"
)

func TestSplitWindowsUser(t *testing.T) {
	cases := []struct {
		in, user, dom string
		ok            bool
	}{
		{"ayse", "ayse", ".", true},
		{"OFIS\\ayse", "ayse", "OFIS", true},
		{"\\ayse", "ayse", ".", true},
		{"ayse@ofis.example", "ayse@ofis.example", "", true},
		{"OFIS\\", "", "", false},
		{"a\\b\\c", "", "", false},
		{"a/b", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		u, d, ok := splitWindowsUser(c.in)
		if ok != c.ok || u != c.user || d != c.dom {
			t.Errorf("%q: %q %q %v", c.in, u, d, ok)
		}
	}
}

func TestUTF16Secret(t *testing.T) {
	u, ok := utf16Secret([]byte("şİ€😀"))
	if !ok || len(u) != 6 || u[len(u)-1] != 0 {
		t.Fatalf("%v %v", u, ok)
	}
	if _, ok := utf16Secret([]byte{'a', 0, 'b'}); ok {
		t.Fatal("NUL accepted")
	}
	if _, ok := utf16Secret([]byte{0xff}); ok {
		t.Fatal("invalid UTF-8 accepted")
	}
}

// TestWindowsVerifierRefusesUnknownAccount asks LogonUserW about an
// account that does not exist (read only; no account can be locked out).
func TestWindowsVerifierRefusesUnknownAccount(t *testing.T) {
	v, err := NewSystemVerifier()
	if err != nil {
		t.Skip(err)
	}
	err = v.Verify(context.Background(), "openscale-g5-yok-hesap-7d1f", []byte("yanlis-parola"))
	if !errors.Is(err, ErrOSLoginFailed) && !errors.Is(err, ErrOSLoginUnavailable) {
		t.Fatalf("unknown account: %v", err)
	}
	if err := v.Verify(context.Background(), "", []byte("x")); !errors.Is(err, ErrOSLoginFailed) {
		t.Fatalf("empty user: %v", err)
	}
}
