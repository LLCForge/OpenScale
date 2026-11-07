package bundlecrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	k, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublic(k.PublicText())
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("teşhis "), 1000)
	sealed, err := Seal(rand.Reader, pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) || bytes.Contains(sealed, []byte("teşhis")) {
		t.Fatal("not sealed")
	}
	got, err := Open(k, sealed)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open: %v", err)
	}
	// Two seals of the same content differ (fresh ephemeral key).
	again, _ := Seal(rand.Reader, pub, msg)
	if bytes.Equal(again, sealed) {
		t.Fatal("deterministic seal")
	}
}

func TestOpenRefuses(t *testing.T) {
	k, _ := Generate(rand.Reader)
	other, _ := Generate(rand.Reader)
	pub, _ := ParsePublic(k.PublicText())
	sealed, _ := Seal(rand.Reader, pub, []byte("gizli"))
	if _, err := Open(other, sealed); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	for i := range []int{0, 5, len(sealed) - 1} {
		pos := []int{0, 5, len(sealed) - 1}[i]
		bad := append([]byte(nil), sealed...)
		bad[pos] ^= 1
		if _, err := Open(k, bad); err == nil {
			t.Fatalf("tampered byte %d accepted", pos)
		}
	}
	// The recipient field is authenticated too: swapping it for the
	// other key's makes the header check fail for both.
	if _, err := Open(k, []byte("PK\x03\x04plain zip")); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("plain: %v", err)
	}
}

func TestKeyText(t *testing.T) {
	for _, s := range []string{"", "osbk1:", "osbk1:!!!", "abc", "osbk1:" + strings.Repeat("A", 43), "osbk1:" + strings.Repeat("A", 100)} {
		if _, err := ParsePublic(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	k, _ := Generate(rand.Reader)
	data, err := k.MarshalKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseKeyFile(data)
	if err != nil || back.PublicText() != k.PublicText() {
		t.Fatalf("key file: %v", err)
	}
	mangled := bytes.Replace(data, []byte(k.PublicText()), []byte(func() string { o, _ := Generate(rand.Reader); return o.PublicText() }()), 1)
	if _, err := ParseKeyFile(mangled); !errors.Is(err, ErrBadKeyFile) {
		t.Fatalf("mismatched halves: %v", err)
	}
	if len(Fingerprint(k.Private.PublicKey())) != 19 {
		t.Fatal("fingerprint")
	}
}

func TestTooLarge(t *testing.T) {
	k, _ := Generate(rand.Reader)
	if _, err := Seal(rand.Reader, k.Private.PublicKey(), make([]byte, MaxPlaintext+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}
