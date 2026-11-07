package netprofile

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

var testNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func joinNew(t *testing.T, dir string) string {
	t.Helper()
	opts := admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
	n, err := admin.Init(t.TempDir(), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, []byte("doğru at pil zımba 9"), opts, testNow)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	s, err := member.Join(dir, bundle, n.RootFingerprint(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	return s.Anchor().NetworkID
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"default", "aile", "is-2", "a"} {
		if ValidName(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "active", "-x", "Aile", "a/b", "..", "a b", "ağ", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if ValidName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestResolveSwitchList(t *testing.T) {
	base := t.TempDir()
	if d, err := Resolve(base, "", false); err != nil || d != base {
		t.Fatalf("default resolve = %q, %v", d, err)
	}
	if _, err := Resolve(base, "aile", false); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown profile: %v", err)
	}
	if err := Switch(base, "aile"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("switch unknown: %v", err)
	}
	dir, err := Resolve(base, "aile", true)
	if err != nil || dir != filepath.Join(base, "networks", "aile") {
		t.Fatalf("create = %q, %v", dir, err)
	}
	if err := Switch(base, "aile"); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("switch unjoined: %v", err)
	}
	idDefault := joinNew(t, base)
	idFamily := joinNew(t, dir)
	if err := Switch(base, "aile"); err != nil {
		t.Fatal(err)
	}
	if d, err := Resolve(base, "", false); err != nil || d != dir {
		t.Fatalf("active resolve = %q, %v", d, err)
	}
	ps, err := List(base)
	if err != nil || len(ps) != 2 {
		t.Fatalf("list = %+v, %v", ps, err)
	}
	if ps[0].Name != DefaultName || ps[0].NetworkID != idDefault || ps[0].Active ||
		ps[1].Name != "aile" || ps[1].NetworkID != idFamily || !ps[1].Active || ps[0].Duplicate {
		t.Fatalf("list = %+v", ps)
	}
	if err := Switch(base, DefaultName); err != nil {
		t.Fatal(err)
	}
	if a, err := Active(base); err != nil || a != DefaultName {
		t.Fatalf("active = %q, %v", a, err)
	}
}

func TestDamagedPointerFailsClosed(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "networks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "networks", "active"), []byte("../../etc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(base, "", false); err == nil {
		t.Fatal("damaged pointer resolved")
	}
	if _, err := Dir(base, "../x"); err == nil {
		t.Fatal("path traversal accepted")
	}
}
