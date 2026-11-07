//go:build windows

package wintunembed

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// pinned are the SHA-256 digests of the signed binaries from wintun.net
// (Wintun 0.14.1). A changed DLL in the repository fails this test.
var pinned = map[string]string{
	"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
	"arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
	"x86":   "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
	"arm":   "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9",
}

func TestEmbeddedDLLsArePinned(t *testing.T) {
	for arch, want := range pinned {
		data, err := os.ReadFile(filepath.Join("dll", arch, "wintun.dll"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s/wintun.dll sha256 = %s, want %s", arch, got, want)
		}
	}
	if len(embedded) == 0 {
		t.Fatal("no DLL embedded for this architecture")
	}
}

func TestLoadIfVerifiedRejectsTamperedFile(t *testing.T) {
	want := sha256.Sum256(embedded)
	path := filepath.Join(t.TempDir(), "wintun.dll")

	ok, err := loadIfVerified(path, want)
	if err != nil || ok {
		t.Fatalf("missing file: ok=%v err=%v", ok, err)
	}
	tampered := append([]byte(nil), embedded...)
	tampered[len(tampered)/2] ^= 0xff
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err = loadIfVerified(path, want)
	if err != nil || ok {
		t.Fatalf("tampered file must not load: ok=%v err=%v", ok, err)
	}
}
