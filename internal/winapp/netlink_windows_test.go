//go:build windows

package winapp

import (
	"path/filepath"
	"strings"
	"testing"
)

// The link is written in a temporary folder and read back through the
// shell. The UNC target names only this computer (127.0.0.1).
func TestWriteLinkUNC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.lnk")
	const target = `\\127.0.0.1\openscale-test-yok`
	if err := WriteLink(path, target, "OpenScale: test"); err != nil {
		t.Fatal(err)
	}
	got, args := readShortcut(t, path)
	if !strings.EqualFold(got, target) || args != "" {
		t.Fatalf("target = %q args = %q", got, args)
	}
	if err := WriteLink(path, "a\"b", ""); err == nil {
		t.Fatal("quoted target accepted")
	}
}
