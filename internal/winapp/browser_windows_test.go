//go:build windows

package winapp

import (
	"slices"
	"strings"
	"testing"
)

func TestIsolatedBrowserArgs(t *testing.T) {
	args := isolatedBrowserArgs(`C:\p`, "http://127.0.0.1:1/x")
	for _, want := range []string{`--user-data-dir=C:\p`, "--app=http://127.0.0.1:1/x", "--disable-extensions"} {
		if !slices.Contains(args, want) {
			t.Fatalf("missing %s in %v", want, args)
		}
	}
}

func TestBrowserCandidatesAreAbsoluteEdgeFirst(t *testing.T) {
	env := map[string]string{"ProgramFiles": `C:\PF`, "ProgramFiles(x86)": `C:\PF86`, "LOCALAPPDATA": `C:\U\L`}
	got := browserCandidates(func(k string) string { return env[k] })
	if len(got) != 5 || !strings.HasSuffix(got[0], `msedge.exe`) || !strings.HasSuffix(got[4], `chrome.exe`) {
		t.Fatalf("candidates %v", got)
	}
	if len(browserCandidates(func(string) string { return "" })) != 0 {
		t.Fatal("candidates without environment")
	}
}

func TestOpenURLIsolatedRefusesBadInput(t *testing.T) {
	if err := OpenURLIsolated("https://example.com/", t.TempDir()); err == nil {
		t.Fatal("non-loopback URL accepted")
	}
	if err := OpenURLIsolated("http://127.0.0.1:1/", `göreli\yol`); err == nil {
		t.Fatal("relative profile accepted")
	}
}
