//go:build windows

package osnet

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The audit only reads; without administrator rights it reports access
// denied, which is skipped.
func TestKillSwitchBypassRisksReadsOnly(t *testing.T) {
	risks, err := KillSwitchBypassRisks()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || (err != nil && strings.Contains(err.Error(), "yönetici")) {
		t.Skip("needs administrator rights")
	}
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, r := range risks {
		if r.Level != "high" && r.Level != "info" || r.Message == "" {
			t.Fatalf("bad risk %+v", r)
		}
		t.Logf("%s: %s", r.Level, r.Message)
	}
}

func TestCleanWFPName(t *testing.T) {
	if got := cleanWFPName("a\x00b\nc" + strings.Repeat("x", 300)); strings.ContainsAny(got, "\x00\n") || len(got) > maxWFPName {
		t.Fatalf("got %q", got)
	}
}
