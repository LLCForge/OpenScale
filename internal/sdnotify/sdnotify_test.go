package sdnotify

import (
	"strings"
	"testing"
)

func TestStatusLine(t *testing.T) {
	if got := statusLine("  bağlı\nikinci satır "); got != "STATUS=bağlı ikinci satır" {
		t.Fatalf("statusLine = %q", got)
	}
	if got := statusLine(""); got != "" {
		t.Fatalf("empty status = %q", got)
	}
	long := strings.Repeat("ş", maxStatus+50)
	if got := statusLine(long); len([]rune(got)) != len("STATUS=")+maxStatus {
		t.Fatalf("status not cut: %d runes", len([]rune(got)))
	}
}

func TestJoin(t *testing.T) {
	if got := join(stateReady, "", "STATUS=x"); got != "READY=1\nSTATUS=x" {
		t.Fatalf("join = %q", got)
	}
}

func TestValidSocket(t *testing.T) {
	for s, want := range map[string]bool{
		"/run/systemd/notify": true,
		"@/org/systemd/x":     true,
		"relative":            false,
		"":                    false,
		"/":                   false,
	} {
		if validSocket(s) != want {
			t.Errorf("validSocket(%q) != %t", s, want)
		}
	}
}

func TestNoSocketIsNoOp(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	sent, err := Ready("hazır")
	if sent || err != nil {
		t.Fatalf("Ready without NOTIFY_SOCKET = %t, %v", sent, err)
	}
}
