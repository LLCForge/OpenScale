package winapp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPromptText(t *testing.T) {
	if got := promptText("  Kök anahtar parolası: "); got != "Kök anahtar parolası" {
		t.Fatalf("%q", got)
	}
	if promptText("") != "Parola" {
		t.Fatal("empty prompt")
	}
	if got := promptText("a\nb\tc"); strings.ContainsAny(got, "\n\t") {
		t.Fatalf("control characters kept: %q", got)
	}
	if got := promptText(strings.Repeat("ş", 300)); utf8.RuneCountInString(got) != 200 {
		t.Fatalf("not truncated: %d", utf8.RuneCountInString(got))
	}
	t.Setenv(SecureInputEnv, "Desktop")
	if !SecureInputRequested() {
		t.Fatal("env not honoured")
	}
}
