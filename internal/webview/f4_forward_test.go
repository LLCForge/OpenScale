package webview

import (
	"errors"
	"testing"
)

// Without a check there is no one to trust: nothing is forwarded.
func TestForwardWithoutCheckRefuses(t *testing.T) {
	if err := ForwardToOpenWindow("http://127.0.0.1:1/auth/ticket?t=x", nil); !errors.Is(err, ErrNoOpenWindow) {
		t.Fatalf("err = %v, want ErrNoOpenWindow", err)
	}
}
