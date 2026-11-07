//go:build !windows && !(((darwin && cgo) || (linux && cgo)) && !nowebview)

package webview

import (
	"context"
	"errors"
	"testing"
)

// Without a binding Open falls back with an error matching ErrUnavailable,
// so the caller opens the browser instead.
func TestOpenUnsupported(t *testing.T) {
	err := Open(context.Background(), Options{URL: "http://127.0.0.1:8080/"})
	if !errors.Is(err, ErrUnsupported) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open = %v, ErrUnsupported bekleniyordu", err)
	}
}
