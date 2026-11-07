package winapp

import (
	"strings"
	"testing"
)

func TestServerCoreType(t *testing.T) {
	for in, want := range map[string]bool{"Server Core": true, "Nano Server": true, "Server": false, "Client": false, "": false} {
		if got := isServerCoreType(in); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
	if !strings.Contains(ErrNoDesktopShell.Error(), "openscale service install") {
		t.Fatal("the error must name the command line flow")
	}
}
