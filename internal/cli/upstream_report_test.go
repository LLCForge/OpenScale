package cli

import (
	"testing"

	"github.com/openscale/openscale/internal/upstream"
)

func TestUpstreamReportStateTor(t *testing.T) {
	// The Tor exit has no active profile; it is reported by its kind.
	st, ok := upstreamReportState(upstream.Status{Kind: upstream.KindTor, Label: "Tor", Mode: upstream.ModeTunnel})
	if !ok || st.Kind != "tor" || st.Label != "Tor" || st.Mode != upstream.ModeTunnel {
		t.Fatalf("tor: %+v %v", st, ok)
	}
	st, ok = upstreamReportState(upstream.Status{Active: "warp-1", Kind: upstream.ProviderWARP, Mode: upstream.ModeBlocked, LastHandshake: 5})
	if !ok || st.Kind != "warp" || st.Label != "warp-1" || st.LastHandshake != 5 {
		t.Fatalf("warp: %+v %v", st, ok)
	}
	if _, ok := upstreamReportState(upstream.Status{Mode: upstream.ModeOff}); ok {
		t.Fatal("reported without an upstream exit")
	}
}
