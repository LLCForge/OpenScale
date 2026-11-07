package panel

import (
	"testing"

	"github.com/openscale/openscale/internal/sysinfo"
)

func TestUpstreamOfKind(t *testing.T) {
	v := UpstreamOf(sysinfo.Info{UpstreamLabel: "Tor", UpstreamMode: "tunnel", UpstreamKind: "tor"})
	if v == nil || v.Kind != "tor" || v.LastHandshake != nil {
		t.Fatalf("tor view: %+v", v)
	}
	if v := UpstreamOf(sysinfo.Info{UpstreamLabel: "x", UpstreamMode: "off"}); v == nil || v.Kind != "" {
		t.Fatalf("older report: %+v", v)
	}
}
