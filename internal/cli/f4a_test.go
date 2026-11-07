package cli

import (
	"testing"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// ADR-0232 commands: device icon, ranges in group set and exit users set,
// support allow. Each signs a version and raises the client minimum.

func TestF4ACommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	out := h.run(exitOK, append([]string{"device", "icon", "--name", "laptop", "--icon", "laptop"}, dir...)...)
	mustContain(t, out, "laptop: simge - -> laptop", "Asgari istemci sürümü", trust.SchemaV2MinClientVersion)
	h.run(exitUsage, append([]string{"device", "icon", "--name", "laptop", "--icon", "toaster"}, dir...)...)
	h.run(exitUsage, append([]string{"device", "icon", "--name", "laptop"}, dir...)...)
	h.run(exitOK, append([]string{"device", "icon", "--name", "laptop", "--clear"}, dir...)...)

	n, err := admin.Load(h.netDir, h.env.adminOptions())
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := n.Document()
	laptop, _ := doc.DeviceByName("laptop")
	ip := laptop.IPv4.String()
	out = h.run(exitOK, append([]string{"group", "set", "--name", "yonetim", "--members", ip + ",masaustu"}, dir...)...)
	mustContain(t, out, ip+"/32")
	h.run(exitOK, append([]string{"exit", "users", "set", "--users", "group:yonetim," + ip}, dir...)...)
	h.run(exitError, append([]string{"group", "set", "--name", "kotu", "--members", "8.8.8.8"}, dir...)...)

	out = h.run(exitOK, append([]string{"support", "allow", "--from", "laptop", "--to", "masaustu", "--kill"}, dir...)...)
	mustContain(t, out, "support(okuma ve süreç sonlandırma (support.kill))")
	if err := n.Reload(); err != nil {
		t.Fatal(err)
	}
	doc, _ = n.Document()
	if !doc.AllowsSupport("laptop", "masaustu", trust.SupportKill) || doc.MinClientVersion != trust.SchemaV2MinClientVersion {
		t.Fatalf("support rule or minimum missing: %q", doc.MinClientVersion)
	}
	if !doc.MayUseExitNode("laptop") || !doc.MayUseExitNode("masaustu") {
		t.Fatal("exit users by group and range")
	}
}
