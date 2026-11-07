package cli

import "testing"

func TestNetworkDNSZoneCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	out := h.run(exitOK, append([]string{"device", "alias", "--name", "masaustu", "--aliases", "nas,pano"}, dir...)...)
	mustContain(t, out, "masaustu takma adları: yok -> nas,pano")
	out = h.run(exitOK, append([]string{"network", "dns", "record", "add", "--name", "yazici", "--type", "a", "--value", "192.168.1.20"}, dir...)...)
	mustContain(t, out, "+ DNS kaydı yazici A 192.168.1.20")
	out = h.run(exitOK, append([]string{"network", "dns", "record", "add", "--name", "_rdp._tcp.masaustu", "--type", "SRV",
		"--value", "masaustu.openscale.internal.", "--priority", "10", "--port", "3389"}, dir...)...)
	mustContain(t, out, "SRV 10 0 3389 masaustu.openscale.internal")
	h.run(exitOK, append([]string{"network", "dns", "search", "--domains", "openscale.internal"}, dir...)...)
	h.run(exitOK, append([]string{"network", "dns", "subdomains", "--state", "on"}, dir...)...)

	out = h.run(exitOK, "network", "dns", "show", "--dir", h.netDir)
	mustContain(t, out, "Takma adlar: masaustu => nas, pano", "Arama alanları: openscale.internal", "Cihaz alt alanları açık",
		"yazici.openscale.internal A 192.168.1.20")

	// Refused: a record on a device name, a search domain outside the
	// network, a record that does not exist.
	h.run(exitError, append([]string{"network", "dns", "record", "add", "--name", "laptop", "--type", "A", "--value", "192.168.1.2"}, dir...)...)
	h.run(exitError, append([]string{"network", "dns", "search", "--domains", "example.com"}, dir...)...)
	h.run(exitError, append([]string{"network", "dns", "record", "rm", "--name", "yok"}, dir...)...)
	h.run(exitUsage, append([]string{"network", "dns", "subdomains", "--state", "belki"}, dir...)...)

	out = h.run(exitOK, append([]string{"network", "dns", "record", "rm", "--name", "yazici"}, dir...)...)
	mustContain(t, out, "- DNS kaydı yazici A 192.168.1.20")
}
