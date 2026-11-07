package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	rotationLine   = regexp.MustCompile(`osrot1\.[A-Za-z0-9_-]+`)
	masaustuAddr   = regexp.MustCompile(`masaustu\.openscale\.internal\s+(\S+)`)
	inviteCodeLine = regexp.MustCompile(`(?m)^(\S{40,})$`)
)

// policyNetwork creates a network with the devices laptop and masaustu and
// returns the passphrase flag.
func policyNetwork(t *testing.T, h *harness) string {
	t.Helper()
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	for _, name := range []string{"laptop", "masaustu"} {
		req, fp := h.keygen(filepath.Join(t.TempDir(), name), name)
		h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)
	}
	return pass
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Fatalf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestTagsGroupsAndRuleCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	out := h.run(exitOK, append([]string{"device", "tag", "--name", "laptop", "--tags", "sunucu,ev"}, dir...)...)
	mustContain(t, out, "laptop: etiketler [] -> [sunucu,ev]")
	h.run(exitUsage, append([]string{"device", "tag", "--name", "laptop"}, dir...)...)

	out = h.run(exitOK, append([]string{"group", "set", "--name", "ofis", "--members", "masaustu,tag:sunucu"}, dir...)...)
	mustContain(t, out, "+ grup ofis [masaustu,tag:sunucu]")

	// Numeric protocols, deny rules, groups and tags.
	h.run(exitOK, append([]string{"rule", "add", "--from", "group:ofis", "--to", "masaustu", "--proto", "47"}, dir...)...)
	out = h.run(exitUsage, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--proto", "6"}, dir...)...)
	mustContain(t, out, "adıyla yazılmalı")
	h.run(exitUsage, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--action", "belki"}, dir...)...)
	out = h.run(exitOK, append([]string{"rule", "add", "--from", "tag:yok", "--to", "masaustu", "--proto", "any", "--action", "deny"}, dir...)...)
	mustContain(t, out, "+ kural reddet: tag:yok -> masaustu any")

	out = h.run(exitOK, append([]string{"rule", "disable", "--number", "1"}, dir...)...)
	mustContain(t, out, "(kapalı)")
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	mustContain(t, out, "1. group:ofis -> masaustu 47 (kapalı)", "group:ofis  masaustu, tag:sunucu", "etiketler: sunucu,ev", "UYARI: tag:yok hiçbir cihazda yok")
	h.run(exitOK, append([]string{"rule", "enable", "--number", "1"}, dir...)...)
	h.run(exitUsage, append([]string{"rule", "disable", "--number", "0"}, dir...)...)
	h.run(exitError, append([]string{"rule", "disable", "--number", "9"}, dir...)...)

	// A used group cannot be removed; an unused one can.
	h.run(exitError, append([]string{"group", "rm", "--name", "ofis"}, dir...)...)
	h.run(exitOK, append([]string{"group", "set", "--name", "bos"}, dir...)...)
	out = h.run(exitOK, "group", "list", "--dir", h.netDir)
	mustContain(t, out, "group:bos  (boş", "group:ofis  masaustu, tag:sunucu", "UYARI: tag:yok")
	h.run(exitOK, append([]string{"group", "rm", "--name", "bos"}, dir...)...)

	// Renaming carries every reference along.
	out = h.run(exitOK, append([]string{"device", "rename", "--name", "masaustu", "--new-name", "pc"}, dir...)...)
	mustContain(t, out, "ad masaustu -> pc", "+ kural group:ofis -> pc 47", "~ grup ofis [masaustu,tag:sunucu] -> [pc,tag:sunucu]")
	h.run(exitError, append([]string{"device", "rename", "--name", "pc", "--new-name", "laptop"}, dir...)...)
}

func TestMembershipCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}
	out := h.run(exitOK, append([]string{"device", "extend", "--name", "laptop", "--days", "30"}, dir...)...)
	mustContain(t, out, "laptop: üyelik bitişi", "2026-11-28 12:00")
	h.run(exitUsage, append([]string{"device", "extend", "--name", "laptop", "--days", "3651"}, dir...)...)
	h.run(exitError, append([]string{"device", "extend", "--name", "yok", "--days", "30"}, dir...)...)
	out = h.run(exitOK, append([]string{"device", "expire", "--name", "laptop"}, dir...)...)
	mustContain(t, out, "-> 2026-10-29 12:00")
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	mustContain(t, out, "Cihazlar (2)")
}

func TestExitUsersCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}
	out := h.run(exitOK, "exit", "users", "show", "--dir", h.netDir)
	mustContain(t, out, "herkes")
	out = h.run(exitOK, append([]string{"exit", "users", "set", "--users", "laptop"}, dir...)...)
	mustContain(t, out, "Çıkış düğümü kullanıcıları: herkes -> laptop")
	h.run(exitUsage, append([]string{"exit", "users", "set"}, dir...)...)
	h.run(exitUsage, append([]string{"exit", "users", "set", "--users", "laptop", "--none"}, dir...)...)
	h.run(exitError, append([]string{"exit", "users", "set", "--users", "*"}, dir...)...)
	out = h.run(exitOK, append([]string{"exit", "users", "set", "--none"}, dir...)...)
	mustContain(t, out, "laptop -> hiçbir cihaz")
	out = h.run(exitOK, append([]string{"exit", "users", "clear"}, dir...)...)
	mustContain(t, out, "hiçbir cihaz -> herkes")
}

func TestNetworkDNSAndNameCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}
	m := masaustuAddr.FindStringSubmatch(h.run(exitOK, "network", "show", "--dir", h.netDir))
	if len(m) != 2 {
		t.Fatal("masaustu address not found")
	}
	resolver := m[1]

	out := h.run(exitOK, append([]string{"network", "dns", "set", "--split", "ev.lan=" + resolver, "--dry-run"}, dir...)...)
	mustContain(t, out, "Ağ DNS ayarları: yok -> ev.lan => "+resolver, "Kuru çalıştırma")
	out = h.run(exitOK, "network", "dns", "show", "--dir", h.netDir)
	mustContain(t, out, "Ağ DNS ayarı yok")

	h.run(exitOK, append([]string{"network", "dns", "set", "--nameservers", resolver, "--split", "ev.lan=" + resolver}, dir...)...)
	out = h.run(exitOK, "network", "dns", "show", "--dir", h.netDir)
	// No rule lets laptop reach the resolver on 53/udp yet.
	mustContain(t, out, "Ağ geneli çözücüler: "+resolver, "ev.lan => "+resolver, "UYARI: masaustu çözücüsüne 53/udp kuralı yok", "laptop")
	h.run(exitOK, append([]string{"rule", "add", "--from", "*", "--to", "masaustu", "--proto", "udp", "--ports", "53"}, dir...)...)
	out = h.run(exitOK, "network", "dns", "show", "--dir", h.netDir)
	if strings.Contains(out, "UYARI") {
		t.Fatalf("warning after the port 53 rule:\n%s", out)
	}

	// Public resolvers and the MagicDNS domain are refused.
	h.run(exitError, append([]string{"network", "dns", "set", "--nameservers", "8.8.8.8"}, dir...)...)
	h.run(exitError, append([]string{"network", "dns", "set", "--split", "openscale.internal=" + resolver}, dir...)...)
	h.run(exitUsage, append([]string{"network", "dns", "set", "--split", "ev.lan"}, dir...)...)
	h.run(exitUsage, append([]string{"network", "dns", "set"}, dir...)...)
	out = h.run(exitOK, append([]string{"network", "dns", "clear"}, dir...)...)
	mustContain(t, out, "-> yok")

	out = h.run(exitOK, append([]string{"network", "name", "set", "--name", "Ev ağı"}, dir...)...)
	mustContain(t, out, "Ağ adı: yok -> Ev ağı")
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	mustContain(t, out, "Ağ adı:                  Ev ağı")
	h.run(exitUsage, append([]string{"network", "name", "set", "--name", "a\u202eb"}, dir...)...)
	h.run(exitUsage, append([]string{"network", "name", "set"}, dir...)...)
	out = h.run(exitOK, append([]string{"network", "name", "set", "--clear"}, dir...)...)
	mustContain(t, out, "Ağ adı: Ev ağı -> yok")
}

func TestInviteCreateWithTags(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	out := h.run(exitError, "invite", "create", "--dir", h.netDir, pass)
	mustContain(t, out, "koordinatör yok")
	coordKey, coordFP := h.coordinatorKeygen(filepath.Join(t.TempDir(), "koordinator"))
	h.run(exitOK, "network", "set-coordinator", "--dir", h.netDir, "--endpoint", coordinatorURL, "--wireguard-key", coordKey, "--fingerprint", coordFP, pass)
	out = h.run(exitOK, "invite", "create", "--dir", h.netDir, "--tags", "sunucu", pass)
	mustContain(t, out, "Davet kodu", "etiketler: sunucu")
	if inviteCodeLine.FindString(out) == "" {
		t.Fatalf("no invite code:\n%s", out)
	}
	h.run(exitUsage, "invite", "create", "--dir", h.netDir, "--hours", "0", pass)
	h.run(exitError, "invite", "create", "--dir", h.netDir, "--tags", "Büyük", pass)
}

func TestKeyRotationCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	laptopDir := filepath.Join(t.TempDir(), "laptop")
	req, fp := h.keygen(laptopDir, "laptop")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)
	join := func() {
		out := h.run(exitOK, "bundle", "--dir", h.netDir)
		h.run(exitOK, "join", "--state-dir", laptopDir, "--bundle", bundleLine.FindString(out), "--root-fingerprint", rootFPLine.FindStringSubmatch(out)[1])
	}
	join()

	out := h.run(exitOK, "device", "rotate-key", "--state-dir", laptopDir)
	line := rotationLine.FindString(out)
	rotFP := fingerprint.FindStringSubmatch(out)
	if line == "" || len(rotFP) != 2 {
		t.Fatalf("rotate-key output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(laptopDir, "device.key.next")); err != nil {
		t.Fatal("pending key not kept")
	}
	// A second request needs --replace, so a pending one is not lost by accident.
	h.run(exitError, "device", "rotate-key", "--state-dir", laptopDir)
	// Finishing before approval changes nothing.
	h.run(exitError, "device", "rotate-key", "--state-dir", laptopDir, "--finish")

	// The fingerprint is mandatory and must match.
	h.run(exitUsage, "device", "approve-rotation", "--dir", h.netDir, "--request", line, pass)
	out = h.run(exitError, "device", "approve-rotation", "--dir", h.netDir, "--request", line, "--fingerprint", wrongFP, pass)
	mustContain(t, out, "Parmak izleri eşleşmiyor")
	out = h.run(exitOK, "device", "approve-rotation", "--dir", h.netDir, "--request", line, "--fingerprint", strings.ToLower(rotFP[1]), pass)
	mustContain(t, out, "laptop: anahtarlar yenilendi", "1 anahtar çifti emekliye ayrıldı")
	// The same request cannot be applied twice.
	h.run(exitError, "device", "approve-rotation", "--dir", h.netDir, "--request", line, "--fingerprint", rotFP[1], pass)

	join()
	out = h.run(exitOK, "device", "rotate-key", "--state-dir", laptopDir, "--finish")
	mustContain(t, out, "Yeni anahtarlara geçildi")
	if _, err := os.Stat(filepath.Join(laptopDir, "device.key.next")); err == nil {
		t.Fatal("pending key file left behind")
	}
	if _, err := os.Stat(filepath.Join(laptopDir, "device.key.old-1")); err != nil {
		t.Fatal("old key not kept")
	}
	out = h.run(exitOK, "join", "--state-dir", laptopDir, "--bundle", bundleLine.FindString(h.run(exitOK, "bundle", "--dir", h.netDir)), "--root-fingerprint", rootFPLine.FindStringSubmatch(h.run(exitOK, "bundle", "--dir", h.netDir))[1])
	mustContain(t, out, "Bu cihaz ağda kayıtlı: laptop")
}

func TestEngineFlagsAreValidated(t *testing.T) {
	h := newHarness(t)
	empty := t.TempDir()
	for _, args := range [][]string{
		{"--mtu", "1500"},
		{"--mtu", "1000"},
		{"--mtu", "1400", "--force-relay"},
		{"--relay-after", "10ms"},
		{"--relay-after", "1h"},
		{"--direct-retry", "1s"},
	} {
		out := h.run(exitUsage, append([]string{"up", "--state-dir", empty}, args...)...)
		if !strings.Contains(out, "--") {
			t.Fatalf("%v: unexpected output:\n%s", args, out)
		}
	}
	// Valid values pass validation; the missing network fails next.
	h.run(exitError, "up", "--state-dir", empty, "--mtu", "1420", "--relay-after", "5s", "--direct-retry", "1m", "--network-dns=false")
	h.run(exitError, "up", "--state-dir", empty, "--force-relay")
	h.run(exitUsage, "coordinator", "run", "--state-dir", empty, "--relay-rate", "1000")
	h.run(exitUsage, "coordinator", "run", "--state-dir", empty, "--relay-burst", "10")
	h.run(exitError, "coordinator", "run", "--state-dir", empty, "--relay-rate", "1048576", "--relay-burst", "1048576")
}
