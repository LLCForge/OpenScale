package cloudinit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The minimal image recipe (#636, ADR-0184) and the RAM-mode drop-in
// (#633) must stay consistent with the shipped units.

func readDeploy(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "deploy"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func TestMinimalImageRecipe(t *testing.T) {
	conf := readDeploy(t, "image", "coordinator-mkosi", "mkosi.conf")
	for _, want := range []string{"Format=disk", "Bootable=yes", "KernelCommandLine=ro systemd.volatile=state", "CleanPackageMetadata=yes"} {
		if !strings.Contains(conf, want) {
			t.Errorf("mkosi.conf lacks %q", want)
		}
	}
	// Minimal: no package manager front end, no SSH server, no shell tools.
	for _, banned := range []string{"openssh-server", "apt\n", "sudo", "bash-completion"} {
		if strings.Contains(conf, banned) {
			t.Errorf("mkosi.conf installs %q", strings.TrimSpace(banned))
		}
	}
	script := readDeploy(t, "image", "coordinator-mkosi", "hazirla.sh")
	// Every file the script copies from deploy/linux exists.
	for _, m := range regexp.MustCompile(`\$DEPLOY/([A-Za-z0-9._-]+)`).FindAllStringSubmatch(script, -1) {
		if _, err := os.Stat(filepath.Join("..", "..", "deploy", "linux", m[1])); err != nil {
			t.Errorf("hazirla.sh copies missing deploy/linux/%s", m[1])
		}
	}
	if strings.Contains(script, "curl") || strings.Contains(script, "wget") {
		t.Error("hazirla.sh downloads something")
	}
}

func TestRAMDropInMatchesUnit(t *testing.T) {
	unit := readDeploy(t, "linux", "openscale-coordinator.service")
	ram := readDeploy(t, "linux", "openscale-coordinator-ram.conf")
	// The drop-in replaces ExecStart with the same port and only moves the
	// state directory to the runtime directory.
	port := regexp.MustCompile(`--listen-port (\d+)`).FindStringSubmatch(unit)
	if port == nil || !strings.Contains(ram, "--listen-port "+port[1]) {
		t.Fatalf("listen port differs between unit and RAM drop-in")
	}
	for _, want := range []string{"StateDirectory=\n", "RuntimeDirectory=openscale-coordinator", "ExecStart=\n", "--state-dir /run/openscale-coordinator", "ram-seed --seed ${CREDENTIALS_DIRECTORY}", "LoadCredentialEncrypted=coordinator.key:"} {
		if !strings.Contains(ram, want) {
			t.Errorf("RAM drop-in lacks %q", want)
		}
	}
	if !strings.Contains(unit, "LimitCORE=0") || !strings.Contains(readDeploy(t, "linux", "openscale-device.service"), "LimitCORE=0") {
		t.Error("units allow core dumps (#638)")
	}
	if !strings.Contains(readDeploy(t, "linux", "50-openscale-journald.conf"), "Storage=volatile") {
		t.Error("journald drop-in is not volatile")
	}
	if !strings.Contains(readDeploy(t, "linux", "50-openscale-coredump.conf"), "Storage=none") {
		t.Error("coredump drop-in stores dumps")
	}
}
